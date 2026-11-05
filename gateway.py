"""РФ-шлюз: российские сайты видят адрес VPS в России. Настройка узла и установка на VPS, без Docker и без переноса файлов.

На узле (из образа агента): gateway.py make --exit-ip АДРЕС_VPS --initiator node|ru [--node-host УЗЕЛ]
    печатает код подключения. Секреты туннеля есть только в нём и в /state на узле, в чаты его не пересылайте.
На VPS:  sudo python3 gateway.py install     спросит код, создаст свой ключ, поставит службу, покажет публичный ключ
На узле: gateway.py finish --peer-key КЛЮЧ   дописывает конфиг узла
На VPS:  sudo python3 gateway.py status
         sudo python3 gateway.py relay-on --node-ip АДРЕС_УЗЛА     реле: клиенты подключаются к этому VPS
         sudo python3 gateway.py relay-off
         sudo python3 gateway.py remove      откат: убирает всё, что поставили install и relay-on

Приватный ключ VPS создаётся на нём самом и никуда не передаётся. Реле только пересылает пакеты на узел и не зависит от
туннеля шлюза: сбой шлюза не отключает клиентов. Ключей клиентов на VPS нет, узел видит адрес реле вместо адресов клиентов.

На VPS нет ключей клиентов и их зарубежного трафика: сюда приходит только российский трафик от узла, с адреса узла в
туннеле, поэтому отличить клиентов друг от друга здесь нельзя. Журналов нет: служба пишет в /dev/null, правил log нет.
Из туннеля нельзя обратиться к самому VPS и к частным сетям хостера. Только стандартная библиотека Python.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

INSTALL_ROOT = Path("/opt/awg-gateway")
UNIT_PATH = Path("/etc/systemd/system/awg-gateway.service")
SYSCTL_PATH = Path("/etc/sysctl.d/90-awg-gateway.conf")
NFT_TABLE = "awg_gateway"
RELAY_TABLE = "awg_relay"
RELAY_UNIT_PATH = Path("/etc/systemd/system/awg-relay.service")
RELAY_UDP = (47530,)  # AWG
RELAY_TCP = (80, 443, 8443)  # заглушка и MTProto
IFACE = "gw0"
PORT = 51821
MTU = 1280
NETWORK = "10.78.0.0/30"
NODE_ADDRESS = "10.78.0.1"
RU_ADDRESS = "10.78.0.2"
LOADER = "ld-musl-x86_64.so.1"
PRIVATE_NETWORKS = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
SOCKET_WAIT_SECONDS = 10
CODE_PREFIX = "gw1-"
PENDING = "gateway-pending.json"  # приватный ключ узла до получения ключа VPS
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def run(*cmd: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, input=input, timeout=60)


def awg_command(root: Path) -> list[str]:
    """На VPS awg лежит рядом и запускается через загрузчик musl; в образе агента это обычная команда."""
    return [str(root / LOADER), str(root / "awg")] if (root / LOADER).exists() else ["awg"]


# ---------- конфиги ----------
def dns_i1() -> str:
    """Форма как у текущих клиентов, значение своё. Варианты маскировки сравниваются отдельно (этап 11)."""
    body = bytes.fromhex("85800001000100000000") + b"\x07example\x02ru\x00" + bytes.fromhex("00010001") \
        + bytes.fromhex("c00c000100010000012c0004") + secrets.token_bytes(4)
    return f"<r 2><b 0x{body.hex()}>"


def make_params() -> dict:
    return {"Jc": 4, "Jmin": 10, "Jmax": 50, "S1": 12, "S2": 12, "S3": 12, "S4": 12, "H1": 1, "H2": 2, "H3": 3, "H4": 4,
            "HeaderProtectionKey": base64.b64encode(secrets.token_bytes(32)).decode(), "I1": dns_i1()}


def render_conf(private: str, peer_public: str, psk: str, params: dict, allowed: str, initiator: bool,
                peer_host: str | None, port: int) -> str:
    """Конфиг `awg setconf`. Endpoint и I1 только у стороны, начинающей соединение."""
    if initiator and not peer_host:
        raise ValueError("сторона, начинающая соединение, должна знать адрес второй")
    lines = ["[Interface]", f"PrivateKey = {private}", f"ListenPort = {port}"]
    lines += [f"{k} = {v}" for k, v in params.items() if k != "I1" or initiator]
    lines += ["", "[Peer]", f"PublicKey = {peer_public}", f"PresharedKey = {psk}", f"AllowedIPs = {allowed}"]
    if initiator:
        lines += [f"Endpoint = {peer_host}:{port}", "PersistentKeepalive = 25"]
    return "\n".join(lines) + "\n"


def render_gateway_nft(iface: str, outer: str) -> str:
    """Одна транзакция nft. Пересылка только из туннеля наружу и ответы обратно, к самому VPS из туннеля нельзя."""
    if not _IFACE_RE.fullmatch(iface) or not _IFACE_RE.fullmatch(outer):
        raise ValueError("недопустимое имя интерфейса")
    private = ", ".join(PRIVATE_NETWORKS)
    return (
        f"table ip {NFT_TABLE} {{}}\n"
        f"delete table ip {NFT_TABLE}\n"
        f"table ip {NFT_TABLE} {{\n"
        f"  set private {{ type ipv4_addr; flags interval; elements = {{ {private} }}; }}\n"
        "  chain input {\n"
        "    type filter hook input priority filter; policy accept;\n"
        f'    iifname "{iface}" ct state established,related accept\n'
        f'    iifname "{iface}" drop\n'
        "  }\n"
        "  chain forward {\n"
        "    type filter hook forward priority filter; policy drop;\n"
        "    ct status dnat accept\n"  # пересылка реле: отбор делает его таблица, здесь только не мешаем
        f'    iifname "{iface}" oifname "{outer}" ip daddr @private drop\n'
        f'    iifname "{iface}" oifname "{outer}" accept\n'
        f'    iifname "{outer}" oifname "{iface}" ct state established,related accept\n'
        "  }\n"
        "  chain clamp_mss {\n"
        "    type filter hook forward priority mangle; policy accept;\n"
        f'    oifname "{iface}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu\n'
        f'    iifname "{iface}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu\n'
        "  }\n"
        "  chain nat {\n"
        "    type nat hook postrouting priority srcnat; policy accept;\n"
        f'    ip saddr {NETWORK} oifname "{outer}" masquerade\n'
        "  }\n"
        "}\n"
    )


def render_relay_nft(outer: str, node_ip: str, udp: tuple[int, ...] = RELAY_UDP, tcp: tuple[int, ...] = RELAY_TCP) -> str:
    """Отдельная таблица: перезапуск туннеля шлюза её не трогает. Наружу уходит только то, что пришло на порты реле;
    адрес клиента заменяется адресом реле. Счётчики без адресов, журналов нет."""
    if not _IFACE_RE.fullmatch(outer):
        raise ValueError("недопустимое имя интерфейса")
    node = ipaddress.IPv4Address(node_ip)
    if node.is_loopback or node.is_unspecified or node.is_multicast:
        raise ValueError("недопустимый адрес узла")
    for port in (*udp, *tcp):
        if not 1 <= port <= 65535 or port == PORT:
            raise ValueError("недопустимый порт реле")
    def ports(values):
        return ", ".join(str(p) for p in sorted(values))
    return (
        f"table ip {RELAY_TABLE} {{}}\n"
        f"delete table ip {RELAY_TABLE}\n"
        f"table ip {RELAY_TABLE} {{\n"
        "  chain to_node {\n"  # не dnat: это слово зарезервировано в nft
        "    type nat hook prerouting priority dstnat; policy accept;\n"
        f'    iifname "{outer}" udp dport {{ {ports(udp)} }} counter dnat to {node}\n'
        f'    iifname "{outer}" tcp dport {{ {ports(tcp)} }} counter dnat to {node}\n'
        "  }\n"
        "  chain forward {\n"
        "    type filter hook forward priority filter; policy accept;\n"
        f'    iifname "{outer}" oifname "{outer}" ct status & dnat == 0 drop\n'
        "  }\n"
        "  chain nat {\n"
        "    type nat hook postrouting priority srcnat; policy accept;\n"
        f'    oifname "{outer}" ct status dnat masquerade\n'
        "  }\n"
        "}\n"
    )


def render_relay_unit(root: Path) -> str:
    return (
        "[Unit]\nDescription=relay rules\nAfter=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        f"ExecStart=/usr/bin/python3 {root}/gateway.py relay-apply --root {root}\n"
        f"ExecStop=-/usr/sbin/nft delete table ip {RELAY_TABLE}\n"
        "StandardOutput=null\nStandardError=null\nLogLevelMax=0\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def render_unit(root: Path, iface: str) -> str:
    return (
        "[Unit]\nDescription=gateway tunnel\nAfter=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"ExecStart={root}/amneziawg-go -f {iface}\n"
        f"ExecStartPost=/usr/bin/python3 {root}/gateway.py configure --root {root}\n"
        f"ExecStopPost=-/usr/sbin/ip link del {iface}\n"
        f"ExecStopPost=-/usr/sbin/nft delete table ip {NFT_TABLE}\n"
        "Restart=always\nRestartSec=5\nStandardOutput=null\nStandardError=null\nLogLevelMax=0\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    path.chmod(0o600)


# ---------- код подключения ----------
def keypair(awg: list[str]) -> tuple[str, str]:
    private = run(*awg, "genkey").stdout.strip()
    return private, run(*awg, "pubkey", input=private + "\n").stdout.strip()


def encode_code(data: dict) -> str:
    return CODE_PREFIX + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def decode_code(code: str) -> dict:
    """Код проверяется целиком до любых изменений: вставляют его руками, он может быть обрезан."""
    code = code.strip()
    if not code.startswith(CODE_PREFIX):
        raise ValueError("это не код подключения")
    body = code[len(CODE_PREFIX):]
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError as e:
        raise ValueError("код повреждён или вставлен не целиком") from e
    required = {"node_public", "psk", "params", "port", "initiator"}
    if not isinstance(data, dict) or not required <= set(data) or data["initiator"] not in ("node", "ru"):
        raise ValueError("код повреждён или вставлен не целиком")
    if data["initiator"] == "ru" and not _IPV4_RE.fullmatch(str(data.get("node_host", ""))):
        raise ValueError("в коде нет адреса узла")
    return data


def new_code(awg: list[str], initiator: str, exit_ip: str, node_host: str | None, port: int) -> tuple[dict, str]:
    """(ожидание на узле с приватным ключом, код для VPS). Приватного ключа узла в коде нет."""
    private, public = keypair(awg)
    psk = run(*awg, "genpsk").stdout.strip()
    params = make_params()
    pending = {"private": private, "psk": psk, "params": params, "port": port, "initiator": initiator, "exit_ip": exit_ip}
    code = {"node_public": public, "psk": psk, "params": params, "port": port, "initiator": initiator}
    if initiator == "ru":
        code["node_host"] = node_host
    return pending, encode_code(code)


def node_conf(pending: dict, peer_public: str) -> str:
    starts = pending["initiator"] == "node"
    return render_conf(pending["private"], peer_public, pending["psk"], pending["params"], "0.0.0.0/0", starts,
                       pending["exit_ip"] if starts else None, pending["port"])


def vps_conf(code: dict, private: str) -> str:
    starts = code["initiator"] == "ru"
    return render_conf(private, code["node_public"], code["psk"], code["params"], f"{NODE_ADDRESS}/32", starts,
                       code.get("node_host") if starts else None, code["port"])


# ---------- узел ----------
def make(args: argparse.Namespace) -> None:
    ipaddress.IPv4Address(args.exit_ip)
    state = Path(args.state)
    pending, code = new_code(["awg"], args.initiator, args.exit_ip, args.node_host, args.port)
    write_private(state / PENDING, json.dumps(pending))
    print("Код подключения для VPS, вставьте его при установке. В чаты не пересылайте:")
    print(code)


def finish(args: argparse.Namespace) -> None:
    if not _KEY_RE.fullmatch(args.peer_key):
        raise SystemExit("Это не публичный ключ: скопируйте его из вывода установки на VPS")
    state = Path(args.state)
    try:
        pending = json.loads((state / PENDING).read_text(encoding="utf-8"))
    except OSError:
        raise SystemExit("Сначала gateway-make: ожидающего подключения нет") from None
    write_private(state / "gateway.conf", node_conf(pending, args.peer_key))
    write_private(state / "gateway.json", json.dumps({"address": NODE_ADDRESS, "mtu": MTU, "exit_ip": pending["exit_ip"],
                                                      "initiator": pending["initiator"], "port": pending["port"]}))
    (state / PENDING).unlink()
    print("Файлы шлюза на узле готовы")


# ---------- VPS ----------
def outer_iface() -> str:
    match = re.search(r"\bdev (\S+)", run("ip", "-4", "route", "show", "default").stdout)
    if not match:
        raise SystemExit("Не найден основной сетевой интерфейс")
    return match.group(1)


def configure(root: Path, outer: str | None = None) -> None:
    """Запускается службой после старта туннеля и после каждого его перезапуска."""
    meta = json.loads((root / "gateway.json").read_text(encoding="utf-8"))
    iface = meta["iface"]
    sock = Path(f"/var/run/amneziawg/{iface}.sock")
    end = time.monotonic() + SOCKET_WAIT_SECONDS
    while not sock.exists():
        if time.monotonic() > end:
            raise SystemExit("Туннель не запустился")
        time.sleep(0.2)
    run(*awg_command(root), "setconf", iface, str(root / "gw.conf"))
    run("ip", "address", "replace", f"{meta['address']}/30", "dev", iface)
    run("ip", "link", "set", iface, "mtu", str(meta["mtu"]), "up")
    run("nft", "-f", "-", input=render_gateway_nft(iface, outer or meta.get("outer") or outer_iface()))


def join(root: Path, code_text: str, outer: str | None = None) -> str:
    """Создаёт свой ключ и настройки по коду. Возвращает публичный ключ VPS."""
    code = decode_code(code_text)
    private, public = keypair(awg_command(root))
    write_private(root / "gw.conf", vps_conf(code, private))
    write_private(root / "gateway.json", json.dumps({"iface": IFACE, "address": RU_ADDRESS, "mtu": MTU, "port": code["port"],
                                                     "outer": outer or outer_iface()}))
    return public


def read_code() -> str:
    """Со скрытым вводом и с терминала: скрипт могут запустить через curl | bash, и stdin занят."""
    return getpass.getpass("Вставьте код подключения с узла (ввод скрыт): ")


def install(args: argparse.Namespace) -> None:
    """Запускается из /opt/awg-gateway, куда файлы положил установщик. Повторный запуск с новым кодом заменяет настройки."""
    for tool in ("nft", "ip", "systemctl"):
        if not shutil.which(tool):
            raise SystemExit(f"Не найдена утилита {tool}")
    root = Path(args.root)
    ufw = shutil.which("ufw")
    if ufw and "Status: active" in run(ufw, "status", check=False).stdout:
        print(f"Внимание: ufw включён. Если соединение начинает узел, разрешите {PORT}/udp вручную.")
    try:
        public = join(root, read_code())
    except ValueError as e:
        raise SystemExit(f"Код не принят: {e}") from None
    meta = json.loads((root / "gateway.json").read_text(encoding="utf-8"))
    SYSCTL_PATH.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    run("sysctl", "-p", str(SYSCTL_PATH))
    UNIT_PATH.write_text(render_unit(root, meta["iface"]), encoding="utf-8")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "awg-gateway")
    run("systemctl", "restart", "awg-gateway")
    print("Шлюз установлен. Откат: sudo python3 " + str(root / "gateway.py") + " remove")
    print("Выполните на узле, ключ не секретный:")
    print(f"  sudo ./manage.sh egress gateway-finish --peer-key {public}")


def flush_relay_flows() -> None:
    """DNAT решается только на первом пакете потока. Клиент повторяет рукопожатие с того же порта, поэтому старая запись
    conntrack не истекает сама: без сброса новые правила или новый адрес узла к нему никогда не применятся."""
    if not shutil.which("conntrack"):
        return
    for proto, values in (("udp", RELAY_UDP), ("tcp", RELAY_TCP)):
        for port in values:
            run("conntrack", "-f", "ipv4", "-D", "-p", proto, "--orig-port-dst", str(port), check=False)


def relay_apply(root: Path, outer: str | None = None) -> None:
    meta = json.loads((root / "relay.json").read_text(encoding="utf-8"))
    run("nft", "-f", "-", input=render_relay_nft(outer or meta.get("outer") or outer_iface(), meta["node_ip"]))
    flush_relay_flows()


def busy_ports() -> list[str]:
    """Порты реле, которые уже слушает сам VPS: пересылка перехватила бы их."""
    busy = []
    for proto, flag, values in (("udp", "-lun", RELAY_UDP), ("tcp", "-ltn", RELAY_TCP)):
        for port in values:
            if run("ss", "-H", flag, "sport", "=", f":{port}", check=False).stdout.strip():
                busy.append(f"{port}/{proto}")
    return busy


def relay_on(args: argparse.Namespace) -> None:
    render_relay_nft("eth0", args.node_ip)  # проверка адреса и портов до любых изменений
    if not INSTALL_ROOT.exists():
        raise SystemExit("Сначала sudo python3 gateway.py install")
    if not shutil.which("conntrack"):
        raise SystemExit("Нужна утилита conntrack: sudo apt-get install -y conntrack")
    busy = busy_ports()
    if busy:
        raise SystemExit("Эти порты уже заняты на VPS: " + ", ".join(busy))
    write_private(INSTALL_ROOT / "relay.json", json.dumps({"node_ip": args.node_ip, "outer": outer_iface()}))
    SYSCTL_PATH.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    run("sysctl", "-p", str(SYSCTL_PATH))
    relay_apply(INSTALL_ROOT)  # новый адрес узла применяется одной транзакцией, клиенты не отключаются
    RELAY_UNIT_PATH.write_text(render_relay_unit(INSTALL_ROOT), encoding="utf-8")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "awg-relay")
    run("systemctl", "start", "awg-relay")
    print("Реле включено. Клиенты пойдут через него, когда домен подключения будет указывать на этот VPS.")


def relay_off(args: argparse.Namespace) -> None:
    run("systemctl", "disable", "--now", "awg-relay", check=False)
    RELAY_UNIT_PATH.unlink(missing_ok=True)
    run("systemctl", "daemon-reload", check=False)
    run("nft", "delete", "table", "ip", RELAY_TABLE, check=False)
    flush_relay_flows()
    (INSTALL_ROOT / "relay.json").unlink(missing_ok=True)
    if run("systemctl", "is-active", "awg-gateway", check=False).stdout.strip() != "active":
        SYSCTL_PATH.unlink(missing_ok=True)
        run("sysctl", "-w", "net.ipv4.ip_forward=0", check=False)
    print("Реле выключено. Если домен подключения указывает на этот VPS, клиенты не подключатся: верните его на узел.")


def remove(args: argparse.Namespace) -> None:
    relay_off(args)
    run("systemctl", "disable", "--now", "awg-gateway", check=False)
    UNIT_PATH.unlink(missing_ok=True)
    run("systemctl", "daemon-reload", check=False)
    SYSCTL_PATH.unlink(missing_ok=True)
    run("sysctl", "-w", "net.ipv4.ip_forward=0", check=False)
    run("nft", "delete", "table", "ip", NFT_TABLE, check=False)
    run("ip", "link", "del", IFACE, check=False)
    shutil.rmtree(INSTALL_ROOT, ignore_errors=True)
    print("Шлюз удалён: служба, правила, пересылка и ключи. Распакованный архив удалите сами.")


def status(args: argparse.Namespace) -> None:
    active = run("systemctl", "is-active", "awg-gateway", check=False).stdout.strip()
    print("Служба:", active or "нет")
    out = run(*awg_command(INSTALL_ROOT), "show", IFACE, "latest-handshakes", check=False).stdout.split()
    stamp = int(out[1]) if len(out) > 1 else 0
    print(f"Последнее рукопожатие: {int(time.time()) - stamp} с назад" if stamp else "Рукопожатия не было")
    print("Пересылка:", Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip())
    print("Правила nft:", "есть" if run("nft", "list", "table", "ip", NFT_TABLE, check=False).returncode == 0 else "нет")
    relay = run("nft", "list", "table", "ip", RELAY_TABLE, check=False)
    if relay.returncode:
        print("Реле: выключено")
    else:
        counts = re.findall(r"dport \{?[^}]*\}? counter packets (\d+) bytes (\d+)", relay.stdout)
        total = sum(int(b) for _, b in counts)
        print(f"Реле: включено, переслано новых соединений и пакетов NAT: {sum(int(p) for p, _ in counts)}, байт в них: {total}")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="РФ-шлюз")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("make")
    c.add_argument("--exit-ip", required=True)
    c.add_argument("--initiator", choices=("node", "ru"), required=True)
    c.add_argument("--node-host", help="IP узла для VPS, если соединение начинает VPS: домен позже укажет на само реле")
    c.add_argument("--port", type=int, default=PORT)
    c.add_argument("--state", default="/state")
    c.set_defaults(func=make)
    c = sub.add_parser("finish")
    c.add_argument("--peer-key", required=True)
    c.add_argument("--state", default="/state")
    c.set_defaults(func=finish)
    c = sub.add_parser("configure")
    c.add_argument("--root", default=str(INSTALL_ROOT))
    c.add_argument("--outer")
    c.set_defaults(func=lambda a: configure(Path(a.root), a.outer))
    c = sub.add_parser("relay-on")
    c.add_argument("--node-ip", required=True)
    c.set_defaults(func=relay_on)
    sub.add_parser("relay-off").set_defaults(func=relay_off)
    c = sub.add_parser("relay-apply")
    c.add_argument("--root", default=str(INSTALL_ROOT))
    c.add_argument("--outer")
    c.set_defaults(func=lambda a: relay_apply(Path(a.root), a.outer))
    c = sub.add_parser("install")
    c.add_argument("--root", default=str(INSTALL_ROOT))
    c.set_defaults(func=install)
    sub.add_parser("remove").set_defaults(func=remove)
    sub.add_parser("status").set_defaults(func=status)
    return p


def main() -> None:
    args = parser().parse_args()
    if args.command == "make" and args.initiator == "ru" and not (args.node_host and _IPV4_RE.fullmatch(args.node_host)):
        sys.exit("Если соединение начинает VPS, укажите --node-host с IP узла: домен позже укажет на само реле")
    if os.geteuid() != 0:
        sys.exit("Нужны права root")
    args.func(args)


if __name__ == "__main__":
    main()
