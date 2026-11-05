#!/usr/bin/env python3
"""Зонд доступности серверов из России.

Ставится на хост в РФ (обычно реле и шлюз, без Docker: install.sh), только стандартная библиотека Python. Раз в минуту
проверяет цели из PROBE_TARGETS: TCP-соединение с адресом или HTTP-запрос к проверочной странице. При смене состояния
пишет в Telegram: вид сбоя, состояние остальных целей, сбои за 7 дней и ресурсы своего хоста, при возврате длительность.
IP-адреса целей в лог и в сообщения не попадают: только имена и домены.

Если не отвечают цели и контрольные сайты, неполадка у самого зонда: состояние не меняется, тревоги нет.
Без зависимостей от бота: зонд сообщает и о том, что сервер с ботом перестал отвечать.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

log = logging.getLogger("probe")

SAMARA = timezone(timedelta(hours=4))  # без перехода на летнее время, tzdata в образе не нужен
HEALTH_FILE = os.environ.get("PROBE_HEALTH_FILE", "/tmp/probe.ok")  # noqa: S108
HISTORY = timedelta(days=7)

OK, DNS, TIMEOUT, RESET, REFUSED, ERROR, HTTP = "ok", "dns", "timeout", "reset", "refused", "error", "http"
KIND_TEXT = {
    DNS: "домен не резолвится (возможна подмена DNS или проблема с записью)",
    TIMEOUT: "соединение не устанавливается, пакеты пропадают (типичная блокировка по IP)",
    RESET: "соединение сброшено (возможна фильтрация провайдером)",
    REFUSED: "соединение отклонено (на сервере не слушает порт или он недоступен)",
    ERROR: "сетевая ошибка",
    HTTP: "сервер отвечает, но приложение нет: страница проверки вернула ошибку",
}


@dataclass(frozen=True)
class Target:
    """Цель проверки. url: страница должна ответить 200; иначе TCP к host на любой из ports."""
    name: str
    host: str = ""
    ports: tuple[int, ...] = (443,)
    url: str = ""


def parse_targets(text: str) -> tuple[Target, ...]:
    """«Узел=адрес:443,8443;Кабинет=https://домен/healthz». Разделитель целей: точка с запятой."""
    out: list[Target] = []
    for item in (x.strip() for x in text.split(";") if x.strip()):
        name, sep, spec = item.partition("=")
        name, spec = name.strip(), spec.strip()
        if not sep or not name or not spec:
            raise SystemExit("PROBE_TARGETS: ожидается «Имя=адрес:порт» или «Имя=https://адрес/страница»")
        if spec.startswith(("http://", "https://")):
            out.append(Target(name, url=spec))
            continue
        host, _, ports = spec.partition(":")
        try:
            parsed = tuple(int(p) for p in ports.split(",") if p) or (443,)
        except ValueError:
            raise SystemExit(f"PROBE_TARGETS: порт цели «{name}» должен быть числом") from None
        out.append(Target(name, host=host, ports=parsed))
    if len({t.name for t in out}) != len(out):
        raise SystemExit("PROBE_TARGETS: имена целей должны различаться")
    return tuple(out)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Config:
    target: str = ""
    ports: tuple[int, ...] = (443,)
    controls: tuple[str, ...] = ("ya.ru:443", "vk.com:443")
    interval: float = 60.0
    timeout: float = 5.0
    fail_after: int = 3
    ok_after: int = 2
    remind_hours: float = 6.0
    name: str = "РФ"
    token: str = ""
    chats: tuple[int, ...] = ()
    tg_api: str = "https://api.telegram.org"
    tg_via: str = ""  # адрес:порт передатчика на узле, если Telegram отсюда закрыт
    targets: tuple[Target, ...] = ()
    state_file: str = ""

    @property
    def all_targets(self) -> tuple[Target, ...]:
        return self.targets or (Target("Сервер", host=self.target, ports=self.ports),)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        e = os.environ if env is None else env

        def num(key: str, default: float) -> float:
            try:
                return float(e.get(key) or default)
            except ValueError:
                raise SystemExit(f"{key}: ожидается число") from None

        target = (e.get("PROBE_TARGET") or "").strip()
        token = (e.get("TG_BOT_TOKEN") or "").strip()
        try:
            chats = tuple(int(x) for x in (e.get("TG_CHAT_IDS") or "").replace(" ", "").split(",") if x)
            ports = tuple(int(x) for x in (e.get("PROBE_PORTS") or "443").replace(" ", "").split(",") if x)
        except ValueError:
            raise SystemExit("TG_CHAT_IDS и PROBE_PORTS: ожидается список чисел через запятую") from None
        targets = parse_targets(e.get("PROBE_TARGETS") or "")
        if not (target or targets) or not token or not chats or not ports:
            raise SystemExit("Нужны PROBE_TARGETS или PROBE_TARGET, TG_BOT_TOKEN, TG_CHAT_IDS (см. .env.example)")
        controls = tuple(x for x in (e.get("PROBE_CONTROLS") or "ya.ru:443,vk.com:443").replace(" ", "").split(",") if x)
        return cls(target=target, ports=ports, controls=controls, interval=max(10.0, num("PROBE_INTERVAL", 60)),
                   timeout=num("PROBE_TIMEOUT", 5), fail_after=max(1, int(num("PROBE_FAIL_AFTER", 3))),
                   ok_after=max(1, int(num("PROBE_OK_AFTER", 2))), remind_hours=num("PROBE_REMIND_HOURS", 6),
                   name=(e.get("PROBE_NAME") or "РФ").strip(), token=token, chats=chats,
                   tg_api=(e.get("TG_API") or "https://api.telegram.org").rstrip("/"), targets=targets,
                   tg_via=(e.get("TG_VIA") or "").strip(),
                   state_file=(e.get("PROBE_STATE_FILE") or "").strip())


# ---------- проверка ----------
def check_port(host: str, port: int, timeout: float) -> str:
    """OK или вид сбоя одного TCP-соединения. Резолв отдельно, чтобы отличить DNS от блокировки."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return DNS
    worst = ERROR
    for family, socktype, proto, _, addr in infos[:2]:
        try:
            with socket.socket(family, socktype, proto) as s:
                s.settimeout(timeout)
                s.connect(addr)
            return OK
        except TimeoutError:
            worst = TIMEOUT
        except ConnectionRefusedError:
            worst = REFUSED
        except ConnectionResetError:
            worst = RESET
        except OSError:
            worst = ERROR
    return worst


def check_http(url: str, timeout: float, opener=urllib.request.urlopen) -> str:  # noqa: ANN001
    """Страница проверки: 200 значит, что работает само приложение, а не только порт. Сертификат проверяется."""
    try:
        with opener(urllib.request.Request(url, headers={"User-Agent": "awg-probe"}), timeout=timeout) as resp:
            return OK if resp.status == 200 else HTTP
    except urllib.error.HTTPError:
        return HTTP
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.gaierror):
            return DNS
        if isinstance(reason, TimeoutError):
            return TIMEOUT
        if isinstance(reason, ConnectionRefusedError):
            return REFUSED
        if isinstance(reason, ConnectionResetError):
            return RESET
        if isinstance(reason, ssl.SSLError):
            return HTTP
        return ERROR
    except TimeoutError:
        return TIMEOUT
    except OSError:
        return ERROR


def check_target(cfg: Config, probe=check_port, target: Target | None = None, http=check_http) -> str:  # noqa: ANN001
    """Цель доступна, если отвечает хотя бы один из портов; иначе самый «информативный» сбой."""
    target = target or cfg.all_targets[0]
    if target.url:
        return http(target.url, cfg.timeout)
    results = [probe(target.host, p, cfg.timeout) for p in target.ports]
    if OK in results:
        return OK
    for kind in (TIMEOUT, RESET, REFUSED, DNS, HTTP, ERROR):
        if kind in results:
            return kind
    return ERROR


def probe_online(cfg: Config, probe=check_port) -> bool:  # noqa: ANN001
    """Есть ли у самого зонда выход в интернет: хотя бы один контрольный сайт отвечает."""
    for item in cfg.controls:
        host, _, port = item.rpartition(":")
        if host and port.isdigit() and probe(host, int(port), cfg.timeout) == OK:
            return True
    return not cfg.controls


# ---------- состояние ----------
@dataclass
class Tracker:
    """Тревога после fail_after неудач подряд, отбой после ok_after успехов подряд, напоминание раз в remind_hours."""
    cfg: Config
    down: bool = False
    fails: int = 0
    oks: int = 0
    since: datetime | None = None
    kind: str = ERROR
    last_alert: datetime | None = None
    events: list[str] = field(default_factory=list)
    target: Target | None = None
    outages: list[tuple[datetime, datetime]] = field(default_factory=list)  # закончившиеся сбои за 7 дней
    last_ms: float | None = None  # время ответа последней удачной проверки
    ended: datetime | None = None

    def feed(self, result: str, now: datetime) -> str | None:
        """Возвращает 'down', 'up', 'remind' или None."""
        if result == OK:
            self.fails = 0
            self.oks += 1
            if self.down and self.oks >= self.cfg.ok_after:
                self.down = False
                self.ended = now
                if self.since:
                    self.outages.append((self.since, now))
                self.outages = [o for o in self.outages if now - o[1] < HISTORY]
                return "up"
            return None
        self.oks = 0
        self.fails += 1
        self.kind = result
        if not self.down and self.fails >= self.cfg.fail_after:
            self.down, self.since, self.last_alert = True, now - timedelta(seconds=self.cfg.interval * (self.fails - 1)), now
            return "down"
        if self.down and self.cfg.remind_hours > 0 and now - (self.last_alert or now) >= timedelta(hours=self.cfg.remind_hours):
            self.last_alert = now
            return "remind"
        return None


def _fmt(dt: datetime | None) -> str:
    return dt.astimezone(SAMARA).strftime("%d.%m.%Y %H:%M") + " (Самара)" if dt else "-"


def _duration(delta: timedelta) -> str:
    minutes = max(1, round(delta.total_seconds() / 60))
    if minutes < 60:
        return f"{minutes} мин"
    hours, rest = divmod(minutes, 60)
    return f"{hours} ч {rest} мин" if hours < 24 else f"{hours // 24} дн {hours % 24} ч"


def history_line(tr: Tracker, now: datetime) -> str:
    recent = [o for o in tr.outages if now - o[1] < HISTORY]
    total = sum((o[1] - o[0] for o in recent), timedelta())
    return f"Сбоев за 7 дней: {len(recent)}" + (f", всего {_duration(total)}." if recent else ".")


def read_resources(meminfo: str = "/proc/meminfo", loadavg: str = "/proc/loadavg", root: str = "/") -> str:
    """Ресурсы хоста зонда одной строкой: если сбой из-за него самого, это будет видно."""
    parts: list[str] = []
    try:
        with open(loadavg, encoding="ascii") as f:
            parts.append(f"нагрузка {float(f.read().split()[0]):.2f}")
    except (OSError, ValueError, IndexError):
        pass
    try:
        mem = {}
        with open(meminfo, encoding="ascii") as f:
            for line in f:
                key, _, rest = line.partition(":")
                mem[key] = int(rest.split()[0])
        parts.append(f"память свободна на {mem['MemAvailable'] / mem['MemTotal'] * 100:.0f} %")
    except (OSError, ValueError, IndexError, KeyError, ZeroDivisionError):
        pass
    try:
        st = os.statvfs(root)
        parts.append(f"диск свободен на {st.f_bavail / st.f_blocks * 100:.0f} %")
    except (OSError, ZeroDivisionError):
        pass
    return ", ".join(parts)


def others_line(trackers: dict[str, Tracker], skip: str) -> str:
    items = []
    for name, tr in trackers.items():
        if name == skip:
            continue
        if tr.down:
            items.append(f"{name} ❌")
        else:
            items.append(f"{name} ✅" + (f" {tr.last_ms:.0f} мс" if tr.last_ms is not None else ""))
    return "Остальные: " + " · ".join(items) + "." if items else ""


def message(cfg: Config, event: str, tr: Tracker, now: datetime, others: str = "", resources: str = "") -> str:
    name = tr.target.name if tr.target else "Сервер"
    where = f"Проверка из точки «{cfg.name}»."
    if tr.target and tr.target.host and not is_ip(tr.target.host):  # IP в сообщения не попадает, домен можно
        where = f"Проверка из точки «{cfg.name}», домен {tr.target.host}."
    tail = [line for line in (others, history_line(tr, now), f"Зонд: {resources}." if resources else "", where) if line]
    if event == "down":
        lines = [f"🚨 {name} недоступен из России с {_fmt(tr.since)}.", f"{KIND_TEXT.get(tr.kind, KIND_TEXT[ERROR])}.",
                 f"Неудач подряд: {tr.fails}."]
    elif event == "remind":
        lines = [f"🚨 {name} по-прежнему недоступен из России, уже {_duration(now - (tr.since or now))} (с {_fmt(tr.since)}).",
                 f"{KIND_TEXT.get(tr.kind, KIND_TEXT[ERROR])}."]
    else:
        lines = [f"✅ {name} снова доступен из России ({_fmt(now)}), недоступен был с {_fmt(tr.since)}, "
                 f"{_duration(now - (tr.since or now))}."]
        if tr.last_ms is not None:
            lines.append(f"Время ответа сейчас: {tr.last_ms:.0f} мс.")
    return "\n".join(lines + tail)


# ---------- Telegram ----------
def via_opener(via: str, context: ssl.SSLContext | None = None):  # noqa: ANN201
    """Запрос через передатчик: соединение с ним, а TLS с проверкой сертификата до самого сервера из адреса запроса."""
    addr, _, port = via.rpartition(":")

    def open_(req: urllib.request.Request, timeout: float) -> http.client.HTTPResponse:
        host = req.host
        raw = socket.create_connection((addr, int(port)), timeout=timeout)
        tls = (context or ssl.create_default_context()).wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        conn.sock = tls
        conn.request(req.get_method(), req.selector, req.data, dict(req.header_items()))
        return conn.getresponse()
    return open_


def send(cfg: Config, chat: int, text: str, opener=urllib.request.urlopen) -> bool:  # noqa: ANN001
    req = urllib.request.Request(f"{cfg.tg_api}/bot{cfg.token}/sendMessage",
                                 data=json.dumps({"chat_id": chat, "text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    # Сначала передатчик, если задан: с хоста в РФ прямого пути может не быть. Токен не покидает TLS
    for way in ([via_opener(cfg.tg_via)] if cfg.tg_via else []) + [opener]:
        try:
            with way(req, timeout=15) as resp:
                if resp.status == 200:
                    return True
        except Exception as e:  # noqa: BLE001  в тексте ошибки может быть адрес с токеном: пишем только класс
            log.warning("Telegram недоступен: %s", type(e).__name__)
    return False


def flush(cfg: Config, pending: list[tuple[int, str]], sender=send) -> None:  # noqa: ANN001
    """Недоставленные сообщения остаются в очереди до следующего круга."""
    pending[:] = [(c, m) for c, m in pending if not sender(cfg, c, m)]


# ---------- цикл ----------
def make_trackers(cfg: Config) -> dict[str, Tracker]:
    return {t.name: Tracker(cfg, target=t) for t in cfg.all_targets}


def step_all(cfg: Config, trackers: dict[str, Tracker], pending: list[tuple[int, str]], now: datetime,
             probe=check_port, http=check_http, resources=read_resources) -> dict[str, str]:  # noqa: ANN001
    """Круг проверок: сначала все цели, потом сообщения, чтобы в них было свежее состояние остальных целей."""
    if not probe_online(cfg, probe):
        log.warning("у зонда нет выхода в интернет, круг пропущен")
        return {}
    results: dict[str, str] = {}
    events: list[tuple[Tracker, str]] = []
    for name, tr in trackers.items():
        started = time.monotonic()
        result = check_target(cfg, probe, tr.target, http)
        if result == OK:
            tr.last_ms = (time.monotonic() - started) * 1000
        results[name] = result
        event = tr.feed(result, now)
        if event:
            log.info("цель %s: событие %s (%s)", name, event, result)
            events.append((tr, event))
    for tr, event in events:
        name = tr.target.name if tr.target else ""
        text = message(cfg, event, tr, now, others_line(trackers, name), resources())
        pending.extend((c, text) for c in cfg.chats)
    return results


def step(cfg: Config, tr: Tracker, pending: list[tuple[int, str]], now: datetime, probe=check_port) -> str:  # noqa: ANN001
    """Одна цель (для совместимости с прежней настройкой PROBE_TARGET)."""
    tr.target = tr.target or cfg.all_targets[0]
    results = step_all(cfg, {tr.target.name: tr}, pending, now, probe, resources=lambda: "")
    return results.get(tr.target.name, "offline")


def save_state(cfg: Config, trackers: dict[str, Tracker]) -> None:
    """Сбои за 7 дней переживают перезапуск. Адресов в файле нет."""
    if not cfg.state_file:
        return
    data = {name: {"down": tr.down, "since": tr.since.isoformat() if tr.since else None, "kind": tr.kind,
                   "outages": [[a.isoformat(), b.isoformat()] for a, b in tr.outages]}
            for name, tr in trackers.items()}
    tmp = cfg.state_file + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, cfg.state_file)
    except OSError as e:
        log.warning("состояние не сохранено: %s", type(e).__name__)


def load_saved(cfg: Config, trackers: dict[str, Tracker]) -> None:
    if not cfg.state_file:
        return
    try:
        with open(cfg.state_file, encoding="utf-8") as f:
            data = json.load(f)
        for name, tr in trackers.items():
            item = data.get(name) or {}
            tr.outages = [(datetime.fromisoformat(a), datetime.fromisoformat(b)) for a, b in item.get("outages", [])]
            if item.get("down") and item.get("since"):
                tr.down, tr.since, tr.kind = True, datetime.fromisoformat(item["since"]), item.get("kind", ERROR)
                tr.last_alert = datetime.now(timezone.utc)
    except (OSError, ValueError, TypeError, AttributeError) as e:
        log.warning("состояние не прочитано: %s", type(e).__name__)


def health(cfg: Config) -> int:
    try:
        age = time.time() - os.path.getmtime(HEALTH_FILE)
    except OSError:
        return 1
    return 0 if age < cfg.interval * 3 + 30 else 1


def read_env_file(path: str) -> dict[str, str]:
    """KEY=значение построчно, как читает systemd. В оболочку такой файл не подставить: в целях есть точка с запятой."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip().strip('"')
    return out


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if "--env-file" in argv:
        os.environ.update(read_env_file(argv[argv.index("--env-file") + 1]))
    cfg = Config.from_env()
    if "--health" in argv:
        return health(cfg)
    stop = False

    def _stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    if "--test-message" in argv:  # проверка связки с Telegram при установке
        names = ", ".join(t.name for t in cfg.all_targets)
        ok = all(send(cfg, c, f"Зонд «{cfg.name}» установлен и проверяет: {names}.") for c in cfg.chats)
        return 0 if ok else 1
    trackers, pending = make_trackers(cfg), []
    load_saved(cfg, trackers)
    log.info("зонд запущен: целей %d, интервал %.0f с", len(trackers), cfg.interval)
    while not stop:
        step_all(cfg, trackers, pending, datetime.now(timezone.utc))
        flush(cfg, pending)
        save_state(cfg, trackers)
        try:
            with open(HEALTH_FILE, "w") as f:
                f.write(str(int(time.time())))
        except OSError:
            pass
        deadline = time.monotonic() + cfg.interval
        while not stop and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
