#!/usr/bin/env bash
# Установка реле и шлюза на чистый VPS (Ubuntu 24.04). Исходники проекта и Docker здесь не нужны.
# Файлы скачиваются из этого же репозитория с проверкой контрольных сумм, затем установщик спросит код подключения.
# Повторный запуск безопасен. Запуск: curl -fsSL <адрес>/relay.sh | sudo SETUP_REF=<версия> bash
set -euo pipefail

REF="${SETUP_REF:-main}"
BASE="${SETUP_BASE:-https://raw.githubusercontent.com/fintuzzz/server-setup/$REF}"
ROOT="${SETUP_ROOT:-/opt/awg-gateway}"
FILES=(gateway.py bin/amneziawg-go bin/awg bin/ld-musl-x86_64.so.1)

say() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ОШИБКА: %s\n' "$*" >&2
	exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "нужны права root: запустите через sudo"
[[ -r /dev/tty ]] || die "нужен терминал: установщик спросит код подключения"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "скрипт рассчитан на Ubuntu, здесь ${ID:-неизвестная система}"
[[ "${VERSION_ID:-}" == 24.04 ]] || printf 'Внимание: проверено на Ubuntu 24.04, здесь %s\n' "${VERSION_ID:-неизвестно}"

say "Сервер"
virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "Виртуализация: $virt"
case "$virt" in
openvz | lxc | lxc-libvirt) die "нужна KVM: в этой виртуализации туннель и правила могут не заработать" ;;
esac
[[ -e /dev/net/tun ]] || die "нет /dev/net/tun: попросите хостера включить TUN"
[[ "$(uname -m)" == x86_64 ]] || die "бинарники собраны для x86_64, здесь $(uname -m)"

say "Пакеты: python3, nftables, conntrack, iproute2, curl"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 nftables conntrack iproute2 curl >/dev/null
echo "установлено"

say "Файрвол"
if ufw status 2>/dev/null | grep -q "Status: active"; then
	ssh_port="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
	ufw allow "${ssh_port:-22}/tcp" >/dev/null
	ufw allow 47530/udp >/dev/null
	ufw allow 51821/udp >/dev/null
	ufw allow 8443/tcp >/dev/null
	ufw allow 80/tcp >/dev/null
	ufw allow 443/tcp >/dev/null
	ufw route allow proto udp to any port 47530 >/dev/null
	ufw route allow proto tcp to any port 8443 >/dev/null
	ufw route allow proto tcp to any port 80 >/dev/null
	ufw route allow proto tcp to any port 443 >/dev/null
	ufw route allow in on gw0 >/dev/null
	echo "ufw активен: открыты SSH (${ssh_port:-22}), 47530/udp, 51821/udp, 8443, 80 и 443, пересылка разрешена"
else
	echo "ufw не активен. В панели хостера нужны: SSH, 47530/udp, 51821/udp, 8443/tcp, 80/tcp, 443/tcp."
fi

say "Файлы: версия $REF"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$BASE/SHA256SUMS" || die "список контрольных сумм не скачался"
for name in "${FILES[@]}"; do
	mkdir -p "$tmp/$(dirname "$name")"
	curl -fsSL --retry 3 -o "$tmp/$name" "$BASE/$name" || die "файл не скачался: $name"
	expected="$(awk -v f="$name" '$2 == f {print $1}' "$tmp/SHA256SUMS")"
	[[ -n "$expected" ]] || die "нет контрольной суммы: $name"
	[[ "$(sha256sum "$tmp/$name" | cut -d' ' -f1)" == "$expected" ]] || die "контрольная сумма не совпала: $name"
done
echo "контрольные суммы совпали"
install -d -m 700 "$ROOT"
for name in "${FILES[@]}"; do
	install -m 700 "$tmp/$name" "$ROOT/$(basename "$name")"
done

say "Установка"
python3 -I "$ROOT/gateway.py" install --root "$ROOT"

say "Готово"
cat <<EOF
Журналы трафика здесь не ведутся.
Состояние: sudo python3 $ROOT/gateway.py status
Откат:     sudo python3 $ROOT/gateway.py remove
EOF
