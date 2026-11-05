#!/usr/bin/env bash
# Установка зонда без Docker (реле и шлюз в РФ): служба awg-probe со своим непривилегированным пользователем.
# Токен и цели в /etc/awg-probe.env (права 600), порты не открываются. Повторный запуск обновляет зонд.
# Запуск из папки с probe.py: sudo bash install.sh. Удаление: sudo bash install.sh --remove
set -euo pipefail

ROOT="/opt/awg-probe"
ENV_FILE="/etc/awg-probe.env"
UNIT="/etc/systemd/system/awg-probe.service"

die() {
	printf 'ОШИБКА: %s\n' "$*" >&2
	exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "нужны права root: sudo bash install.sh"
command -v python3 >/dev/null || die "нужен python3"

if [[ "${1:-}" == --remove ]]; then
	systemctl disable --now awg-probe 2>/dev/null || true
	rm -f "$UNIT"
	systemctl daemon-reload
	rm -rf "$ROOT"
	echo "Зонд удалён. Настройки с токеном удалите сами, если они больше не нужны: rm $ENV_FILE"
	exit 0
fi

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$here/probe.py" ]] || die "рядом нет probe.py"
install -d -m 755 "$ROOT"
install -m 644 "$here/probe.py" "$ROOT/probe.py"

if [[ ! -f "$ENV_FILE" ]]; then
	install -m 600 "$here/.env.example" "$ENV_FILE"
	echo "Создан $ENV_FILE. Заполните PROBE_TARGETS, TG_BOT_TOKEN и TG_CHAT_IDS и запустите скрипт ещё раз."
	exit 0
fi
chmod 600 "$ENV_FILE"

cat >"$UNIT" <<EOF
[Unit]
Description=availability probe
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
Environment=PROBE_STATE_FILE=/var/lib/awg-probe/state.json
Environment=PROBE_HEALTH_FILE=/run/awg-probe/ok
ExecStart=/usr/bin/python3 -I $ROOT/probe.py
Restart=always
RestartSec=10
DynamicUser=yes
StateDirectory=awg-probe
RuntimeDirectory=awg-probe
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=48M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

python3 -I "$ROOT/probe.py" --env-file "$ENV_FILE" --test-message || die "сообщение в Telegram не ушло: проверьте токен, /start у бота и доступ к Telegram (TG_VIA)"
systemctl enable awg-probe >/dev/null
systemctl restart awg-probe
echo "Зонд работает, в Telegram пришло тестовое сообщение. Состояние: systemctl status awg-probe"
