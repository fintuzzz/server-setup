#!/usr/bin/env bash
# Установка зонда доступности без Docker. Спросит цели и токен бота: токен в /etc/awg-probe.env с правами 600, в истории
# команд его не будет. Повторный запуск обновляет зонд и сохраняет настройки.
# Запуск: curl -fsSL <адрес>/probe.sh | sudo SETUP_REF=<версия> bash
set -euo pipefail

REF="${SETUP_REF:-main}"
BASE="${SETUP_BASE:-https://raw.githubusercontent.com/fintuzzz/server-setup/$REF}"
ENV_FILE="/etc/awg-probe.env"
FILES=(probe/probe.py probe/install.sh probe/env.example)

die() {
	printf 'ОШИБКА: %s\n' "$*" >&2
	exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "нужны права root: запустите через sudo"
command -v python3 >/dev/null || die "нужен python3"
command -v curl >/dev/null || die "нужен curl"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$BASE/SHA256SUMS" || die "список контрольных сумм не скачался"
for name in "${FILES[@]}"; do
	target="$tmp/$(basename "$name")"
	curl -fsSL --retry 3 -o "$target" "$BASE/$name" || die "файл не скачался: $name"
	expected="$(awk -v f="$name" '$2 == f {print $1}' "$tmp/SHA256SUMS")"
	[[ -n "$expected" ]] || die "нет контрольной суммы: $name"
	[[ "$(sha256sum "$target" | cut -d' ' -f1)" == "$expected" ]] || die "контрольная сумма не совпала: $name"
done
mv "$tmp/env.example" "$tmp/.env.example"

if [[ ! -f "$ENV_FILE" ]]; then
	[[ -r /dev/tty ]] || die "нужен терминал, чтобы спросить настройки"
	echo "Цели через точку с запятой: Имя=адрес:порт,порт или Имя=https://домен/страница"
	read -r -p "Цели: " targets </dev/tty
	read -r -s -p "Токен бота (ввод скрыт): " token </dev/tty
	echo
	read -r -p "ID получателей через запятую: " chats </dev/tty
	read -r -p "Адрес передатчика Telegram, если прямого доступа нет (Enter, чтобы пропустить): " via </dev/tty
	[[ -n "$targets" && -n "$token" && -n "$chats" ]] || die "цели, токен и получатели обязательны"
	(
		umask 077
		printf 'PROBE_TARGETS=%s\nTG_BOT_TOKEN=%s\nTG_CHAT_IDS=%s\n' "$targets" "$token" "$chats" >"$ENV_FILE"
		[[ -z "$via" ]] || printf 'TG_VIA=%s\n' "$via" >>"$ENV_FILE"
	)
fi
bash "$tmp/install.sh"
