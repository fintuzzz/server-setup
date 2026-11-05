#!/usr/bin/env bash
# Подготовка чистого VPS (Ubuntu 24.04) под сервер управления: пакеты, Docker, ключ доступа к закрытому репозитории,
# клонирование проекта. Повторный запуск безопасен. Бот, домен и туннель здесь не настраиваются.
# Запуск: curl -fsSL <адрес>/control.sh | sudo SETUP_REPO=владелец/имя SETUP_TARGET=/путь bash
set -euo pipefail

[[ -n "${SETUP_REPO:-}" ]] || {
	printf 'ОШИБКА: укажите репозиторий проекта: SETUP_REPO=владелец/имя\n' >&2
	exit 1
}
REPO="git@github-project:$SETUP_REPO.git"
TARGET="${SETUP_TARGET:-/opt/project}"
KEY="/root/.ssh/project_deploy"
SSH_CONFIG="/root/.ssh/config"
LINK_PORT=51822

say() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ОШИБКА: %s\n' "$*" >&2
	exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "нужны права root: sudo bash prepare-control.sh"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "скрипт рассчитан на Ubuntu, здесь ${ID:-неизвестная система}"
[[ "${VERSION_ID:-}" == 24.04 ]] || printf 'Внимание: проверено на Ubuntu 24.04, здесь %s\n' "${VERSION_ID:-неизвестно}"

say "Пакеты: Docker, Compose, git"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 git python3 age curl openssh-client >/dev/null
systemctl enable --now docker >/dev/null
docker version --format 'Docker {{.Server.Version}}'
docker compose version --short

say "Приватный туннель"
# Сетевую службу не переключаем сами: неудачное переключение может оборвать SSH
if systemctl is-active --quiet systemd-networkd; then
	echo "systemd-networkd работает, туннель поднимется командой ./manage.sh link up"
else
	echo "Внимание: systemd-networkd не запущен. Команда ./manage.sh link up откажется работать."
	echo "Включите его вручную через консоль хостера, держа запасной доступ к серверу."
fi

say "Файрвол"
if ufw status 2>/dev/null | grep -q "Status: active"; then
	ssh_port="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
	ufw allow "${ssh_port:-22}/tcp" >/dev/null
	ufw allow 80/tcp >/dev/null
	ufw allow 443/tcp >/dev/null
	ufw allow "$LINK_PORT/udp" >/dev/null
	echo "ufw активен: открыты SSH (${ssh_port:-22}), 80, 443 и $LINK_PORT/udp"
else
	echo "ufw не активен. Проверьте, что в панели хостера открыты 80/tcp, 443/tcp и $LINK_PORT/udp."
fi

say "Ключ доступа к репозитории"
install -d -m 700 /root/.ssh
[[ -f "$KEY" ]] || ssh-keygen -q -t ed25519 -N "" -C "project-control" -f "$KEY"
if ! grep -q "^Host github-project$" "$SSH_CONFIG" 2>/dev/null; then
	cat >>"$SSH_CONFIG" <<EOF
Host github-project
	HostName github.com
	User git
	IdentityFile $KEY
	IdentitiesOnly yes
	StrictHostKeyChecking accept-new
EOF
	chmod 600 "$SSH_CONFIG"
fi

until git ls-remote "$REPO" HEAD >/dev/null 2>&1; do
	echo
	echo "Добавьте этот ключ в GitHub: репозиторий → Settings → Deploy keys → Add deploy key."
	echo "Галочку «Allow write access» не ставьте: серверу управления нужно только чтение."
	echo
	cat "$KEY.pub"
	echo
	read -r -p "Когда добавите, нажмите Enter (Ctrl+C для выхода): " _ </dev/tty # stdin занят при запуске через curl | bash
done
echo "доступ к репозитории есть"

say "Проект"
if [[ -d "$TARGET/.git" ]]; then
	git -C "$TARGET" pull --ff-only
else
	git clone -q "$REPO" "$TARGET"
fi
git -C "$TARGET" checkout -q main
git -C "$TARGET" log --oneline -1

say "Готово"
cat <<EOF
Сервер подготовлен, проект в $TARGET. Дальше по инструкции проекта:
  cd $TARGET
  sudo ./manage.sh link key
EOF
