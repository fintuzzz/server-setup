#!/usr/bin/env bash
# Проверка VPS в РФ перед настройкой реле и шлюза. Только чтение: ничего не устанавливает и не меняет.
# Адреса серверов в отчёт не попадают, поэтому его можно прислать в чат целиком.
# Запуск: sudo bash check.sh <домен_или_адрес_узла>
set -u

TARGET="${1:?укажите домен или адрес узла: sudo bash check.sh <адрес>}"
TCP_TIMEOUT="${PROBE_TCP_TIMEOUT:-5}"
RU_SITES="gosuslugi.ru ozon.ru yandex.ru vk.com sberbank.ru wildberries.ru"

say() { printf '\n== %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
line() { printf '%-34s %s\n' "$1" "$2"; }

say "Сервер"
# shellcheck disable=SC1091
[ -r /etc/os-release ] && . /etc/os-release
line "Система" "${PRETTY_NAME:-неизвестно}"
line "Ядро" "$(uname -r)"
line "Виртуализация" "$(have systemd-detect-virt && systemd-detect-virt || echo 'не определена')"
line "Ядер" "$(nproc 2>/dev/null || echo '?')"
line "Память, МБ" "$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
line "Свободно на диске" "$(df -h / 2>/dev/null | awk 'NR==2 {print $4}')"
line "Устройство /dev/net/tun" "$([ -e /dev/net/tun ] && echo есть || echo НЕТ)"
line "Модуль wireguard" "$(have modinfo && modinfo wireguard >/dev/null 2>&1 && echo есть || echo 'не найден')"
line "nft" "$(have nft && echo есть || echo 'не установлен')"
line "Docker" "$(have docker && echo есть || echo 'не установлен')"
line "Пересылка IPv4" "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"

say "Адрес и сеть хостера"
public="$(curl -4 -s --max-time 10 https://ifconfig.me 2>/dev/null)"
if [ -z "$public" ]; then
	line "Внешний адрес" "не определён"
elif have ip && ip -4 -o addr show 2>/dev/null | grep -qF " $public/"; then
	line "Внешний адрес на интерфейсе" "да, настоящий публичный IPv4"
else
	line "Внешний адрес на интерфейсе" "НЕТ: похоже на NAT, реле не подойдёт"
fi
line "Сеть (AS)" "$(curl -4 -s --max-time 10 https://ipinfo.io/org 2>/dev/null || echo '?')"
line "Страна" "$(curl -4 -s --max-time 10 https://ipinfo.io/country 2>/dev/null || echo '?')"
line "Глобальных адресов IPv6" "$(have ip && ip -6 -o addr show scope global 2>/dev/null | wc -l || echo '?')"
if have ufw; then
	state="$(ufw status 2>/dev/null | head -1)"
	line "ufw" "${state:-нет данных: запустите через sudo}"
else
	line "ufw" "не установлен"
fi

say "Занятые порты, которые нужны реле"
for port in 80 443 8443 47530 51822; do
	if have ss && ss -H -ltnu "sport = :$port" 2>/dev/null | grep -q .; then
		line "Порт $port" "занят"
	else
		line "Порт $port" "свободен"
	fi
done

say "Связь с узлом ($TARGET)"
node="$(getent ahostsv4 "$TARGET" 2>/dev/null | awk 'NR==1 {print $1}')"
if [ -z "$node" ]; then
	line "Имя" "НЕ разрешается"
else
	if have ping; then
		line "ping, потери и среднее" "$(ping -4 -c 5 -q -W 3 "$node" 2>/dev/null |
			awk -F'[ ,/=]+' '/packet loss/ {for (i=1;i<=NF;i++) if ($i ~ /%/) loss=$i} /^rtt|^round-trip/ {avg=$7} END {print (loss==""?"нет ответа":loss" "avg" мс")}')"
		for size in 1400 1372 1252; do
			if ping -4 -c 2 -q -W 3 -M "do" -s "$size" "$node" >/dev/null 2>&1; then
				line "Пакет $((size + 28)) байт без дробления" "проходит"
			else
				line "Пакет $((size + 28)) байт без дробления" "НЕ проходит"
			fi
		done
	fi
	for port in 443 8443 80 2233; do
		if timeout "$TCP_TIMEOUT" bash -c "exec 3<>/dev/tcp/$node/$port" 2>/dev/null; then
			line "TCP $port" "открывается"
		else
			line "TCP $port" "НЕ открывается"
		fi
	done
	line "HTTPS заглушки: код и время" "$(curl -4 -s -o /dev/null --max-time 15 -w '%{http_code} %{time_total} с' "https://$TARGET/" 2>/dev/null)"
fi
echo "UDP здесь не проверяется: узел молчит в ответ на чужие пакеты, нужен тестовый туннель (следующий шаг)."

say "Российские сайты отсюда (код и время)"
for site in $RU_SITES; do
	# -k: проверяем доступность, а не сертификат; у части сайтов он выдан российским центром, которого нет в системе
	line "$site" "$(curl -4 -k -s -o /dev/null -L --max-time 15 -A 'Mozilla/5.0' -w '%{http_code} %{time_total} с' "https://www.$site/" 2>/dev/null)"
done

say "Скачивание за 15 секунд (обрыв на 15-20 КБ означает фильтрацию)"
download() {
	line "$1" "$(curl -4 -s -o /dev/null --max-time 15 -w '%{size_download} байт, %{speed_download} байт/с' "$2" 2>/dev/null)"
}
download "Россия: mirror.yandex.ru" "https://mirror.yandex.ru/ubuntu/ls-lR.gz"
download "Зарубежный CDN: CacheFly" "https://cachefly.cachefly.net/100mb.test"
download "Зарубежный дата-центр: Hetzner" "https://fsn1-speed.hetzner.com/100MB.bin"

say "UDP наружу"
if have dig; then
	line "DNS 1.1.1.1 по UDP" "$(dig +short +time=3 +tries=1 @1.1.1.1 example.com A 2>/dev/null | grep -q . && echo проходит || echo 'НЕ проходит')"
else
	line "DNS 1.1.1.1 по UDP" "не проверено: нет dig"
fi

printf '\nГотово. Сервер не изменялся.\n'
