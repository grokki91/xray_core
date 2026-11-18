#!/usr/bin/env bash
# Системный тест L4 (docs/testing.md §2), каркас фазы 2: настоящий xm на чистой машине с systemd.
# Запуск: sudo bash tests/system/l4.sh /путь/к/xm — только на одноразовой машине (исполнитель CI,
# виртуальная машина): скрипт ставит службу xray и не убирает её. Печатает «ok <шаг>» и в конце
# «l4: PASS|FAIL»; вывод xm и значения из состояния на экран не попадают (docs/security/secrets.md).
# Сценарии следующих фаз добавляются сюда же отдельными функциями.
set -u
xm=${1:-}
[[ -x $xm ]] || { echo "usage: sudo bash $0 /path/to/xm" >&2; exit 2; }
((EUID == 0)) || { echo "нужен root" >&2; exit 2; }

fails=0
out=$(mktemp -d) # вывод xm: до проверки на секреты на экран не идёт
trap 'rm -rf "$out"' EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { # check ШАГ КОМАНДА… — успех команды
	local name=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
eq() { # eq ШАГ ПОЛУЧЕНО ОЖИДАЕТСЯ
	if [[ $2 == "$3" ]]; then ok "$1"; else bad "$1: получено «$2», ожидалось «$3»"; fi
}
perm() { # perm ПУТЬ ВЛАДЕЛЕЦ:ГРУППА ПРАВА — строка манифеста data-model.md §1
	local got
	got=$(stat -c '%U:%G %a' "$1" 2>/dev/null)
	if [[ $got == "$2 $3" ]]; then ok "права $1"; else bad "права $1: $got, ожидалось $2 $3"; fi
}

sni=example.com
addr=192.0.2.10 # документационный адрес RFC 5737: проверке нужна форма, а не достижимость
port=443

# 0. Среда: факты о машине для разбора провалов (секретов здесь нет)
# На свежем раннере systemd — PID 1, но загрузка ещё идёт (starting): xm в этом состоянии
# отказывает по предусловию, поэтому тест сначала дожидается конца загрузки (не дольше 2 минут).
timeout 120 systemctl is-system-running --wait >/dev/null 2>&1
echo "env  is-system-running: $(systemctl is-system-running 2>&1 | head -1)"
echo "env  PID 1: $(ps -p 1 -o comm= 2>&1)"
echo "env  ОС: $(sed -n 's/^PRETTY_NAME=//p' /usr/lib/os-release), память: $(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo) МиБ"

# 1. Установка
"$xm" install --sni "$sni" --address "$addr" --port "$port" >"$out/install" 2>&1
rc=$?
if [[ $rc == 0 ]]; then
	ok "install: код 0"
else
	bad "install: код $rc"
	# Состояния нет — ключей нет: вывод отказа (он и так проходит редактор xm) печатается целиком.
	[[ -e /etc/xm/state.json ]] || sed 's/^/     | /' "$out/install"
fi

# 2. Служба и процесс
check "служба активна" systemctl is-active --quiet xray.service
check "автозапуск включён" systemctl is-enabled --quiet xray.service
pid=$(systemctl show -p MainPID --value xray.service)
user=$(ps -o user= -p "${pid:-0}" 2>/dev/null | tr -d ' ')
eq "процесс от пользователя xray" "$user" xray
# CAP_NET_BIND_SERVICE — бит 10 → 0x400; NoNewPrivs — из NoNewPrivileges юнита
cap=$(awk '/^CapEff:/ {print $2}' "/proc/${pid:-0}/status" 2>/dev/null)
eq "возможности процесса: только CAP_NET_BIND_SERVICE" "$((16#${cap:-0}))" 1024
nnp=$(awk '/^NoNewPrivs:/ {print $2}' "/proc/${pid:-0}/status" 2>/dev/null)
eq "NoNewPrivs" "${nnp:-нет}" 1
check "порт $port слушается" bash -c "ss -ltnH 'sport = :$port' | grep -q ."
# Память Xray на конфигурации пресета без клиентов и трафика — факт для compatibility.md
echo "env  память xray: VmRSS $(awk '/^VmRSS:/ {print $2, $3}' "/proc/${pid:-0}/status" 2>/dev/null), VmHWM $(awk '/^VmHWM:/ {print $2, $3}' "/proc/${pid:-0}/status" 2>/dev/null)"

# 3. Манифест прав (data-model.md §1)
perm /usr/local/lib/xm root:root 755
perm /usr/local/lib/xm/core root:root 755
ver=$(readlink /usr/local/lib/xm/core/current 2>/dev/null)
if [[ $ver =~ ^[0-9A-Za-z._-]+$ ]]; then ok "current указывает на каталог версии"; else bad "current: «$ver»"; fi
perm "/usr/local/lib/xm/core/$ver" root:root 755
perm "/usr/local/lib/xm/core/$ver/xray" root:root 755
perm /etc/xm root:root 700
perm /etc/xm/state.json root:root 600
perm /usr/local/etc/xray root:xray 750
perm /usr/local/etc/xray/config.json root:xray 640
perm /etc/systemd/system/xray.service root:root 644
perm /var/lib/xm root:root 700
perm /var/lib/xm/backups root:root 700
perm /var/lib/xm/tx root:root 700
perm /var/lib/xm/cache root:root 700

# 4. status
"$xm" status --json >"$out/status" 2>&1
# shellcheck disable=SC2016 # $p — переменная jq, не оболочки
check "status: версия Xray и порт" jq -e --argjson p "$port" \
	'.data.installed and .data.service.active == "active" and .data.versions.xray != "" and .data.port == $p and (.data.drift | not)' "$out/status"

# 5. Повторная установка — отказ с кодом 3 (ADR-0025)
"$xm" install --sni "$sni" --address "$addr" --port "$port" >"$out/again" 2>&1
rc=$?
eq "повторная установка: код" "$rc" 3

# 6. stop → start: служба и порт
"$xm" stop >"$out/stop" 2>&1
check "stop: служба неактивна" bash -c '! systemctl is-active --quiet xray.service'
check "stop: порт свободен" bash -c "! ss -ltnH 'sport = :$port' | grep -q ."
"$xm" start >"$out/start" 2>&1
check "start: служба активна" systemctl is-active --quiet xray.service

# 7. Контроль после падения (A5, ADR-0026): xm restart проходит контроль у службы, которую
# systemd уже перезапускал сам, — и когда она снова работает, и в окне ожидания авто-перезапуска
# (RestartSec=5s), где ручной перезапуск NRestarts не обнуляет. Значения счётчика — факты среды.
nrestarts() { systemctl show -p NRestarts --value xray.service; }
# shellcheck disable=SC2317 # crash и waiting вызываются через check
crash() { # crash — убить процесс и дождаться авто-перезапуска systemd (не дольше 20 с)
	local n
	n=$(nrestarts)
	systemctl kill -s SIGKILL xray.service
	for _ in $(seq 40); do
		[[ $(nrestarts) -gt $n ]] && systemctl is-active --quiet xray.service && return 0
		sleep 0.5
	done
	return 1
}
check "падение: systemd перезапустил службу сам" crash
"$xm" restart >"$out/restart" 2>&1
eq "restart после падения: код" "$?" 0
echo "env  NRestarts после ручного restart работающей службы: $(nrestarts)"
waiting() { # waiting — убить процесс и дождаться, пока systemd ждёт авто-перезапуска
	systemctl kill -s SIGKILL xray.service
	for _ in $(seq 20); do
		[[ $(systemctl show -p SubState --value xray.service) == auto-restart ]] && return 0
		sleep 0.2
	done
	return 1
}
check "падение в окне: systemd перезапустил службу сам" crash
check "падение в окне: systemd ждёт авто-перезапуска" waiting
before=$(nrestarts)
"$xm" restart >"$out/restart-window" 2>&1
eq "restart в окне авто-перезапуска: код" "$?" 0
check "restart в окне: служба активна" systemctl is-active --quiet xray.service
# Счётчик не вырос и не обнулился — restart попал в окно, а не после авто-перезапуска systemd
# (тот дал бы before+1, а ручной restart после него — 0); значение — факт compatibility.md §1.
((before > 0)) || bad "restart в окне: счётчик до restart $before, ожидался больше 0"
eq "restart в окне: NRestarts сохранён" "$(nrestarts)" "$before"

# 8. Первый профиль: установка завершается его ссылкой (секрет печатают только install, add и
# show), а xm list ссылки не содержит. Идентификатор клиента — секрет: он идёт через файл с
# правами 600, а не аргументами процесса (их видно в ps и /proc).
touch "$out/.link" && chmod 600 "$out/.link"
jq -j '"vless://" + .profiles[0].id + "@"' /etc/xm/state.json >"$out/.link" 2>/dev/null
if [[ $(wc -c <"$out/.link") -lt 20 ]]; then bad "первый профиль: в состоянии его нет"; fi
check "install: ссылка первого профиля в выводе" grep -qF -f "$out/.link" "$out/install"
"$xm" list >"$out/list" 2>&1
eq "list: код" "$?" 0
check "list: профиль profile-1" grep -q '^profile-1 ' "$out/list"
"$xm" show profile-1 >"$out/show" 2>&1
eq "show: код" "$?" 0
check "show: ссылка профиля" grep -qF -f "$out/.link" "$out/show"
# Приватный ключ REALITY не печатает ни одна команда, в том числе install и show.
jq -r '.inbounds[].reality.private_key' /etc/xm/state.json >"$out/.private" 2>/dev/null
chmod 600 "$out/.private"
if [[ -s $out/.private ]]; then
	if grep -qF -f "$out/.private" "$out/install" "$out/show"; then bad "приватный ключ в выводе install или show"; else ok "install и show без приватного ключа"; fi
else
	bad "приватный ключ не найден в состоянии"
fi

# 9. Секреты не попали в вывод команд, чьё назначение — не показывать их: значения из состояния —
# канарейка (install, add и show показывают ссылку намеренно, поэтому не проверяются). Значения
# идут через файл, а не аргументы процесса; пустой список — провал, а не «чисто».
jq -r '(.inbounds[].reality | .private_key, .public_key, .short_ids[]), (.profiles[]?.id)' /etc/xm/state.json >"$out/.secrets" 2>/dev/null
chmod 600 "$out/.secrets"
n=$(grep -c . "$out/.secrets")
if ((n < 3)); then
	bad "канарейка: в состоянии найдено $n значений, нужно не меньше 3"
else
	grep -qF -f "$out/.secrets" "$out/list" "$out/status" "$out/again" "$out/stop" "$out/start" "$out/restart" "$out/restart-window"
	case $? in
	0) bad "секрет состояния в выводе команд" ;;
	1) ok "вывод команд без секретов состояния" ;;
	*) bad "канарейка: grep не прочитал вывод команд" ;;
	esac
fi

if ((fails == 0)); then echo "l4: PASS"; else echo "l4: FAIL ($fails)"; fi
((fails == 0))
