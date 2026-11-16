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
perm() { # perm ПУТЬ ВЛАДЕЛЕЦ:ГРУППА ПРАВА — строка манифеста data-model.md §1
	local got
	got=$(stat -c '%U:%G %a' "$1" 2>/dev/null)
	if [[ $got == "$2 $3" ]]; then ok "права $1"; else bad "права $1: $got, ожидалось $2 $3"; fi
}

sni=example.com
addr=192.0.2.10 # документационный адрес RFC 5737: проверке нужна форма, а не достижимость
port=443

# 1. Установка
"$xm" install --sni "$sni" --address "$addr" --port "$port" >"$out/install" 2>&1
rc=$?
[[ $rc == 0 ]] && ok "install: код 0" || bad "install: код $rc"

# 2. Служба и процесс
check "служба активна" systemctl is-active --quiet xray.service
check "автозапуск включён" systemctl is-enabled --quiet xray.service
pid=$(systemctl show -p MainPID --value xray.service)
user=$(ps -o user= -p "${pid:-0}" 2>/dev/null | tr -d ' ')
[[ $user == xray ]] && ok "процесс от пользователя xray" || bad "процесс от пользователя: $user"
# CAP_NET_BIND_SERVICE — бит 10 → 0x400; NoNewPrivs — из NoNewPrivileges юнита
cap=$(awk '/^CapEff:/ {print $2}' "/proc/${pid:-0}/status" 2>/dev/null)
[[ $((16#${cap:-0})) == 1024 ]] && ok "возможности процесса: только CAP_NET_BIND_SERVICE" || bad "возможности процесса: ${cap:-нет}"
nnp=$(awk '/^NoNewPrivs:/ {print $2}' "/proc/${pid:-0}/status" 2>/dev/null)
[[ $nnp == 1 ]] && ok "NoNewPrivs" || bad "NoNewPrivs: ${nnp:-нет}"
check "порт $port слушается" bash -c "ss -ltnH 'sport = :$port' | grep -q ."

# 3. Манифест прав (data-model.md §1)
perm /usr/local/lib/xm root:root 755
perm /usr/local/lib/xm/core root:root 755
ver=$(readlink /usr/local/lib/xm/core/current 2>/dev/null)
[[ $ver =~ ^[0-9A-Za-z._-]+$ ]] && ok "current указывает на каталог версии" || bad "current: $ver"
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
check "status: версия Xray и порт" jq -e --argjson p "$port" \
	'.data.installed and .data.service.active == "active" and .data.versions.xray != "" and .data.port == $p and (.data.drift | not)' "$out/status"

# 5. Повторная установка — отказ с кодом 3 (ADR-0025)
"$xm" install --sni "$sni" --address "$addr" --port "$port" >"$out/again" 2>&1
rc=$?
[[ $rc == 3 ]] && ok "повторная установка: код 3" || bad "повторная установка: код $rc"

# 6. stop → start: служба и порт
"$xm" stop >"$out/stop" 2>&1
check "stop: служба неактивна" bash -c '! systemctl is-active --quiet xray.service'
check "stop: порт свободен" bash -c "! ss -ltnH 'sport = :$port' | grep -q ."
"$xm" start >"$out/start" 2>&1
check "start: служба активна" systemctl is-active --quiet xray.service

# 7. Секреты не попали в вывод команд: значения из состояния — канарейка. Значения идут через
# файл, а не аргументы процесса; пустой список — провал, а не «чисто».
jq -r '(.inbounds[].reality | .private_key, .public_key, .short_ids[]), (.profiles[]?.id)' /etc/xm/state.json >"$out/.secrets" 2>/dev/null
chmod 600 "$out/.secrets"
n=$(grep -c . "$out/.secrets")
if ((n < 3)); then
	bad "канарейка: в состоянии найдено $n значений, нужно не меньше 3"
elif grep -qF -f "$out/.secrets" "$out/install" "$out/status" "$out/again" "$out/stop" "$out/start"; then
	bad "секрет состояния в выводе команд"
else
	ok "вывод команд без секретов состояния"
fi

if ((fails == 0)); then echo "l4: PASS"; else echo "l4: FAIL ($fails)"; fi
((fails == 0))
