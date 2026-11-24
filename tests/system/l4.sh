#!/usr/bin/env bash
# Системный тест L4 (docs/testing.md §2): настоящие install.sh и xm на чистой машине с systemd —
# установка, повторная установка, профили, служба, права, удаление.
# Запуск: sudo bash tests/system/l4.sh /путь/к/xm — только на одноразовой машине (исполнитель CI,
# виртуальная машина): скрипт ставит службу xray и не убирает её. Печатает «ok <шаг>» и в конце
# «l4: PASS|FAIL»; вывод xm и значения из состояния на экран не попадают (docs/security/secrets.md).
# Сценарии следующих фаз добавляются сюда же отдельными функциями.
set -u
src=${1:-} # собранный xm; ставит его install.sh, дальше команды — от установленного xm
[[ -x $src ]] || { echo "usage: sudo bash $0 /path/to/xm" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
xm=/usr/local/bin/xm
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

# Адрес сервера: у исполнителя CI публичного адреса нет, а install принимает только публичный.
# Документационный адрес (TEST-NET-3) вешается на петлевой интерфейс: он «публичный» для xm и
# достижим с самой машины — самопроверка в контроле установки (ADR-0033) подключает клиента
# к адресу из состояния. Адрес снимается при выходе.
addr=203.0.113.10
ip addr add "$addr/32" dev lo 2>/dev/null || { echo "l4: FAIL (не удалось назначить $addr на lo)"; exit 1; }
trap 'ip addr del "$addr/32" dev lo 2>/dev/null; rm -rf "$out" "${rel:-}"' EXIT
port=443

# 0. Среда: факты о машине для разбора провалов (секретов здесь нет)
# На свежем раннере systemd — PID 1, но загрузка ещё идёт (starting): xm в этом состоянии
# отказывает по предусловию, поэтому тест сначала дожидается конца загрузки (не дольше 2 минут).
timeout 120 systemctl is-system-running --wait >/dev/null 2>&1
echo "env  is-system-running: $(systemctl is-system-running 2>&1 | head -1)"
echo "env  PID 1: $(ps -p 1 -o comm= 2>&1)"
echo "env  ОС: $(sed -n 's/^PRETTY_NAME=//p' /usr/lib/os-release), память: $(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo) МиБ"

# 1. Установка настоящим install.sh. Выпуска с этой сборкой нет, поэтому сеть загрузчика
# подменена: curl из каталога-заглушки в начале PATH отдаёт файлы релиза из локального каталога,
# остальной install.sh — без изменений (скачать, сверить SHA-256, положить, запустить xm install).
# xm качает Xray сам (Go, не curl), подмена его не касается.
rel=$(mktemp -d)
mkdir "$rel/bin" "$rel/good" "$rel/bad"
cat >"$rel/bin/curl" <<'SHIM'
#!/usr/bin/env bash
# Заглушка curl для L4: -o ФАЙЛ URL релиза v0.0.0 → копия из $L4_RELEASE; остальное — отказ.
o= url=
while (($#)); do case $1 in -o) o=$2; shift 2 ;; -w) shift 2 ;; https://*) url=$1; shift ;; *) shift ;; esac; done
f=${url#https://github.com/grokki91/xray_core/releases/download/v0.0.0/}
[[ $f != "$url" && $f =~ ^[A-Za-z0-9._-]+$ && -f $L4_RELEASE/$f && -n $o ]] || exit 22
cp "$L4_RELEASE/$f" "$o"
SHIM
chmod 755 "$rel/bin/curl"
cp "$src" "$rel/good/xm-linux-amd64"
(cd "$rel/good" && sha256sum xm-linux-amd64 >SHA256SUMS)
# Испорченный бинарник: сумма — от настоящего, в файле лишний байт.
cp "$rel/good/xm-linux-amd64" "$rel/good/SHA256SUMS" "$rel/bad/" && printf x >>"$rel/bad/xm-linux-amd64"
loader() { # loader КАТАЛОГ_РЕЛИЗА ВЫВОД — install.sh с аргументами установки
	PATH="$rel/bin:$PATH" L4_RELEASE=$1 XM_VERSION=v0.0.0 bash "$root/install.sh" --address "$addr" --port "$port" >"$2" 2>&1
}
loader "$rel/bad" "$out/loader-bad"
rc=$?
if [[ $rc != 0 ]]; then ok "install.sh: испорченный бинарник отвергнут (код $rc)"; else bad "install.sh: испорченный бинарник принят"; fi
check "install.sh: отказ по сумме назван" grep -q 'SHA-256' "$out/loader-bad"
check "install.sh: после отказа нет ни xm, ни юнита" bash -c '[[ ! -e /usr/local/bin/xm && ! -e /etc/systemd/system/xray.service ]]'

loader "$rel/good" "$out/install"
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

# 5. Повторная установка тем же install.sh ничего не меняет: код 0, состояние, конфигурация и
# юнит побайтно те же, ключи не перевыпущены (они в состоянии)
sums() { sha256sum /etc/xm/state.json /usr/local/etc/xray/config.json /etc/systemd/system/xray.service | cut -d' ' -f1 | tr '\n' ' '; }
before=$(sums)
loader "$rel/good" "$out/again"
rc=$?
eq "повторная установка: код" "$rc" 0
eq "повторная установка: состояние, конфигурация и юнит не изменились" "$(sums)" "$before"

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
# Второй профиль: xm add — новая ссылка, xm list видит оба
"$xm" add >"$out/add" 2>&1
eq "add: код" "$?" 0
jq -j '"vless://" + .profiles[1].id + "@"' /etc/xm/state.json >"$out/.link2" 2>/dev/null
chmod 600 "$out/.link2"
if [[ $(wc -c <"$out/.link2") -lt 20 ]]; then bad "add: второго профиля в состоянии нет"; else check "add: ссылка второго профиля в выводе" grep -qF -f "$out/.link2" "$out/add"; fi
"$xm" list >"$out/list2" 2>&1
check "list: оба профиля" bash -c "grep -q '^profile-1 ' '$out/list2' && grep -q '^profile-2 ' '$out/list2'"
# Приватный ключ REALITY не печатает ни одна команда, в том числе install и show.
jq -r '.inbounds[].reality.private_key' /etc/xm/state.json >"$out/.private" 2>/dev/null
chmod 600 "$out/.private"
if [[ -s $out/.private ]]; then
	if grep -qF -f "$out/.private" "$out/install" "$out/again" "$out/show" "$out/add"; then bad "приватный ключ в выводе install, повторного install, show или add"; else ok "install, повторный install, show и add без приватного ключа"; fi
else
	bad "приватный ключ не найден в состоянии"
fi

# 9. Секреты не попали в вывод команд, чьё назначение — не показывать их: значения из состояния —
# канарейка (install, повторный install, add и show показывают ссылку намеренно, поэтому не проверяются). Значения
# идут через файл, а не аргументы процесса; пустой список — провал, а не «чисто».
jq -r '(.inbounds[].reality | .private_key, .public_key, .short_ids[]), (.profiles[]?.id)' /etc/xm/state.json >"$out/.secrets" 2>/dev/null
chmod 600 "$out/.secrets"
n=$(grep -c . "$out/.secrets")
if ((n < 3)); then
	bad "канарейка: в состоянии найдено $n значений, нужно не меньше 3"
else
	grep -qF -f "$out/.secrets" "$out/list" "$out/list2" "$out/status" "$out/stop" "$out/start" "$out/restart" "$out/restart-window"
	case $? in
	0) bad "секрет состояния в выводе команд" ;;
	1) ok "вывод команд без секретов состояния" ;;
	*) bad "канарейка: grep не прочитал вывод команд" ;;
	esac
fi

# 10. Токен API GitHub (ADR-0031): только в памяти xm — его нет в выводе команд, в файлах xm и
# Xray и в их записях журнала (весь журнал машины — не предмет проверки: там пишет и CI).
# Значение — через файл, не аргументом; при провале печатаются только имена файлов. Без токена
# проверять нечего.
if [[ -n ${XM_GITHUB_TOKEN:-} ]]; then
	(umask 077 && printf '%s\n' "$XM_GITHUB_TOKEN" >"$out/.token")
	journalctl --no-pager -o cat -t xm -u xray >"$out/.journal" 2>/dev/null
	hits=$(grep -rlF -f "$out/.token" "$out"/[!.]* "$out/.journal" /etc/xm /var/lib/xm /usr/local/etc/xray)
	case $? in
	0) bad "токен API найден: $(tr '\n' ' ' <<<"$hits")" ;;
	1) ok "токен API только в памяти" ;;
	*) bad "токен API: grep не прочитал файлы" ;;
	esac
else
	echo "env  XM_GITHUB_TOKEN не задан: проверка токена не выполнялась"
fi

# 11. Удаление (data-model.md §6, ADR-0042) — последним: дальше службы нет. Посторонние файлы
# рядом с путями манифеста должны остаться.
foreign=(/usr/local/lib/l4-foreign /usr/local/etc/l4-foreign /var/lib/l4-foreign /etc/l4-foreign)
for f in "${foreign[@]}"; do echo l4 >"$f"; done
"$xm" uninstall >"$out/uninstall" 2>&1
eq "uninstall: код" "$?" 0
check "uninstall: служба и юнит сняты" bash -c '! systemctl is-active --quiet xray.service && [[ ! -e /etc/systemd/system/xray.service ]]'
check "uninstall: бинарники Xray и xm сняты" bash -c '[[ ! -e /usr/local/lib/xm && ! -e /usr/local/bin/xm ]]'
check "uninstall: состояние и конфигурация на месте" test -s /etc/xm/state.json -a -s /usr/local/etc/xray/config.json
check "uninstall: снимок сделан" bash -c 'compgen -G "/var/lib/xm/backups/*-uninstall.tar.gz" >/dev/null'
check "uninstall: порт $port свободен" bash -c "! ss -ltnH 'sport = :$port' | grep -q ."
# xm удалён вместе со службой: --purge — от собранного бинарника (ADR-0042, «Последствия»).
echo no | "$src" uninstall --purge >"$out/purge-no" 2>&1
eq "uninstall --purge без слова: код" "$?" 2
check "uninstall --purge без слова: состояние на месте" test -s /etc/xm/state.json
echo purge | "$src" uninstall --purge >"$out/purge" 2>&1
eq "uninstall --purge: код" "$?" 0
gone=0
for p in /usr/local/bin/xm /usr/local/lib/xm /etc/xm /usr/local/etc/xray /etc/systemd/system/xray.service /var/lib/xm /run/xm; do
	[[ -e $p || -L $p ]] && { bad "uninstall --purge: остался $p"; gone=1; }
done
((gone == 0)) && ok "uninstall --purge: путей манифеста нет"
check "uninstall --purge: пользователя xray нет" bash -c '! getent passwd xray >/dev/null'
for f in "${foreign[@]}"; do check "посторонний файл цел: $f" grep -qx l4 "$f"; done
rm -f "${foreign[@]}"
"$src" uninstall >"$out/uninstall-again" 2>&1
eq "uninstall после --purge: не установлено, код" "$?" 3
# Вывод удаления — тоже канарейка: секретов состояния и токена API в нём нет (значения сняты до удаления).
(umask 077 && cat "$out/.secrets" >"$out/.canary")
[[ -s $out/.token ]] && cat "$out/.token" >>"$out/.canary"
grep -qF -f "$out/.canary" "$out/uninstall" "$out/purge-no" "$out/purge" "$out/uninstall-again"
case $? in
0) bad "секрет состояния в выводе uninstall" ;;
1) ok "вывод uninstall без секретов состояния" ;;
*) bad "канарейка uninstall: grep не прочитал вывод" ;;
esac

if ((fails == 0)); then echo "l4: PASS"; else echo "l4: FAIL ($fails)"; fi
((fails == 0))
