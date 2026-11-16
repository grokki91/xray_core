#!/usr/bin/env bash
# Тесты каркаса проверки на реальной интеграции для VPS: scripts/integration/vps.sh.
# Каркас заполняется так же, как это делает субагент integration-check (параметры и шаги),
# и запускается против локального голого репозитория вместо GitHub. Сеть и root не нужны.
# Запуск: bash tests/test-integration-skeleton.sh
# Шаги в одинарных кавычках — текст тела checks: переменные раскрывает заполненный скрипт.
# shellcheck disable=SC2016
set -u
cd "${BASH_SOURCE[0]%/*}/.." || exit 1
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
fails=0
ok() { printf '  ✓ %s\n' "$1"; }
no() {
  printf '  ✗ FAIL %s\n' "$1"
  fails=$((fails + 1))
}

# Голый репозиторий с одним коммитом; выдача коммита по SHA, как у GitHub.
git init -q "$work/seed"
printf 'module example.com/xm\n' >"$work/seed/go.mod"
git -C "$work/seed" -c user.name=t -c user.email=t@example.com add go.mod
git -C "$work/seed" -c user.name=t -c user.email=t@example.com commit -qm seed
git clone -q --bare "$work/seed" "$work/origin.git"
git -C "$work/origin.git" config uploadpack.allowAnySHA1InWant true
sha=$(git -C "$work/seed" rev-parse HEAD)

# Поддельные apt-get, dpkg-query и sudo: список установленных — файл $FAKE_DB, «установка»
# пакета кладёт одноимённую команду в $FAKE_BIN. FAKE_REMV — apt хочет удалить чужой пакет при
# установке; FAKE_UPG — apt хочет обновить стоящий пакет; FAKE_EXTRA — лишний пакет в плане
# удаления; FAKE_DEP — зависимость при установке; FAKE_SLOW — секунды «установки».
export FAKE_BIN=$work/bin FAKE_DB=$work/db PATH=$work/bin:$PATH
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/apt-get" <<'FAKE'
#!/usr/bin/env bash
sim=0
[[ $1 == -s ]] && { sim=1; shift; }
cmd=$1
shift
pkgs=()
for a; do [[ $a == -* ]] || pkgs+=("$a"); done
case $cmd in
update) ;;
install)
  if ((sim)); then
    for p in "${pkgs[@]}" ${FAKE_DEP:-}; do echo "Inst $p (1.0 fake)"; done
    [[ -n ${FAKE_REMV:-} ]] && echo "Remv $FAKE_REMV [1.0]"
    [[ -n ${FAKE_UPG:-} ]] && echo "Inst $FAKE_UPG [1.0] (2.0 fake)"
    exit 0
  fi
  for p in "${pkgs[@]}" ${FAKE_DEP:-}; do
    sleep "${FAKE_SLOW:-0}"
    echo "$p" >>"$FAKE_DB"
    printf '#!/bin/sh\n' >"$FAKE_BIN/$p"
    chmod +x "$FAKE_BIN/$p"
  done ;;
purge)
  if ((sim)); then
    for p in "${pkgs[@]}" ${FAKE_EXTRA:-}; do echo "Purg $p [1.0]"; done
    exit 0
  fi
  for p in "${pkgs[@]}"; do
    grep -vx "$p" "$FAKE_DB" >"$FAKE_DB.new"
    mv "$FAKE_DB.new" "$FAKE_DB"
    rm -f "$FAKE_BIN/$p"
  done ;;
*) exit 100 ;;
esac
FAKE
cat >"$FAKE_BIN/dpkg-query" <<'FAKE'
#!/bin/sh
sed 's/^/ii  /' "$FAKE_DB"
printf 'rc  xmfake-old\n'
FAKE
cat >"$FAKE_BIN/sudo" <<'FAKE'
#!/bin/sh
case $1 in -v | -k) exit 0 ;; esac
exec "$@"
FAKE
chmod +x "$FAKE_BIN"/*

# fill ФАЙЛ КОММИТ ШАГ… — заполнить каркас: параметры ($tools — строка TOOLS) и тело checks
tools='(git)'
fill() {
  local out=$1 commit=$2 body
  shift 2
  body=$(printf '  %s\n' "$@")
  awk -v id=t-1 -v url="file://$work/origin.git" -v commit="$commit" -v tools="$tools" -v body="$body" '
    /^CHECK_ID=/ { print "CHECK_ID=\x27" id "\x27"; next }
    /^REPO_URL=/ { print "REPO_URL=\x27" url "\x27"; next }
    /^COMMIT=/ { print "COMMIT=\x27" commit "\x27"; next }
    /^TOOLS=/ { print "TOOLS=" tools; next }
    /^checks\(\) \{$/ { print; print body; skip = 1; next }
    skip && /^\}$/ { skip = 0 }
    !skip { print }
  ' scripts/integration/vps.sh >"$out"
}

# run ИМЯ ОЖИДАЕМОЕ КОММИТ ШАГ… — stdout — ровно одна ожидаемая строка, песочница удалена
run() {
  local name=$1 want=$2 commit=$3 got
  shift 3
  fill "$work/s.sh" "$commit" "$@"
  mkdir -p "$work/tmp"
  got=$(TMPDIR="$work/tmp" bash "$work/s.sh" 2>"$work/err" </dev/null)
  if [[ $got != "$want" ]]; then
    no "$name: «$got», ожидалось «$want» — $(head -n 3 "$work/err" | tr '\n' ' ')"
  elif [[ -n $(find "$work/tmp" -mindepth 1 -print -quit) ]]; then
    no "$name: песочница не удалена"
  else
    ok "$name"
  fi
  rm -rf "$work/tmp"
}

echo "каркас VPS"
run "успешные шаги → PASS clean" "XM-CHECK t-1 ${sha:0:7} PASS clean" "$sha" \
  'step files test -f "$src/go.mod"' \
  'step cache mkdir -p "$GOMODCACHE/ro"' \
  'step cache touch "$GOMODCACHE/ro/f"' \
  'step cache chmod a-w "$GOMODCACHE/ro"'
run "провал шага → его имя" "XM-CHECK t-1 ${sha:0:7} FAIL files clean" "$sha" \
  'step files test -f "$src/нет-такого"'
run "вывод шага не попадает в ответ" "XM-CHECK t-1 ${sha:0:7} PASS clean" "$sha" \
  'step noisy echo 203.0.113.7'
run "чужой коммит → FAIL fetch" "XM-CHECK t-1 0000000 FAIL fetch clean" \
  0000000000000000000000000000000000000000 'step files true'

# db ОЖИДАЕМОЕ — список «установленных» пакетов после прогона
db() {
  local got
  got=$(tr '\n' ' ' <"$FAKE_DB")
  if [[ $got == "$1" ]]; then ok "  пакеты: «$1»"; else no "  пакеты: «$got», ожидалось «$1»"; fi
}

echo "каркас VPS: пакеты"
tools='(git xmfake)'
printf 'owner-pkg\n' >"$FAKE_DB"
run "недостающий пакет ставится и удаляется" "XM-CHECK t-1 ${sha:0:7} PASS clean" "$sha" \
  'step use xmfake'
FAKE_DEP=xmfake-lib
export FAKE_DEP
run "зависимость тоже удаляется" "XM-CHECK t-1 ${sha:0:7} PASS clean" "$sha" 'step use xmfake'
unset FAKE_DEP
db "owner-pkg "
FAKE_REMV=owner-pkg run "apt удалил бы чужой пакет → отказ до установки" \
  "XM-CHECK t-1 ${sha:0:7} FAIL tools clean" "$sha" 'step use xmfake'
db "owner-pkg "
FAKE_EXTRA=owner-pkg run "лишний пакет в плане удаления → dirty, ничего не удалено" \
  "XM-CHECK t-1 ${sha:0:7} PASS dirty" "$sha" 'step use xmfake'
db "owner-pkg xmfake "
printf 'owner-pkg\n' >"$FAKE_DB"
rm -f "$FAKE_BIN/xmfake"
FAKE_UPG=owner-pkg run "apt обновил бы стоящий пакет → отказ до установки" \
  "XM-CHECK t-1 ${sha:0:7} FAIL tools clean" "$sha" 'step use xmfake'
db "owner-pkg "
FAKE_DEP=xmfake-old run "пакет с оставшимися настройками (rc) → отказ до установки" \
  "XM-CHECK t-1 ${sha:0:7} FAIL tools clean" "$sha" 'step use xmfake'
db "owner-pkg "

echo "каркас VPS: окружение песочницы"
tools='(git)'
GOPROXY=off GOFLAGS=-mod=mod GIT_CONFIG_GLOBAL=$work/owner.gitconfig run "конфигурация владельца не читается" \
  "XM-CHECK t-1 ${sha:0:7} PASS clean" "$sha" \
  'step home test "$HOME" = "$box/home"' \
  'step tmp test "$TMPDIR" = "$box/tmp"' \
  'step git test "$GIT_CONFIG_GLOBAL" = /dev/null' \
  'step go test -z "${GOPROXY:-}${GOFLAGS:-}" -a "$GOENV" = off' \
  'step root as_root sh -c "test \"\$HOME\" = \"$box/home\" -a \"\$GOENV\" = off"'

# Фоновый процесс неинтерактивного bash игнорирует SIGINT, поэтому — TERM: ловушка та же.
echo "каркас VPS: прерывание"
tools='(git)'
fill "$work/s.sh" "$sha" 'step wait sleep 2'
mkdir -p "$work/tmp"
TMPDIR="$work/tmp" bash "$work/s.sh" >"$work/out" 2>/dev/null </dev/null &
pid=$!
sleep 1
kill -TERM "$pid"
wait "$pid"
got=$(cat "$work/out")
want="XM-CHECK t-1 ${sha:0:7} FAIL wait clean"
if [[ $got != "$want" ]]; then no "прерывание: «$got», ожидалось «$want»"
elif [[ -n $(find "$work/tmp" -mindepth 1 -print -quit) ]]; then no "прерывание: песочница не удалена"
else ok "прерывание → строка и уборка"; fi
rm -rf "$work/tmp"

tools='(git xmfake)'
fill "$work/s.sh" "$sha" 'step use xmfake'
mkdir -p "$work/tmp"
FAKE_SLOW=2 TMPDIR="$work/tmp" bash "$work/s.sh" >"$work/out" 2>/dev/null </dev/null &
pid=$!
sleep 1
kill -TERM "$pid"
wait "$pid"
got=$(cat "$work/out")
want="XM-CHECK t-1 ${sha:0:7} FAIL tools clean"
if [[ $got != "$want" ]]; then no "прерывание установки: «$got», ожидалось «$want»"
else ok "прерывание установки → строка, поставленное удалено"; fi
db "owner-pkg "
rm -rf "$work/tmp"

if ((fails)); then
  echo "integration skeleton: FAIL ($fails)"
  exit 1
fi
echo "integration skeleton: PASS"
