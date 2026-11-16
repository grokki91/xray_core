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

# fill ФАЙЛ КОММИТ ШАГ… — заполнить каркас: параметры и тело checks
fill() {
  local out=$1 commit=$2 body
  shift 2
  body=$(printf '  %s\n' "$@")
  awk -v id=t-1 -v url="file://$work/origin.git" -v commit="$commit" -v body="$body" '
    /^CHECK_ID=/ { print "CHECK_ID=\x27" id "\x27"; next }
    /^REPO_URL=/ { print "REPO_URL=\x27" url "\x27"; next }
    /^COMMIT=/ { print "COMMIT=\x27" commit "\x27"; next }
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

if ((fails)); then
  echo "integration skeleton: FAIL ($fails)"
  exit 1
fi
echo "integration skeleton: PASS"
