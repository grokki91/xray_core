#!/usr/bin/env bash
# Все обязательные проверки репозитория одной командой: синтаксис, инструкции, ссылки, ADR,
# карта пакетов, реестр зависимостей, правила workflow CI, чувствительные данные, Go (gofmt, go vet, go test),
# тесты tests/test-*.sh. Печатает только провалы и итог «checks: PASS|FAIL»; код выхода 0 — только PASS.
# Нет нужной утилиты — провал, а не пропуск. Проверки Go — для модуля с go.mod в корне.
#   bash scripts/check.sh [ФАЙЛ…]   ФАЙЛ — дополнительный текст для сканера (сообщение коммита, тело PR)
set -u
export LC_ALL=C.UTF-8
extra=()
for f in "$@"; do extra+=("$(realpath "$f")"); done
cd "${BASH_SOURCE[0]%/*}/.." || exit 1
fails=0
bad() { printf '  ✗ %s\n' "$*"; fails=$((fails + 1)); }
files() { git ls-files -co --exclude-standard "$@"; }
limit() { # limit ФАЙЛ ПРЕДЕЛ_СТРОК
  local n
  n=$(wc -l <"$1")
  ((n <= $2)) || bad "$1: $n строк, предел $2 (docs/dev/ai-ecosystem.md §2)"
}
front() { sed -n '1{/^---$/!q};2,/^---$/p' "$1"; } # фронтматтер без первой строки

for t in git jq grep sed awk timeout; do command -v "$t" >/dev/null || bad "нет утилиты $t"; done

# ─── 1. Синтаксис
while IFS= read -r f; do
  [[ -f $f ]] || continue
  bash -n "$f" 2>/dev/null || bad "bash -n $f"
done < <(files '*.sh')
while IFS= read -r f; do
  [[ -f $f ]] || continue
  jq empty "$f" 2>/dev/null || bad "JSON не разбирается: $f"
done < <(files '*.json')
for f in .claude/hooks/*.sh; do
  [[ -f $f ]] || continue
  [[ -x $f ]] || bad "$f: не исполняемый"
done

# ─── 2. Инструкции: пределы размера и фронтматтер
for pair in AGENTS.md:150 CLAUDE.md:40 README.md:90; do
  [[ -f ${pair%:*} ]] && limit "${pair%:*}" "${pair#*:}"
done
for f in .claude/rules/*.md; do
  [[ -f $f ]] || continue
  limit "$f" 40
  front "$f" | grep -q '^paths:' || bad "$f: нет фронтматтера с paths"
done
for f in .claude/skills/*/SKILL.md; do
  [[ -f $f ]] || continue
  limit "$f" 150
  d=${f%/SKILL.md}
  d=${d##*/}
  [[ $(front "$f" | sed -n 's/^name:[[:space:]]*//p') == "$d" ]] || bad "$f: name ≠ $d"
  n=$(front "$f" | sed -n 's/^description:[[:space:]]*//p' | tr -d '\n' | wc -m)
  ((n >= 1 && n <= 1024)) || bad "$f: description $n символов (1…1024)"
done
for f in .claude/agents/*.md; do
  [[ -f $f ]] || continue
  limit "$f" 60
  d=${f##*/}
  [[ $(front "$f" | sed -n 's/^name:[[:space:]]*//p') == "${d%.md}" ]] || bad "$f: name ≠ ${d%.md}"
  front "$f" | grep -q '^description:' || bad "$f: нет description"
done

# ─── 3. Ссылки Markdown и пути в обратных кавычках
while IFS= read -r f; do
  [[ -f $f ]] || continue
  dir=.
  [[ $f == */* ]] && dir=${f%/*}
  while IFS= read -r t; do
    t=${t%%#*}
    [[ -z $t || -e $dir/$t ]] || bad "$f: ссылка на несуществующий $t"
  done < <(grep -oE '\]\([^)[:space:]]+\)' "$f" | sed -E 's/^\]\(//; s/\)$//' | grep -vE '^(https?:|mailto:|#)|[<>{}]')
  while IFS= read -r t; do
    [[ -e ${t%/} ]] || bad "$f: нет пути $t"
  done < <(grep -oE '`[^`[:space:]]+`' "$f" | tr -d '`' | grep -E '^(docs|\.claude|scripts)/' | grep -vE '[*<>{}…$]' | sort -u)
done < <(files '*.md')

# ─── 4. ADR: статус, строка в указателе, уникальный номер
for f in docs/adr/[0-9][0-9][0-9][0-9]-*.md; do
  [[ -f $f ]] || continue
  grep -q '^- Статус: ' "$f" || bad "$f: нет строки «- Статус:»"
  n=${f##*/}
  n=${n%%-*}
  [[ $n == 0000 ]] || grep -qF "[$n](" docs/adr/README.md || bad "$f: нет строки в docs/adr/README.md"
done
if [[ -d docs/adr ]]; then
  dups=$(find docs/adr -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.md' -printf '%f\n' | cut -c1-4 | sort | uniq -d | tr '\n' ' ')
  [[ -z $dups ]] || bad "docs/adr: повтор номера $dups"
fi

# ─── 5. Карта пакетов: каждый internal/<имя> описан в repository.md
for d in internal/*/; do
  [[ -d $d ]] || continue
  n=${d%/}
  n=${n##*/}
  grep -qE "^  $n/" docs/architecture/repository.md || bad "internal/$n: нет строки в docs/architecture/repository.md"
done

# ─── 6. Реестр зависимостей: меняется вместе с зависимостями и CI
if base=$(git merge-base HEAD origin/main 2>/dev/null); then
  changed=$({ git diff --name-only "$base"; git ls-files -o --exclude-standard; } | sort -u)
else
  changed=$(files)
fi
if grep -qE '^(go\.(mod|sum)$|\.github/workflows/|web/vendor/)' <<<"$changed" &&
  ! grep -qx 'docs/dev/dependencies.md' <<<"$changed"; then
  bad "зависимости или CI изменены без правки docs/dev/dependencies.md"
fi

# ─── 6а. Workflow CI: правила конвейера (docs/security/policy.md §6)
run_subst() { # строки run:, где есть подстановка ${{ }}
  awk 'inrun { if ($0 ~ /^[[:space:]]*$/) next
               if (match($0, /[^ ]/) - 1 > ri) { if (index($0, "${{")) print NR; next }
               inrun = 0 }
       /^[[:space:]]*(- )?run:/ { ri = match($0, /[^ ]/) - 1; s = $0; sub(/^[^:]*run:/, "", s)
               if (index(s, "${{")) print NR; inrun = (s ~ /^[[:space:]]*[|>]/) }' "$1"
}
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  [[ -f $f ]] || continue
  ! grep -qE '^[[:space:]]*(pull_request_target|workflow_run)[[:space:]]*:' "$f" ||
    bad "$f: событие pull_request_target или workflow_run"
  perms=$(awk '/^permissions:/ { p = 1; sub(/^permissions:[[:space:]]*/, ""); if ($0 != "") print; next }
               p && /^[[:space:]]/ { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if ($0 != "") print; next }
               { p = 0 }' "$f")
  [[ $perms == 'contents: read' ]] || bad "$f: на уровне workflow нужно ровно «permissions: contents: read»"
  ! grep -nE '^[[:space:]]*(- )?uses:' "$f" | grep -vqE 'uses:[[:space:]]*[^@[:space:]]+@[0-9a-f]{40}([[:space:]]|$)' ||
    bad "$f: действие не зафиксировано по хэшу коммита"
  ! grep -qE 'secrets\.|github\.token' "$f" || bad "$f: секрет в задании проверок"
  lines=$(run_subst "$f" | tr '\n' ' ')
  [[ -z $lines ]] || bad "$f: подстановка \${{ }} в run: (строки $lines) — данные только через env:"
  co=$(grep -cE 'uses:[[:space:]]*actions/checkout@' "$f")
  pc=$(grep -cE '^[[:space:]]*persist-credentials:[[:space:]]*false[[:space:]]*$' "$f")
  ((co == pc)) || bad "$f: actions/checkout без persist-credentials: false"
  ! grep -q 'gitleaks' "$f" || grep -q -- '--ignore-gitleaks-allow' "$f" || bad "$f: gitleaks без --ignore-gitleaks-allow"
done
for f in .gitleaksignore .gitleaks.toml; do
  [[ ! -e $f ]] || bad "$f: списки исключений gitleaks запрещены (docs/security/secrets.md §4)"
done

# ─── 7. Чувствительные данные
guard() {
  local out
  out=$(bash scripts/guard.sh "$@" 2>&1) && return 0
  while IFS= read -r l; do
    [[ -n $l ]] || continue
    printf '%s\n' "$l"
    fails=$((fails + 1))
  done <<<"$out"
}
guard --branch
((${#extra[@]})) && guard --text "${extra[@]}"

# ─── 8. Go: форматирование, go vet, тесты (в них и тест графа импортов)
# Переменные окружения Go, которые отключают тесты или проверку сумм, сбрасываются: иначе PASS ложный.
if [[ -f go.mod ]]; then
  export GOFLAGS='' GOSUMDB=sum.golang.org GONOSUMDB='' GONOSUMCHECK='' GOINSECURE='' GOPRIVATE=''
  if command -v go >/dev/null; then
    mapfile -t gofiles < <(files '*.go')
    unformatted=$( ((${#gofiles[@]})) && gofmt -l "${gofiles[@]}" 2>&1)
    [[ -z $unformatted ]] || bad "gofmt: $(tr '\n' ' ' <<<"$unformatted")"
    out=$(go vet ./... 2>&1) || bad "go vet: $(head -n 5 <<<"$out")"
    out=$(go test ./... 2>&1) || bad "go test: $(grep -m 5 -E 'FAIL|panic|error' <<<"$out" || tail -n 5 <<<"$out")"
  else
    bad "нет утилиты go"
  fi
fi

# ─── 9. Тесты; внутри теста (CHECK_NESTED) — без них, иначе check.sh запустит сам себя
if [[ -z ${CHECK_NESTED:-} ]]; then
  export CHECK_NESTED=1
  for t in tests/test-*.sh; do
    [[ -f $t ]] || continue
    out=$(timeout 120 bash "$t" 2>&1) || bad "$t: $(grep -m 1 -E 'FAIL|✗' <<<"$out" || tail -n 1 <<<"$out")"
  done
fi

if ((fails)); then
  echo "checks: FAIL"
  exit 1
fi
echo "checks: PASS"
