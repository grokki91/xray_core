#!/usr/bin/env bash
# Все обязательные проверки репозитория одной командой: синтаксис, инструкции, ссылки, ADR,
# карта пакетов, реестр зависимостей, чувствительные данные, тесты tests/test-*.sh.
# Печатает только провалы и итог «checks: PASS|FAIL»; код выхода 0 — только PASS.
# Нет нужной утилиты — провал, а не пропуск. С появлением кода сюда добавляются gofmt, go vet, go test.
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

# ─── 8. Тесты; внутри теста (CHECK_NESTED) — без них, иначе check.sh запустит сам себя
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
