#!/usr/bin/env bash
# PostToolUse (Write, Edit): по классу изменённого файла один раз за сессию напоминает политику:
# архитектура, зависимости, конфигурация Xray, чувствительный модуль, инструкции.
# Ничего не блокирует; обязательную часть проверяет scripts/check.sh.
input=$(cat)
command -v jq >/dev/null 2>&1 || {
  echo "change-notes: нужен jq" >&2
  exit 1
}
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
file=$(jq -r '.tool_input.file_path // empty' <<<"$input")
[[ $file == "$root"/* ]] || exit 0
rel=${file#"$root"/}

case $rel in
  docs/architecture/* | docs/adr/*)
    class=architecture
    note="Изменена архитектура. Решение о границах, контракте, данных или безопасности фиксируется ADR (скил adr); сверь затронутые документы docs/architecture/ между собой и с docs/roadmap.md; перед PR — субагент architecture-reviewer."
    ;;
  go.mod | go.sum | .github/workflows/* | web/vendor/*)
    class=dependencies
    note="Изменены зависимости или CI. Нужны согласие владельца и строка в docs/dev/dependencies.md — без неё scripts/check.sh не пройдёт; действия CI фиксируются по хэшу коммита."
    ;;
  internal/config/*)
    class=config
    note="Изменена отрисовка конфигурации Xray. Правило .claude/rules/config.md: эталонный файл, проверка xray run -test, только фиктивные данные; поля сверяются с upstream по скилу xray-upstream."
    ;;
  internal/store/* | internal/security/* | internal/redact/* | internal/backup/* | internal/logging/* | \
    internal/update/* | internal/core/* | internal/platform/* | install.sh)
    class=sensitive
    note="Изменён чувствительный модуль. Действуют docs/security/policy.md и docs/security/secrets.md: данные наружу — через редактор, процессы — без оболочки, новый вид секрета — в редактор и канареечный тест; перед PR — субагент security-reviewer."
    ;;
  AGENTS.md | CLAUDE.md | .claude/*)
    class=instructions
    note="Изменены инструкции. Правило .claude/rules/agent-instructions.md: один факт — одно место, пределы размера, новая строка в docs/dev/ai-ecosystem.md §3; затем bash scripts/check.sh."
    ;;
  *) exit 0 ;;
esac

session=$(jq -r '.session_id // "none"' <<<"$input" | tr -c 'A-Za-z0-9_-' '_')
seen=${TMPDIR:-/tmp}/xm-change-notes/$session
mkdir -p "$seen" 2>/dev/null
[[ -e $seen/$class ]] && exit 0
: >"$seen/$class"

jq -n --arg note "$note" '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $note}}'
