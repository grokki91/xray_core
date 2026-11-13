#!/usr/bin/env bash
# PreToolUse (Bash и инструменты GitHub): всё, что публикует данные, — git commit, git push,
# gh pr|issue|release, создание и правка PR, комментарии, запись файлов через GitHub — проходит
# только при зелёном scripts/check.sh; текст вызова (сообщение коммита, тело PR) сканируется на
# чувствительные данные. Отказ — код 2, причины в stderr. Без jq публикация не пропускается.
input=$(cat)
grep -qE 'git|gh[[:space:]]|mcp__github__' <<<"$input" || exit 0
command -v jq >/dev/null 2>&1 || {
  echo "publish-guard: нужен jq — без него проверка публикации невозможна" >&2
  exit 2
}
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
tool=$(jq -r '.tool_name // empty' <<<"$input")
case $tool in
  Bash)
    text=$(jq -r '.tool_input.command // empty' <<<"$input")
    re='(^|[^[:alnum:]_.-])(git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+(commit|push)|gh[[:space:]]+(pr|issue|release)[[:space:]]+(create|edit|comment))([[:space:]]|$)'
    [[ $text =~ $re ]] || exit 0
    ;;
  mcp__github__create_* | mcp__github__update_* | mcp__github__push_files | mcp__github__add_* | \
    mcp__github__issue_write | mcp__github__sub_issue_write | mcp__github__pull_request_review_write)
    text=$(jq -r '[.tool_input | .. | strings] | join("\n")' <<<"$input")
    ;;
  *) exit 0 ;;
esac
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
# Локальные пути /tmp/… и /root/… несут идентификатор сессии, а не данные установки.
printf '%s\n' "$text" | sed -E "s#/(tmp|root)/[^[:space:]'\"]*##g" >"$tmp"
out=$(bash "$root/scripts/check.sh" "$tmp" 2>&1) && exit 0
printf '%s\n' "Публикация остановлена: scripts/check.sh не прошёл — исправь и повтори." "$out" >&2
exit 2
