#!/usr/bin/env bash
# PreToolUse (Write, Edit, NotebookEdit): в файлы проекта не пишутся чувствительные данные и не
# создаются файлы с секретами (docs/security/secrets.md §4). Отказ — код 2, причины в stderr.
# Файлы вне проекта не проверяются. Без jq запись не пропускается.
input=$(cat)
command -v jq >/dev/null 2>&1 || {
  echo "write-guard: нужен jq — без него проверка записи невозможна" >&2
  exit 2
}
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
file=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' <<<"$input")
[[ $file == "$root"/* ]] || exit 0

case ${file##*/} in
  .env.example) ;;
  .env | .env.* | *.pem | *.key | *.p12 | *.pfx | state.json | id_rsa | id_dsa | id_ecdsa | id_ed25519)
    echo "write-guard: ${file#"$root"/} — файл с секретами в репозитории не создаётся; шаблон называется *.example или *.tmpl" >&2
    exit 2
    ;;
esac

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
jq -r '.tool_input | [.content?, .new_string?, .new_source?] | map(strings) | join("\n")' <<<"$input" >"$tmp"
out=$(bash "$root/scripts/guard.sh" --text "$tmp" 2>&1) && exit 0
printf '%s\n' "write-guard: в тексте для ${file#"$root"/} — чувствительные данные. Замени фиктивными значениями (docs/security/secrets.md §4)." "$out" >&2
exit 2
