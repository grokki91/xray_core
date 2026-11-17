#!/usr/bin/env bash
# PreToolUse (Bash и инструменты GitHub): всё, что публикует данные, — git commit, git push,
# gh pr|issue|release, создание и правка PR, комментарии, запись файлов через GitHub — проходит
# только при зелёном scripts/check.sh; текст вызова (сообщение коммита, тело PR) сканируется на
# чувствительные данные. PR создаётся только черновиком; перевод в ready и слияние — только
# владелец (ADR-0018). Отказ — код 2, причины в stderr. Без jq публикация не пропускается.
input=$(cat)
grep -qE 'git|gh[[:space:]]|mcp__github__' <<<"$input" || exit 0
command -v jq >/dev/null 2>&1 || {
  echo "publish-guard: нужен jq — без него проверка публикации невозможна" >&2
  exit 2
}
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
# Исполнитель оркестратора коммитит в своём рабочем дереве: проверяется дерево из `git -C ПУТЬ`
# (относительный — от cwd) или из cwd, если это рабочее дерево того же репозитория (общий
# каталог git совпадает); чужой репозиторий корень не подменяет.
common() { git -C "$1" rev-parse --path-format=absolute --git-common-dir 2>/dev/null; }
dir=$(jq -r '.cwd // empty' <<<"$input")
c_re='git[[:space:]]+-C[[:space:]]+([^[:space:]]+)[[:space:]]+(commit|push)([[:space:]]|$)'
if [[ $(jq -r '.tool_input.command // empty' <<<"$input") =~ $c_re ]]; then
  [[ ${BASH_REMATCH[1]} == /* || -z $dir ]] && dir=${BASH_REMATCH[1]} || dir=$dir/${BASH_REMATCH[1]}
fi
root_common=$(common "$root")
if [[ -n $dir && -n $root_common ]] && top=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null) &&
  [[ $(common "$top") == "$root_common" ]]; then
  root=$top
fi
tool=$(jq -r '.tool_name // empty' <<<"$input")
owner_only() {
  echo "publish-guard: $1 — только владелец; агент создаёт PR черновиком (ADR-0018)" >&2
  exit 2
}
draft_is() { jq -e --argjson v "$1" '.tool_input.draft == $v' <<<"$input" >/dev/null; }
case $tool in
  mcp__github__merge_pull_request | mcp__github__enable_pr_auto_merge) owner_only "слияние PR" ;;
  mcp__github__create_pull_request) draft_is true || owner_only "PR не черновиком" ;;
  mcp__github__update_pull_request) draft_is false && owner_only "перевод PR в ready" ;;
esac
# Тело PR и комментарии — только «## Что сделано» тезисами, без подписи ассистента (ADR-0018).
case $tool in
  mcp__github__create_pull_request | mcp__github__update_pull_request | mcp__github__add_issue_comment | \
    mcp__github__add_reply_to_pull_request_comment | mcp__github__add_comment_to_pending_review)
    body=$(jq -r '.tool_input.body // empty' <<<"$input")
    if grep -qiE 'Generated (with|by) \[?Claude|claude\.ai/code' <<<"$body" ||
      grep -E '^#' <<<"$body" | grep -qvxF '## Что сделано'; then
      echo "publish-guard: в PR только «## Что сделано» тезисами, без подписи и ссылки на сессию (ADR-0018)" >&2
      exit 2
    fi
    ;;
  mcp__github__push_files | mcp__github__create_or_update_file | mcp__github__delete_file)
    jq -e '.tool_input.branch == "main"' <<<"$input" >/dev/null && owner_only "запись в main"
    ;;
  Bash)
    # Строки в кавычках — данные (заголовок, тело, текст для echo), а не аргументы gh и git.
    cmd=$(jq -r '.tool_input.command // empty' <<<"$input" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
    gh='(^|[;&|(][[:space:]]*)gh([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+'
    [[ $cmd =~ ${gh}pr[[:space:]]+merge([[:space:]]|$) ]] && owner_only "слияние PR"
    [[ $cmd =~ ${gh}pr[[:space:]]+ready([[:space:]]|$) && ! $cmd =~ [[:space:]]--undo([[:space:]]|$) ]] &&
      owner_only "перевод PR в ready"
    [[ $cmd =~ ${gh}pr[[:space:]]+create([[:space:]]|$) && ! $cmd =~ [[:space:]](--draft|-d)([[:space:]]|$) ]] &&
      owner_only "PR не черновиком"
    [[ $cmd =~ ${gh}api[[:space:]] && $cmd =~ (pulls|PullRequest) && ! $cmd =~ -X[[:space:]]*GET ]] &&
      owner_only "изменение PR через gh api"
    [[ $cmd =~ ${gh}alias[[:space:]] ]] && owner_only "gh alias"
    # Переход в команде меняет дерево коммита незаметно для хука: дерево задаётся `git -C ПУТЬ`.
    cd_re='(^|[;&|(][[:space:]]*)(cd|pushd)([[:space:]]|$)'
    git_re='git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+(commit|push)([[:space:]]|$)'
    if [[ $cmd =~ $cd_re && $cmd =~ $git_re ]]; then
      echo "publish-guard: cd вместе с git commit|push не проверяется — используй git -C ПУТЬ" >&2
      exit 2
    fi
    [[ $cmd =~ git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+push[[:space:]].*([[:space:]]|:)main([[:space:]]|$) ]] &&
      owner_only "push в main"
    ;;
esac
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
