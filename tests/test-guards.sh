#!/usr/bin/env bash
# Тесты сканера scripts/guard.sh и хуков .claude/hooks/*.sh. Запуск: bash tests/test-guards.sh
# Образцы «секретов» собираются из частей во время теста: в файле их нет, сканер репозитория
# на этот файл не срабатывает. Хуки проверяются на временной копии репозитория.
set -u
cd "${BASH_SOURCE[0]%/*}/.." || exit 1
repo=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TMPDIR=$work
fails=0
ok() { printf '  ✓ %s\n' "$1"; }
no() {
  printf '  ✗ FAIL %s\n' "$1"
  fails=$((fails + 1))
}
# expect КОД ИМЯ КОМАНДА… — команда должна завершиться с этим кодом
expect() {
  local want=$1 name=$2 got
  shift 2
  "$@" >"$work/out" 2>&1
  got=$?
  if [[ $got == "$want" ]]; then ok "$name"; else no "$name: код $got, ожидался $want — $(head -n 3 "$work/out" | tr '\n' ' ')"; fi
}

# ─── Образцы
pub4="93.184"".216.34"
pub6="2a01:4f8"":c17::1"
uuid="3f2b8c1a-9d4e""-4f6a-8b7c-1a2b3c4d5e6f"
key=$(printf 'k%.0s' {1..20})$(printf 'Z%.0s' {1..23})
dummy_key=$(printf 'A%.0s' {1..43})
token="gh""p_$(printf 'a1%.0s' {1..18})"
link="vless:""//user-secret@example.com:443"
pem="-----BEGIN OPENSSH PRIVATE"" KEY-----"

text() { printf '%s\n' "$1" >"$work/t.txt"; }
scan_fail() {
  text "$2"
  expect 1 "guard ловит: $1" bash scripts/guard.sh --text "$work/t.txt"
}
scan_pass() {
  text "$2"
  expect 0 "guard пропускает: $1" bash scripts/guard.sh --text "$work/t.txt"
}

echo "guard --text"
scan_fail "публичный IPv4" "server $pub4 port 443"
scan_fail "глобальный IPv6" "listen [$pub6]:443"
scan_fail "настоящий UUID" "id: $uuid"
scan_fail "блок приватного ключа" "$pem"
scan_fail "ключ REALITY" "\"privateKey\": \"$key\""
scan_fail "ключ в ссылке" "pbk=$key&fp=chrome"
scan_fail "токен GitHub" "export TOKEN=$token"
scan_fail "ссылка с учётными данными" "$link"
scan_pass "документационные и частные IPv4, резолвер" "203.0.113.7 192.0.2.1 10.0.0.1 127.0.0.1 1.1.1.1 0.0.0.0"
scan_pass "документационный IPv6" "2001:db8::10"
scan_pass "фиктивный UUID" "00000000-0000-4000-8000-000000000001"
scan_pass "заглушка ключа" "\"private_key\": \"$dummy_key\""
scan_pass "ссылка с фиктивным UUID" "vless:""//00000000-0000-4000-8000-000000000001@example.com:443?type=xhttp"
scan_pass "версии и хэши" "Xray v26.11.9, Go 1.27, sing-box 1.14.4, коммит 8cdf7bf"

text "id: $uuid at $pub4"
out=$(bash scripts/guard.sh --text "$work/t.txt" 2>&1)
if grep -qF -e "$uuid" -e "$pub4" <<<"$out"; then no "guard не печатает значение целиком"; else ok "guard не печатает значение целиком"; fi

# ─── Временная копия репозитория: сканер по ветке и хуки
copy=$work/repo
mkdir -p "$copy/.claude" "$copy/docs"
cp -r scripts "$copy/"
cp -r .claude/hooks "$copy/.claude/"
git -C "$copy" init -q
git -C "$copy" -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m init
export CLAUDE_PROJECT_DIR=$copy

echo "guard --branch"
expect 0 "чистое дерево" bash -c "cd '$copy' && bash scripts/guard.sh --branch"
printf 'addr = %s\n' "$pub4" >"$copy/notes.txt"
expect 1 "адрес в новом файле" bash -c "cd '$copy' && bash scripts/guard.sh --branch"
rm "$copy/notes.txt"
: >"$copy/.env"
expect 1 "файл .env" bash -c "cd '$copy' && bash scripts/guard.sh --branch"
rm "$copy/.env"
: >"$copy/.env.example"
expect 0 "файл .env.example" bash -c "cd '$copy' && bash scripts/guard.sh --branch"
rm "$copy/.env.example"

hook() { # hook ИМЯ JSON — вход хука со stdin
  local h=$1
  shift
  bash "$copy/.claude/hooks/$h.sh" <<<"$1"
}
bash_in() { jq -n --arg c "$1" '{session_id: "s1", tool_name: "Bash", tool_input: {command: $c}}'; }
write_in() { jq -n --arg f "$1" --arg c "$2" '{session_id: "s1", tool_name: "Write", tool_input: {file_path: $f, content: $c}}'; }
edit_in() { jq -n --arg f "$1" --arg c "$2" '{session_id: "s1", tool_name: "Edit", tool_input: {file_path: $f, old_string: "x", new_string: $c}}'; }
mcp_in() { jq -n --arg t "$1" --arg b "$2" '{session_id: "s1", tool_name: $t, tool_input: {owner: "o", repo: "r", title: "t", body: $b}}'; }

echo "publish-guard"
expect 0 "посторонняя команда" hook publish-guard "$(bash_in 'ls -la')"
expect 0 "git status не проверяется" hook publish-guard "$(bash_in 'git status')"
expect 0 "чистый git commit" hook publish-guard "$(bash_in 'git commit -m "docs: update"')"
expect 2 "git commit с адресом в сообщении" hook publish-guard "$(bash_in "git commit -m 'fix for $pub4'")"
printf '%s\n' "$uuid" >"$copy/leak.txt"
expect 2 "git push при находке в дереве" hook publish-guard "$(bash_in 'git push -u origin main')"
rm -f "$copy/leak.txt"
expect 2 "gh pr create с UUID" hook publish-guard "$(bash_in "gh pr create --title t --body '$uuid'")"
expect 2 "создание PR с UUID в теле" hook publish-guard "$(mcp_in mcp__github__create_pull_request "client $uuid")"
expect 0 "создание PR с чистым телом" hook publish-guard "$(mcp_in mcp__github__create_pull_request 'Adds docs')"
expect 0 "читающий инструмент GitHub" hook publish-guard "$(mcp_in mcp__github__list_pull_requests "$uuid")"

echo "write-guard"
expect 0 "чистая запись" hook write-guard "$(write_in "$copy/docs/a.md" 'server 203.0.113.7')"
expect 2 "запись с адресом" hook write-guard "$(write_in "$copy/docs/a.md" "server $pub4")"
expect 2 "правка с ключом" hook write-guard "$(edit_in "$copy/docs/a.md" "password: $key")"
expect 2 "файл .env" hook write-guard "$(write_in "$copy/.env" 'A=1')"
expect 2 "файл ключа" hook write-guard "$(write_in "$copy/deploy/server.key" 'x')"
expect 0 "файл .env.example" hook write-guard "$(write_in "$copy/.env.example" 'A=1')"
expect 0 "файл вне проекта" hook write-guard "$(write_in "$work/else.txt" "server $pub4")"

echo "change-notes"
out=$(hook change-notes "$(write_in "$copy/docs/architecture/overview.md" x)")
if jq -e '.hookSpecificOutput.additionalContext | test("ADR")' <<<"$out" >/dev/null 2>&1; then ok "архитектура → напоминание об ADR"; else no "архитектура → напоминание об ADR"; fi
out=$(hook change-notes "$(write_in "$copy/docs/adr/0099-x.md" x)")
if [[ -z $out ]]; then ok "повтор в той же сессии молчит"; else no "повтор в той же сессии молчит"; fi
out=$(hook change-notes "$(write_in "$copy/go.mod" x)")
if jq -e '.hookSpecificOutput.additionalContext | test("dependencies.md")' <<<"$out" >/dev/null 2>&1; then ok "go.mod → реестр зависимостей"; else no "go.mod → реестр зависимостей"; fi
out=$(hook change-notes "$(write_in "$copy/internal/redact/redact.go" x)")
if jq -e '.hookSpecificOutput.additionalContext | test("security-reviewer")' <<<"$out" >/dev/null 2>&1; then ok "чувствительный модуль → security-reviewer"; else no "чувствительный модуль → security-reviewer"; fi
out=$(hook change-notes "$(write_in "$copy/README.md" x)")
if [[ -z $out ]]; then ok "прочие файлы молчат"; else no "прочие файлы молчат"; fi

echo "check.sh"
expect 0 "временная копия проходит" bash "$copy/scripts/check.sh"
mkdir -p "$copy/internal/ghost"
: >"$copy/internal/ghost/x.go"
mkdir -p "$copy/docs/architecture"
: >"$copy/docs/architecture/repository.md"
expect 1 "пакет без строки в repository.md" bash "$copy/scripts/check.sh"
rm -rf "$copy/internal" "$copy/docs/architecture"
: >"$copy/go.mod"
expect 1 "go.mod без правки реестра" bash "$copy/scripts/check.sh"
mkdir -p "$copy/docs/dev"
: >"$copy/docs/dev/dependencies.md"
expect 0 "go.mod вместе с реестром" bash "$copy/scripts/check.sh"

if ((fails)); then
  echo "FAIL: $fails"
  exit 1
fi
echo "PASS"
