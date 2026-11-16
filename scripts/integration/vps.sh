#!/usr/bin/env bash
# Каркас скрипта проверки на реальной интеграции для VPS (Ubuntu, bash). Контракт —
# docs/dev/integration-check.md. Субагент integration-check меняет только параметры ниже и
# тело checks; остальное — общее для всех проверок и покрыто tests/test-integration-skeleton.sh.
#
# Что делает: песочница во временном каталоге → недостающие пакеты через apt → проверяемый
# коммит по SHA → шаги checks → удаление песочницы и установленных пакетов. Вывод шагов идёт
# в журнал песочницы и удаляется вместе с ней; на stdout — ровно одна строка:
#   XM-CHECK <CHECK_ID> <SHA7> PASS|FAIL <шаг> clean|dirty
# Рабочую установку xm и Xray, юниты, фаервол и публичные порты скрипт не трогает.
set -u
CHECK_ID='example-1'                                   # имя проверки; новая версия — новый суффикс
REPO_URL='https://github.com/grokki91/xray_core.git'   # публичный репозиторий проекта
COMMIT='0000000000000000000000000000000000000000'      # полный SHA проверяемого коммита
NEED_ROOT=0                                            # 1 — шагам нужен root (через sudo)
TOOLS=(git)                                            # команда или команда:пакет apt, например go:golang-go

# Шаги проверки: step <имя> <команда> <аргументы…>. Имя попадает в ответ при провале.
# Доступно: $src — проверяемый коммит, $box — песочница, as_root — команда от root с окружением
# песочницы. Ссылок из песочницы наружу шаги не создают, в дескриптор 3 (строка ответа) не пишут.
checks() {
  step files test -f "$src/go.mod"
}

box='' src='' step_name=start result='' got_sudo=0
new_pkgs=() before='' planned='' installing=0 unaccounted=0
base=${TMPDIR:-/tmp}
exec 3>&1 # строка ответа — в исходный stdout, даже если ловушка сработала внутри шага
box_env=() # окружение песочницы; as_root передаёт его явно: sudo сбрасывает окружение
as_root() { if ((EUID == 0)); then "$@"; else sudo env "${box_env[@]}" "$@"; fi; }
step() {
  step_name=$1
  shift
  "$@" >>"$box/log" 2>&1 || exit 1
}
pkgs_in() { # pkgs_in ШАБЛОН — пакеты, чьё состояние dpkg (ii, rc, iU…) подходит под шаблон awk
  dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk -v re="$1" '$1 ~ re { print $2 }' | sort
}
# Поставленное скриптом — было в плане apt как новое, до установки отсутствовало, теперь есть в
# любом состоянии, кроме «не установлен»: недоустановленное после сбоя apt тоже убирается.
count_new() { mapfile -t new_pkgs < <(comm -13 <(printf '%s\n' "$before") <(pkgs_in '^.[^n]') | comm -12 - <(printf '%s\n' "$planned")); }

# Удаляются только пакеты, поставленные скриптом, и только если apt не тронет ничего сверх них.
purge_new() {
  ((installing)) && count_new
  ((${#new_pkgs[@]})) || return 0
  local plan want
  plan=$(as_root apt-get -s purge "${new_pkgs[@]}" 2>/dev/null | awk '$1 == "Purg" || $1 == "Remv" { print $2 }' | sort)
  want=$(printf '%s\n' "${new_pkgs[@]}" | sort)
  [[ $plan == "$want" ]] || return 1
  as_root env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${new_pkgs[@]}" >/dev/null 2>&1
}
cleanup() {
  local state=clean
  purge_new || state=dirty
  ((unaccounted)) && state=dirty
  if [[ -n $box && -d $box && $box == "$base"/xm-check.?????? ]]; then
    if ((NEED_ROOT)); then as_root rm -rf "$box"; else
      chmod -R u+w "$box" 2>/dev/null
      rm -rf "$box"
    fi
  fi
  [[ -n $box && -e $box ]] && state=dirty
  ((got_sudo)) && sudo -k
  printf 'XM-CHECK %s %s %s %s\n' "$CHECK_ID" "${COMMIT:0:7}" "${result:-FAIL $step_name}" "$state" >&3
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Установка отказывает, если apt удалил бы или обновил стоящий пакет, или поставил бы пакет,
# от которого у владельца остались файлы настроек (состояние rc): purge стёр бы их.
install_missing() {
  local t missing=() rc plan
  for t in "${TOOLS[@]}"; do command -v "${t%%:*}" >/dev/null || missing+=("${t#*:}"); done
  ((${#missing[@]})) || return 0
  command -v apt-get >/dev/null || return 1
  as_root apt-get update -qq || return 1
  plan=$(as_root apt-get -s install --no-install-recommends "${missing[@]}") || return 1
  awk '$1 == "Remv" || ($1 == "Inst" && $3 ~ /^\[/) { bad = 1 } END { exit bad }' <<<"$plan" || return 1
  planned=$(awk '$1 == "Inst" { print $2 }' <<<"$plan" | sort)
  [[ -n $planned && -z $(comm -12 <(printf '%s\n' "$planned") <(pkgs_in '^rc$')) ]] || return 1
  before=$(pkgs_in '^.[^n]')
  installing=1
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-remove "${missing[@]}"
  rc=$?
  count_new
  installing=0
  # Установка прошла, а учёт не сошёлся с планом (например, имена с архитектурой) — уборка неполна.
  ((rc == 0)) && [[ $(printf '%s\n' "${new_pkgs[@]}") != "$planned" ]] && unaccounted=1
  return "$rc"
}

step_name=sandbox
box=$(mktemp -d "$base/xm-check.XXXXXX") || exit 1
readonly box base
src=$box/src
readonly src
chmod 700 "$box"
mkdir -p "$box/tmp" "$box/home" "$box/config" "$box/cache" "$box/go/mod" || exit 1
# Конфигурация владельца (git, go) не читается, кэши и временные файлы — только в песочнице.
unset GOFLAGS GOPROXY GOSUMDB GONOSUMDB GONOPROXY GOPRIVATE GOINSECURE GOENV
box_env=(HOME="$box/home" XDG_CONFIG_HOME="$box/config" XDG_CACHE_HOME="$box/cache"
  TMPDIR="$box/tmp" GOPATH="$box/go" GOMODCACHE="$box/go/mod" GOCACHE="$box/cache/go"
  GOENV=off GOTOOLCHAIN=auto GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0)
export "${box_env[@]}"

step_name=sudo
need_sudo=$NEED_ROOT
for t in "${TOOLS[@]}"; do command -v "${t%%:*}" >/dev/null || need_sudo=1; done
if ((need_sudo)) && [[ $EUID != 0 ]]; then
  sudo -v || exit 1 # запрос пароля — на терминал владельца, до тихих шагов
  got_sudo=1
fi
step tools install_missing
step fetch git init -q "$src"
step fetch git -C "$src" fetch -q --depth 1 "$REPO_URL" "$COMMIT"
step fetch git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
step commit test "$(git -C "$src" rev-parse HEAD 2>/dev/null)" = "$COMMIT"
checks
result=PASS
