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
# Доступно: $src — проверяемый коммит, $box — песочница, as_root — команда от root.
checks() {
  step files test -f "$src/go.mod"
}

box='' src='' step_name=start result='' new_pkgs=()
as_root() { if ((EUID == 0)); then "$@"; else sudo "$@"; fi; }
step() {
  step_name=$1
  shift
  "$@" >>"$box/log" 2>&1 || exit 1
}
cleanup() {
  local state=clean
  if ((${#new_pkgs[@]})); then
    as_root apt-get purge -y "${new_pkgs[@]}" >/dev/null 2>&1 || state=dirty
  fi
  if [[ -n $box && -d $box ]]; then
    if ((NEED_ROOT)); then as_root rm -rf "$box"; else
      chmod -R u+w "$box" 2>/dev/null
      rm -rf "$box"
    fi
    [[ -e $box ]] && state=dirty
  fi
  printf 'XM-CHECK %s %s %s %s\n' "$CHECK_ID" "${COMMIT:0:7}" "${result:-FAIL $step_name}" "$state"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Пакеты, которые поставил скрипт: разница списков dpkg до и после установки.
install_missing() {
  local t missing=() before
  for t in "${TOOLS[@]}"; do command -v "${t%%:*}" >/dev/null || missing+=("${t#*:}"); done
  ((${#missing[@]})) || return 0
  command -v apt-get >/dev/null || return 1
  before=$(dpkg-query -W -f='${Package}\n' | sort)
  as_root apt-get update -qq || return 1
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  local rc=$?
  mapfile -t new_pkgs < <(comm -13 <(printf '%s\n' "$before") <(dpkg-query -W -f='${Package}\n' | sort))
  return "$rc"
}

step_name=sandbox
box=$(mktemp -d "${TMPDIR:-/tmp}/xm-check.XXXXXX") || exit 1
chmod 700 "$box"
src=$box/src
mkdir -p "$box/tmp" "$box/home" "$box/go/mod" "$box/cache" || exit 1
export TMPDIR=$box/tmp XDG_CACHE_HOME=$box/cache GOPATH=$box/go GOMODCACHE=$box/go/mod \
  GOCACHE=$box/cache/go GOTOOLCHAIN=auto GIT_TERMINAL_PROMPT=0

step_name=sudo
need_sudo=$NEED_ROOT
for t in "${TOOLS[@]}"; do command -v "${t%%:*}" >/dev/null || need_sudo=1; done
if ((need_sudo)) && [[ $EUID != 0 ]]; then
  sudo -v || exit 1 # запрос пароля — на терминал владельца, до тихих шагов
fi
step tools install_missing
step fetch git init -q "$src"
step fetch git -C "$src" fetch -q --depth 1 "$REPO_URL" "$COMMIT"
step fetch git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
step commit test "$(git -C "$src" rev-parse HEAD 2>/dev/null)" = "$COMMIT"
checks
result=PASS
