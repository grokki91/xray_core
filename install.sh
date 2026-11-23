#!/usr/bin/env bash
# Загрузчик xm (ADR-0013): проверить root, архитектуру и curl; скачать бинарник и SHA256SUMS из
# релиза; сверить SHA-256; положить в /usr/local/bin/xm; запустить «xm install» с аргументами.
# Вся остальная логика — в xm install. Тело — в функции, вызов последней строкой: оборванная
# загрузка скрипта ничего не исполняет.
#   curl -fsSL https://github.com/grokki91/xray_core/releases/latest/download/install.sh | sudo bash -s -- [аргументы xm install]
#   XM_VERSION=v0.1.0 — фиксированная версия вместо последнего релиза.
set -euo pipefail

xm_bootstrap() {
  local repo=grokki91/xray_core asset=xm-linux-amd64 target=/usr/local/bin/xm
  local version=${XM_VERSION:-} base work

  [[ $(id -u) == 0 ]] || { echo "install.sh: нужен root (запустите через sudo)" >&2; return 3; }
  [[ $(uname -m) == x86_64 ]] || { echo "install.sh: поддерживается только linux/amd64, а здесь $(uname -m)" >&2; return 3; }
  command -v curl >/dev/null || { echo "install.sh: нет curl — установите пакет curl" >&2; return 3; }
  command -v sha256sum >/dev/null || { echo "install.sh: нет sha256sum — установите пакет coreutils" >&2; return 3; }

  if [[ -z $version ]]; then
    # Тег последнего релиза — из перенаправления releases/latest: оба файла берутся из одного релиза.
    version=$(curl -fsS --proto '=https' --tlsv1.2 -o /dev/null -w '%{redirect_url}' "https://github.com/$repo/releases/latest")
    version=${version##*/}
    [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "install.sh: не удалось определить последний релиз" >&2; return 1; }
  elif [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "install.sh: XM_VERSION должна иметь вид vX.Y.Z" >&2
    return 2
  fi
  base="https://github.com/$repo/releases/download/$version"

  work=$(mktemp -d)
  # shellcheck disable=SC2064 # путь фиксируется сейчас: после выхода из функции переменной нет
  trap "rm -rf -- '$work'" EXIT

  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$asset" "$base/$asset"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/SHA256SUMS" "$base/SHA256SUMS"

  local want got
  want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS")
  [[ $want =~ ^[0-9a-f]{64}$ ]] || { echo "install.sh: в SHA256SUMS нет суммы $asset" >&2; return 1; }
  got=$(sha256sum "$work/$asset" | awk '{ print $1 }')
  if [[ $got != "$want" ]]; then
    echo "install.sh: SHA-256 $asset не совпадает с SHA256SUMS — установка отменена" >&2
    return 1
  fi

  install -m 0755 "$work/$asset" "$target"
  "$target" install "$@"
}

xm_bootstrap "$@"
