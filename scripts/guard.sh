#!/usr/bin/env bash
# Сканер чувствительных данных (docs/security/secrets.md §4): адреса, UUID, ключи, токены,
# ссылки с учётными данными, запретные файлы. Исключений нет: найденное убирается из текста.
#   scripts/guard.sh --branch         дерево репозитория, новые файлы, коммиты ветки (строки и сообщения)
#   scripts/guard.sh --text ФАЙЛ…     произвольный текст: сообщение коммита, тело PR, содержимое записи
# Находки — строками «  ✗ …» со значением под маской; код выхода 1 — находки есть.
set -u
export LC_ALL=C.UTF-8
fails=0
bad() { printf '  ✗ %s\n' "$*"; fails=$((fails + 1)); }

# Допустимые IPv4: документационные (RFC 5737), петля, частные, CGNAT, link-local, общеизвестные резолверы.
ip4_ok() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  ((10#$a > 255 || 10#$b > 255 || 10#$c > 255 || 10#$d > 255)) && return 0 # не адрес
  case $1 in
    0.0.0.0 | 127.* | 10.* | 192.168.* | 169.254.* | 192.0.2.* | 198.51.100.* | 203.0.113.* | 255.*) return 0 ;;
    1.1.1.1 | 1.0.0.1 | 8.8.8.8 | 8.8.4.4 | 9.9.9.9 | 149.112.112.112) return 0 ;;
  esac
  [[ $a == 172 ]] && ((10#$b >= 16 && 10#$b <= 31)) && return 0
  [[ $a == 100 ]] && ((10#$b >= 64 && 10#$b <= 127)) && return 0
  return 1
}

# scan МЕТКА — текст со stdin.
scan() {
  local src=$1 text v u
  text=$(cat)
  [[ -n $text ]] || return 0

  while IFS= read -r v; do
    [[ -n $v ]] || continue
    ip4_ok "$v" || bad "IPv4 ${v%.*.*}.x.x ($src): не документационный, не частный, не резолвер"
  done < <(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<<"$text" | sort -u)

  while IFS= read -r v; do
    case $v in
      '' | 2001:db8:* | 2001:4860:4860::8888 | 2001:4860:4860::8844 | 2606:4700:4700::1111 | 2606:4700:4700::1001 | 2620:fe::fe) ;;
      *) bad "IPv6 ${v%%:*}:… ($src): вне 2001:db8::/32" ;;
    esac
  done < <(grep -oiE '\b[23][0-9a-f]{3}:[0-9a-f]{1,4}:[0-9a-f:]*[0-9a-f]\b' <<<"$text" | tr 'A-F' 'a-f' | sort -u)

  while IFS= read -r v; do
    case $v in
      '' | 00000000-0000-*) ;;
      *) bad "UUID ${v%%-*}-… ($src): допустимы только начинающиеся с 00000000-0000-" ;;
    esac
  done < <(grep -oiE '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b' <<<"$text" | tr 'A-F' 'a-f' | sort -u)

  grep -qE -e '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' <<<"$text" && bad "блок приватного ключа ($src)"

  while IFS= read -r v; do
    [[ -n $v ]] || continue
    u=$(grep -oE '[A-Za-z0-9_-]{43,}$' <<<"$v")
    [[ $u =~ ^A+$ ]] || bad "ключ после «${v%%[\"\'=:[:space:]]*}» ($src): в примерах — заглушка из 43 символов A"
  done < <(grep -oiE '(private_?key|public_?key|pbk|password|mldsa65(seed|verify))["'"'"'=:[:space:]]{1,6}[A-Za-z0-9_-]{43,}' <<<"$text" | sort -u)

  while IFS= read -r v; do
    [[ -n $v ]] || continue
    bad "токен ${v:0:6}… ($src)"
  done < <(grep -oE '\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-(ant-)?[A-Za-z0-9_-]{32,}|[0-9]{8,10}:[A-Za-z0-9_-]{35})\b' <<<"$text" | sort -u)

  while IFS= read -r v; do
    u=${v#*://}
    case $u in
      '' | 00000000-0000-*) ;;
      *) bad "ссылка ${v%%://*}://… ($src): учётные данные в ссылке — только фиктивные" ;;
    esac
  done < <(grep -oE '\b(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[A-Za-z0-9][^][:space:]"'"'"'`<>()]*' <<<"$text" | sort -u)
}

mode=${1:-}
[[ $# -gt 0 ]] && shift
case $mode in
  --text)
    for f in "$@"; do
      if [[ -r $f ]]; then scan "текст" <"$f"; else bad "не прочитать $f"; fi
    done
    ;;
  --branch)
    cd "$(git rev-parse --show-toplevel)" || exit 1
    while IFS= read -r f; do
      case ${f##*/} in
        .env.example) ;;
        .env | .env.* | *.pem | *.key | *.p12 | *.pfx | state.json | id_rsa | id_dsa | id_ecdsa | id_ed25519)
          bad "запретный файл $f: секреты не хранятся в репозитории; шаблон — с суффиксом .example или .tmpl"
          ;;
      esac
    done < <(git ls-files -co --exclude-standard)
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    {
      git ls-files -co --exclude-standard -z | xargs -0 -r grep -Ih '' 2>/dev/null
      if base=$(git merge-base HEAD origin/main 2>/dev/null); then
        git log --format=%B "$base..HEAD"
        git log -p --format= "$base..HEAD" | grep '^+[^+]'
      else
        git log --format=%B 2>/dev/null
      fi
    } >"$tmp"
    scan "ветка" <"$tmp"
    ;;
  *)
    echo "использование: scripts/guard.sh --branch | --text ФАЙЛ…" >&2
    exit 2
    ;;
esac

((fails == 0))
