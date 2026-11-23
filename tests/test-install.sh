#!/usr/bin/env bash
# Тесты загрузчика install.sh без сети и без root. Запуск: bash tests/test-install.sh
# Подменяются только внешние команды через PATH: curl отдаёт файлы из локального каталога релиза,
# id и uname сообщают root и x86_64, install записывает вызов в журнал. В install.sh нет отдельного
# тестового пути: он вызывает те же команды, что на сервере.
set -u
cd "${BASH_SOURCE[0]%/*}/.." || exit 1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
ok() { printf '  ✓ %s\n' "$1"; }
no() {
  printf '  ✗ FAIL %s\n' "$1"
  fails=$((fails + 1))
}

bin=$work/bin rel=$work/release
mkdir -p "$bin" "$rel"
# curl … -o ФАЙЛ АДРЕС: копирует из $FAKE_RELEASE файл с именем последней части адреса, адрес — в журнал.
cat >"$bin/curl" <<'EOF'
#!/usr/bin/env bash
out='' url='' fmt=''
while (($#)); do
  case $1 in -o) out=$2; shift 2 ;; -w) fmt=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
echo "curl $url" >>"$FAKE_LOG"
if [[ -n $fmt ]]; then # перенаправление releases/latest
  printf '%s' "https://github.com/grokki91/xray_core/releases/tag/${FAKE_LATEST:-v9.8.7}"
  exit 0
fi
cp -- "$FAKE_RELEASE/${url##*/}" "$out" 2>/dev/null || exit 22
EOF
cat >"$bin/install" <<'EOF'
#!/usr/bin/env bash
echo "install $*" >>"$FAKE_LOG"
EOF
printf '#!/usr/bin/env bash\necho "${FAKE_UID:-0}"\n' >"$bin/id"
printf '#!/usr/bin/env bash\necho "${FAKE_ARCH:-x86_64}"\n' >"$bin/uname"
chmod +x "$bin"/*

printf 'фиктивный бинарник xm\n' >"$rel/xm-linux-amd64"
(cd "$rel" && sha256sum xm-linux-amd64 >SHA256SUMS)
good=$(cat "$rel/SHA256SUMS")

# run ИМЯ — запускает install.sh; код — в $code, журнал — в $work/log
run() {
  : >"$work/log"
  env PATH="$bin:$PATH" FAKE_LOG="$work/log" FAKE_RELEASE="$rel" "$@" bash ./install.sh --sni example.com >"$work/out" 2>&1
  code=$?
}
installed() { grep -q '^install -m 0755 .*/xm-linux-amd64 /usr/local/bin/xm$' "$work/log"; }

# ─── Целый бинарник: сверен и установлен (затем запуск /usr/local/bin/xm, которого здесь нет)
run
if installed; then ok "целый бинарник устанавливается"; else no "целый бинарник не установлен: $(tr '\n' ' ' <"$work/log")"; fi
grep -q '^curl https://github.com/grokki91/xray_core/releases/download/v9.8.7/xm-linux-amd64$' "$work/log" &&
  ok "по умолчанию — тег последнего релиза из перенаправления" || no "адрес последнего релиза: $(tr '\n' ' ' <"$work/log")"
run FAKE_LATEST='v1;rm'
((code != 0)) && ! grep -q download "$work/log" && ok "негодный тег из перенаправления — отказ без загрузки" || no "негодный тег: код $code"

# ─── Подменённый бинарник: отказ до установки
printf 'подменённый бинарник\n' >"$rel/xm-linux-amd64"
run
if ((code != 0)) && ! installed && grep -q 'не совпадает' "$work/out"; then
  ok "подменённый бинарник отвергается до установки"
else
  no "подменённый бинарник: код $code, журнал $(tr '\n' ' ' <"$work/log")"
fi
printf 'фиктивный бинарник xm\n' >"$rel/xm-linux-amd64"

# ─── Нет суммы для бинарника
printf '%s  другой-файл\n' "${good%% *}" >"$rel/SHA256SUMS"
run
((code != 0)) && ! installed && ok "нет суммы — отказ" || no "нет суммы: код $code"
printf '%s\n' "$good" >"$rel/SHA256SUMS"

# ─── Фиксированная версия
run XM_VERSION=v0.0.1
grep -q '^curl https://github.com/grokki91/xray_core/releases/download/v0.0.1/SHA256SUMS$' "$work/log" && installed &&
  ok "XM_VERSION — фиксированный релиз" || no "фиксированная версия: $(tr '\n' ' ' <"$work/log")"
run XM_VERSION='v1;x'
((code == 2)) && ! grep -q curl "$work/log" && ok "неверная XM_VERSION — отказ без загрузки" || no "неверная XM_VERSION: код $code"

# ─── Предусловия: отказ до загрузки
run FAKE_UID=1000
((code == 3)) && ! grep -q curl "$work/log" && ok "не root — отказ" || no "не root: код $code"
run FAKE_ARCH=aarch64
((code == 3)) && ! grep -q curl "$work/log" && ok "не x86_64 — отказ" || no "не x86_64: код $code"
mv "$bin/curl" "$work/curl.off"
nocurl=$work/nocurl
mkdir -p "$nocurl"
for t in bash env sha256sum awk mktemp rm; do ln -s "$(command -v "$t")" "$nocurl/$t"; done
: >"$work/log"
env PATH="$bin:$nocurl" FAKE_LOG="$work/log" bash ./install.sh >"$work/out" 2>&1
code=$?
((code == 3)) && grep -q 'нет curl' "$work/out" && ok "нет curl — отказ с названием пакета" || no "нет curl: код $code"

((fails == 0)) || exit 1
