# Реестр зависимостей и инструментов

Всё внешнее, от чего зависит проект: модули Go, действия CI, инструменты проверки, вендорные
файлы, внешние адреса, к которым обращается `xm`. Правило: **нет строки здесь — нет зависимости**.

- Новая строка требует согласия владельца; в колонке «Согласовано» — дата и ссылка на PR или ADR.
- `scripts/check.sh` не пропускает изменение `go.mod`, `go.sum`, `.github/workflows/` и
  `web/vendor/` без изменения этого файла.
- Перед добавлением: чем не подходит стандартная библиотека; лицензия; кто сопровождает; сколько
  транзитивных зависимостей; как фиксируется версия. Анализ инструментов — [tooling.md](tooling.md).

## 1. В поставке (`xm`)

| Имя | Версия | Зачем | Лицензия | Согласовано |
|---|---|---|---|---|
| `rsc.io/qr` | v0.2.0 (в `go.mod` с шага 5 фазы 3; импорт разрешён только `profile/export`) | QR-код ссылки профиля в терминале (`profile/export`); только корневой пакет, без `libqrencode` | BSD-3 | 2026-11-17, ответ владельца; [ADR-0028](../adr/0028-qr-library-and-selftest-address.md) |

## 2. Внешние компоненты на VPS

| Имя | Источник | Зачем | Проверка | Согласовано |
|---|---|---|---|---|
| `userdel` | утилита ОС (`/usr/sbin/userdel`, закрытый список `platform`) | удаление пользователя `xray` при `uninstall --purge` (`security.Remove`) | имя проверяется до запуска, аргумент один — имя; в L4 — шаг 8 фазы 4 | 2026-11-24, ответ владельца в сессии шага 6 фазы 4 ([ADR-0042](../adr/0042-uninstall-ordered-idempotent.md)) |
| `useradd` | утилита ОС (`/usr/sbin/useradd`, закрытый список `platform`) | создание системного пользователя `xray` (`security.EnsureBaseline`) | имя пользователя проверяется до запуска; аргументы фиксированы; в L4 — пользователь без оболочки и домашнего каталога | 2026-11-17, ответ владельца (A7 аудита); предложено в PR шага 4 фазы 2 |
| `systemctl` | утилита ОС (`/usr/bin/systemctl`, закрытый список `platform`) | управление `xray.service`: `daemon-reload`, `enable`, `disable`, `start`, `stop`, `restart`, `show`, `is-system-running` (`server`) | юнит один и задан константой; аргументы фиксированы; в L4 — служба стартует и держит соединение | 2026-11-17, ответ владельца (A7 аудита); предложено в PR шага 7 фазы 2 |
| `ss` | утилита ОС (`/usr/bin/ss`, закрытый список `platform`) | владелец занятого порта: `ss -H -t -l -n -p sport = :ПОРТ` (`network.PortFree`) | порт проверяется до запуска; аргументы фиксированы; только чтение; имя процесса — только печатные символы без пробелов и кавычек | 2026-11-23, ответ владельца |
| `ufw` | утилита ОС (`/usr/sbin/ufw`, закрытый список `platform`) | состояние UFW для порта: `ufw status verbose` (`network.Facts`); правило порта Xray: `ufw allow <порт>/tcp` и `ufw delete allow <порт>/tcp` (`network.AllowPort`, `RevokePort`) | аргументы фиксированы; чтение, а изменение — только эти два вызова и только из транзакции `app` ([ADR-0036](../adr/0036-install-changes-only-own.md), [ADR-0041](../adr/0041-ufw-rule-in-install-transaction.md)); нет утилиты — переход к `iptables` с причиной в `Note` | 2026-11-23, ответ владельца |
| `iptables`, `ip6tables` | утилиты ОС (`/usr/sbin/iptables`, `/usr/sbin/ip6tables`, закрытый список `platform`) | политика и цели правил цепочки `INPUT`: `-S INPUT` (`network.Facts`) | аргументы фиксированы; только чтение (ADR-0036); строгий разбор, незнакомый формат — «не определено» | 2026-11-23, ответ владельца |
| Xray-core | релизы `XTLS/Xray-core` | управляемый компонент | суммы из `.dgst` ([updates.md](../operations/updates.md) §3) | требование задания |

## 3. Сборка, проверки, CI

| Имя | Вид | Зачем | Фиксация | Согласовано |
|---|---|---|---|---|
| Go | компилятор, стандартная библиотека, `gofmt`, `go vet`, `go test` | сборка `xm` и проверки `scripts/check.sh` | строка `go` в `go.mod` (сейчас 1.27.4); тулчейн этой версии `go` скачивает сам (`GOTOOLCHAIN=auto`) с проверкой суммы по `sum.golang.org` | 2026-11-15, ответ владельца в PR шага 2 фазы 1: последняя стабильная версия в `go.mod`, как в [stack.md](../architecture/stack.md) §1; [ADR-0002](../adr/0002-go-single-binary.md) |
| GitHub Actions | платформа CI | запуск `scripts/check.sh` на PR и `main` | действия — по хэшу коммита, каждое своей строкой при подключении; образ раннера `ubuntu-24.04`, для задания `l4` ещё `ubuntu-22.04` (согласие владельца — открыто, PR шага 11 фазы 2); `go` с образа — только загрузчик тулчейна из `go.mod`, `actions/setup-go` не используется | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| `actions/checkout` | действие CI | получение репозитория с историей для `check.sh` и gitleaks | v7.0.1, коммит `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-11-15, ответ владельца к [PR #67](https://github.com/grokki91/xray_core/pull/67); [ADR-0016](../adr/0016-ci-and-tooling.md) |
| Secret scanning и push protection | настройка репозитория GitHub | отказ в отправке распознанных токенов | включено владельцем 2026-11-15 | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| gitleaks | сканер секретов в CI | рабочее дерево и история | 8.30.1; бинарник из релизов `gitleaks/gitleaks`, SHA-256 в workflow — из `checksums.txt` релиза | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| govulncheck | сканер уязвимостей Go в CI | вызываемые уязвимости модулей и стандартной библиотеки | v1.9.0, `sum.golang.org`; собирается тулчейном из `go.mod` | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| staticcheck | статический анализ Go в CI | ошибки сверх `go vet` | модуль `honnef.co/go/tools` v0.8.2 (выпуск 2026.2.2), `sum.golang.org`; собирается тулчейном из `go.mod` | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| shellcheck | анализ Bash в CI | все `*.sh` репозитория: `scripts/`, `tests/`, хуки, `install.sh` | 0.11.0; бинарник из релизов `koalaman/shellcheck`, SHA-256 в workflow: upstream сумм не публикует — посчитана 2026-11-15 по двум загрузкам с релиза из одной сети (совпали), независимой сверки нет; при обновлении старая сумма сверяется с новой загрузкой старой версии | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md) |
| Пакетный менеджер ОС | `apt-get`, `dpkg-query` на VPS; `winget` на Windows 11 | недостающие инструменты скрипта проверки на реальной интеграции у владельца; поставленное скриптом удаляется в его конце | источники пакетов ОС владельца; версии не фиксируются | 2026-11-16, запрос владельца; [ADR-0021](../adr/0021-owner-integration-check.md) |
| Подтверждение происхождения сборки | шаг конвейера выпуска | свидетельство сборки `xm` из коммита | действие `actions/attest-build-provenance`, задание `provenance` в `release.yml` | 2026-11-14, [ADR-0016](../adr/0016-ci-and-tooling.md); подключается в фазе 4 |
| `actions/attest-build-provenance` | действие CI | подтверждение происхождения `xm-linux-amd64` и `install.sh` в задании `provenance` `release.yml` | v4.2.2, коммит `4d101475d8b20a2381f78447822ac1eab6504dd8` (`git ls-remote --tags`, 2026-11-23) | 2026-11-14, строка «Подтверждение происхождения сборки» ([ADR-0016](../adr/0016-ci-and-tooling.md)) |

Строка здесь — согласие; подключённым инструмент становится с появлением в workflow
([check.yml](../../.github/workflows/check.yml): GitHub Actions, `actions/checkout`, gitleaks,
govulncheck, staticcheck, shellcheck подключены 2026-11-15; [release.yml](../../.github/workflows/release.yml): `actions/checkout`, `actions/attest-build-provenance` — 2026-11-23). Правила
конвейера — [policy.md](../security/policy.md) §6. Внешние адреса сборки и CI (не `xm`):

| Адрес | Кто обращается | Зачем |
|---|---|---|
| `proxy.golang.org`, `sum.golang.org` | `go` локально и в CI; `go run …@версия` в CI; `go` в шагах скрипта проверки у владельца | тулчейн версии из `go.mod`; модули govulncheck и staticcheck; проверка сумм |
| `vuln.go.dev` | govulncheck | база уязвимостей Go |
| `github.com` (релизы `gitleaks/gitleaks`, `koalaman/shellcheck`, `XTLS/Xray-core`; `actions/checkout`, `actions/attest-build-provenance`) | шаги CI, раннер; тесты L3 локально и в CI; скрипт проверки на реальной интеграции у владельца (репозиторий проекта) | бинарники сканеров; архивы Xray для стенда L3 ([ADR-0020](../adr/0020-l3-stand.md)); код действия; проверяемый коммит ([ADR-0021](../adr/0021-owner-integration-check.md)) |
| `release-assets.githubusercontent.com` | шаги CI; тесты L3; установщик Git через `winget` у владельца | файлы релизов сканеров и Xray: на него перенаправляет `github.com` ([ADR-0016](../adr/0016-ci-and-tooling.md)) |
| источники пакетов ОС: зеркала apt из `sources.list` VPS; источник `winget` Microsoft и адрес установщика из манифеста пакета | скрипт проверки на реальной интеграции у владельца | недостающие инструменты ([ADR-0021](../adr/0021-owner-integration-check.md)) |

## 4. Локальные утилиты разработки

Не поставляются и не скачиваются проектом; нужны для `scripts/` и хуков.

| Имя | Зачем | Согласовано |
|---|---|---|
| `bash`, `git`, `grep`, `sed`, `awk` | `scripts/check.sh`, `scripts/guard.sh`, хуки | принятием PR фазы 0 |
| `jq` | разбор входа хуков Claude Code | принятием PR фазы 0 |
| `shellcheck` | проверка скрипта для VPS субагентом `integration-check`, если есть локально; обязательная — в CI (§3) | 2026-11-16, [ADR-0021](../adr/0021-owner-integration-check.md) |

## 5. Внешние адреса, к которым обращается `xm`

Заполняется с кодом (фазы 2–5): DoH-серверы по умолчанию, контрольные узлы диагностики, адрес
для определения внешнего IP, тестовый адрес самопроверки. Каждый адрес — закрытый список в коде и
строка здесь.

| Узел | Пакет | Зачем | Согласовано |
|---|---|---|---|
| `api.github.com` | `update` | последний стабильный релиз `XTLS/Xray-core` и хэши его файлов; с `XM_GITHUB_TOKEN` — с авторизацией | [ADR-0009](../adr/0009-update-source-and-verification.md), [ADR-0031](../adr/0031-github-api-token.md); [updates.md](../operations/updates.md) §1 |
| `github.com` | `update` | архив релиза и `.dgst` | [ADR-0009](../adr/0009-update-source-and-verification.md); [updates.md](../operations/updates.md) §1 |
| `cp.cloudflare.com` | самопроверка (`reach.selftest`); цель сквозного теста L3 в CI | `GET /generate_204` через сервер; успех — 204 | 2026-11-17, ответ владельца; [ADR-0028](../adr/0028-qr-library-and-selftest-address.md); L3 — 2026-11-19, [ADR-0032](../adr/0032-selftest-client-and-l3-target.md) |
| `release-assets.githubusercontent.com` | `update` | файлы релиза: на него перенаправляет `github.com` | [ADR-0009](../adr/0009-update-source-and-verification.md); [updates.md](../operations/updates.md) §1 |
| `1.1.1.1`, `2606:4700:4700::1111` | `network` | внешний адрес за NAT: `GET /cdn-cgi/trace`, поле `ip`; запрос по адресу — семейство однозначно, DNS не нужен; `--address` переопределяет | 2026-11-23, ответ владельца |
| `1.1.1.1` | `dns` | DoH по умолчанию: `https://1.1.1.1/dns-query` в разделе `dns` конфигурации Xray | 2026-11-23, ответ владельца |
| `dns.quad9.net` | `dns` | DoH по умолчанию: `https://dns.quad9.net/dns-query` — второй независимый оператор | 2026-11-23, ответ владельца |
| кандидаты цели REALITY (9 имён, порт 443) | `network` | проверка цели при установке без `--sni`: одно соединение TLS на кандидата; список — [compatibility.md](../compatibility.md) | 2026-11-23, [ADR-0035](../adr/0035-reality-target-candidates.md) |
