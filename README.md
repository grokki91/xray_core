# xm — менеджер Xray-core

> **Состояние: выпуски 0.0.x.** Работают установка, удаление, профили и управление службой;
> остальное — план до выпуска 0.1.0 ([docs/roadmap.md](docs/roadmap.md)).

Простой и безопасный способ поднять и обслуживать официальный
[Xray-core](https://github.com/XTLS/Xray-core) на своём VPS: одна команда — и на выходе ссылка
VLESS и QR-код. Разбираться в сетевой конфигурации не нужно.

## Возможности

- Установка одной командой; повторный запуск ничего не ломает и не перевыпускает ключи.
- Официальный Xray-core без форков: проверка контрольных сумм, обновление с автоматическим откатом.
- Клиентские профили: создать, показать, удалить; VLESS URI и QR-код.
- IPv4 и IPv6, DNS over HTTPS.
- Диагностика сервера и сети, которая отделяет факты от гипотез.
- Резервные копии и восстановление.
- Локальный Web UI через SSH-туннель; в интернет не открывается.
- Секреты создаются и хранятся только на сервере.

Проект не обещает обход DPI и блокировок.

## Стек

| Компонент | Роль |
|---|---|
| Go, один статический бинарник | менеджер `xm` |
| Xray-core (upstream) | VPN-сервер; ставится из официальных релизов |
| systemd | служба Xray, таймеры |
| HTML, CSS, JavaScript без сборки | Web UI, встроен в `xm` |
| Bash | только загрузчик `install.sh` |

Docker не нужен.

## Требования к VPS

Ubuntu Server 22.04 или 24.04, x86_64, доступ root или `sudo`. Рассчитано на 1 vCPU, 2 ГБ RAM,
20 ГБ SSD. Другие версии — [docs/compatibility.md](docs/compatibility.md).

## Установка

В одну строку — последний выпуск, сумма SHA-256 сверяется до запуска:

```bash
curl -fsSL https://github.com/grokki91/xray_core/releases/latest/download/install.sh | sudo bash
```

Скачать и прочитать загрузчик, затем `sudo bash install.sh`; фиксированная версия —
`sudo XM_VERSION=vX.Y.Z bash`. Все три варианта, флаги и что меняется на сервере —
[руководство по установке](docs/guide/install.md). Сборка из исходников (Go — версия из `go.mod`):
`CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=0.0.0-dev" -o xm ./cmd/xm`.

## Команды

```bash
xm status             # состояние сервера, Xray и сети
xm add [имя]          # создать профиль: ссылка и QR
xm list               # профили
xm show <имя>         # ссылка и QR повторно
xm rm <имя>           # удалить профиль
xm start|stop|restart # служба Xray
xm uninstall          # удаление
```

План: `xm update`, `xm diag`, `xm logs`, `xm backup`, `xm restore`, `xm ui`. Все команды и
флаги — [docs/architecture/interfaces.md](docs/architecture/interfaces.md).

## Диагностика

`xm diag` (в плане) проверяет Xray, порты, IPv4 и IPv6, DNS, TLS, соединения и маршрутизацию. Отчёт
разделяет подтверждённые факты, вероятные причины и гипотезы и называет пределы каждого
измерения. `xm diag --export` сохраняет отчёт без адресов, ключей и идентификаторов. Подробнее —
[docs/operations/diagnostics.md](docs/operations/diagnostics.md).

## Репозиторий

```
internal/   код xm; точка входа — cmd/xm/
docs/       архитектура, решения (ADR), безопасность, тестирование, план
.claude/    правила, скилы, субагенты и хуки для разработки с LLM
scripts/    обязательные проверки репозитория
tests/      тесты проверок и хуков
AGENTS.md   инструкции для LLM-агентов
```

С чего начать — [docs/README.md](docs/README.md). Сообщить об уязвимости — [SECURITY.md](SECURITY.md).
