# xm — менеджер Xray-core

> **Состояние: выпуски 0.0.x, готовится 0.1.0** — MVP без Web UI ([docs/roadmap.md](docs/roadmap.md)).

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
- Локальный Web UI через SSH-туннель — после 0.1.0; в интернет не открывается.
- Секреты создаются и хранятся только на сервере.
- Обход DPI и блокировок проект не обещает.

## Стек

| Компонент | Роль |
|---|---|
| Go, один статический бинарник | менеджер `xm` |
| Xray-core (upstream) | VPN-сервер; ставится из официальных релизов |
| systemd | служба Xray, таймеры |
| HTML, CSS, JavaScript без сборки | Web UI, встроен в `xm` |
| Bash | только загрузчик `install.sh`; Docker не нужен |

## Требования к VPS

Ubuntu Server 22.04 или 24.04, x86_64, доступ root или `sudo`. Рассчитано на 1 vCPU, 2 ГБ RAM,
20 ГБ SSD. Другие версии — [docs/compatibility.md](docs/compatibility.md).

## Установка

В одну строку — последний выпуск:

```bash
curl -fsSL https://github.com/grokki91/xray_core/releases/latest/download/install.sh | sudo bash
```

Загрузчик сверяет SHA-256 и запускает `xm install`. Прочитать его до запуска, фиксированная
версия, флаги, что меняется на сервере — [руководство по установке](docs/guide/install.md).
Сборка из исходников (Go — версия из `go.mod`):
`CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=0.0.0-dev" -o xm ./cmd/xm`.

## Команды

```bash
# от root (sudo); кроме version и help
xm status                  # служба, версии, адреса, вердикт здоровья
xm add [имя]               # создать профиль: ссылка и QR
xm list                    # профили без секретов
xm show <имя>              # ссылка и QR повторно
xm rm <имя>                # удалить профиль
xm update [--check]        # обновить Xray: контроль и автоматический откат
xm update --rollback       # вернуть предыдущую версию Xray
xm update --self           # обновить сам xm
xm diag [--export <файл>]  # диагностика; проблемы — код 4
xm logs [-f] [--since 1h]  # журнал Xray и xm
xm backup [--list]         # снимок состояния; список снимков
xm restore <id>            # восстановить из снимка
xm start|stop|restart      # служба Xray
xm uninstall [--purge]     # удаление; --purge — и состояние со снимками
xm version|help            # версия xm; справка
```

Как этим пользоваться — [руководство по эксплуатации](docs/guide/usage.md); все флаги и коды
выхода — [docs/architecture/interfaces.md](docs/architecture/interfaces.md).

## Диагностика

`xm diag` с самого сервера проверяет Xray, порт и локальный фаервол, IPv4 и IPv6, ресурсы узла; отчёт
разделяет факты, вероятные причины и гипотезы, доступность извне не доказывает. `--export` пишет
его без адресов, ключей и идентификаторов — [docs/operations/diagnostics.md](docs/operations/diagnostics.md).

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
