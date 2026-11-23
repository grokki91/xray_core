---
name: release
description: Как выпустить xm — тег vX.Y.Z, конвейер .github/workflows/release.yml (сборка linux/amd64, SHA256SUMS, релиз, подтверждение происхождения), загрузчик install.sh и проверка выпуска командой gh attestation verify. Применять при задачах «выпусти», «релиз», «тег», при правке release.yml или install.sh, при разборе провала задания выпуска.
---

# Выпуск xm

Решения — [ADR-0013](../../../docs/adr/0013-distribution-and-bootstrap.md),
[ADR-0016](../../../docs/adr/0016-ci-and-tooling.md); правила конвейера — `docs/security/policy.md` §6.

## 1. Что публикуется

- `xm-linux-amd64` — `go build -trimpath`, `CGO_ENABLED=0`, версия из тега через
  `-ldflags "-X main.version=<тег>"`.
- `install.sh` — загрузчик из корня репозитория той же ревизии.
- `SHA256SUMS` — суммы обоих файлов.
- Подтверждение происхождения обоих файлов (artifact attestation) — задание `provenance`.
- Все теги, включая `v0.0.*`, публикуются обычными выпусками (решение владельца 2026-11-23):
  `releases/latest` не видит предварительные, и загрузчик без `XM_VERSION` их бы не нашёл.

## 2. Порядок

1. Выпуск делает владелец: агент тег не создаёт и не отправляет.
2. `main` зелёный: `bash scripts/check.sh` и задания `check.yml` (включая `l4`).
3. Тег на коммите `main`: `git tag -a vX.Y.Z -m vX.Y.Z <коммит> && git push origin vX.Y.Z`.
4. Задание `build` проверяет вид тега, запускает `scripts/check.sh`, собирает и создаёт релиз;
   `provenance` скачивает файлы релиза, сверяет `SHA256SUMS` и подписывает происхождение.
5. Провал — тег и релиз удаляет владелец; повтор — новым номером, не переносом тега.

## 3. Проверка выпуска

```bash
gh release download vX.Y.Z --repo grokki91/xray_core --dir /tmp/xm-rel
cd /tmp/xm-rel && sha256sum -c SHA256SUMS
gh attestation verify xm-linux-amd64 --repo grokki91/xray_core
gh attestation verify install.sh --repo grokki91/xray_core
```

`install.sh` на сервере сверяет только SHA-256 (у него нет `gh`); подтверждение происхождения
проверяет тот, у кого `gh` есть.

## 4. Загрузчик

- Только: root, `x86_64`, наличие `curl` и `sha256sum` → скачать бинарник и `SHA256SUMS` →
  сверить → `/usr/local/bin/xm` → `xm install "$@"`. Логика установки — в `xm install`.
- Тело — в функции, вызов последней строкой; `set -euo pipefail`.
- Фиксированная версия — переменная `XM_VERSION=vX.Y.Z`; без неё — последний релиз.
- Тест — `tests/test-install.sh`: подменяет `curl`, `id`, `uname`, `install` через `PATH`; второго
  пути загрузки в `install.sh` нет. Новая проверка загрузчика — новый сценарий там же.
- Действие CI или его версия меняются — хэш коммита по тегу на GitHub (`git ls-remote --tags`),
  строка в `docs/dev/dependencies.md` §3 в той же правке.
