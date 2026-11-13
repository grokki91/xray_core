# Документация

Указатель: что читать под задачу. Читать раздел, а не файл целиком.

## 1. Что читать

| Нужно понять | Документ |
|---|---|
| что это за система и из чего состоит | [architecture/overview.md](architecture/overview.md) |
| за что отвечает компонент и какой у него интерфейс | [architecture/components.md](architecture/components.md) |
| команды, машинный контракт, HTTP API, мост | [architecture/interfaces.md](architecture/interfaces.md) |
| что и с какими правами лежит на VPS | [architecture/data-model.md](architecture/data-model.md) |
| почему Go и что не используется | [architecture/stack.md](architecture/stack.md) |
| где что лежит в репозитории, кто кого импортирует | [architecture/repository.md](architecture/repository.md) |
| почему принято решение, что отвергнуто | [adr/README.md](adr/README.md) |
| что запрещено с точки зрения безопасности | [security/policy.md](security/policy.md) |
| как обращаться с секретами и какие значения допустимы в примерах | [security/secrets.md](security/secrets.md) |
| как обновляется Xray и что такое откат | [operations/updates.md](operations/updates.md) |
| как устроена диагностика, какие есть проверки | [operations/diagnostics.md](operations/diagnostics.md) |
| что и на каком уровне тестировать | [testing.md](testing.md) |
| какие ОС, версии Xray и клиенты поддержаны — с датами | [compatibility.md](compatibility.md) |
| что делать дальше, что входит в MVP | [roadmap.md](roadmap.md) |
| что ещё не решено | [open-questions.md](open-questions.md) |
| как устроены инструкции для LLM | [dev/ai-ecosystem.md](dev/ai-ecosystem.md) |
| правила документации и ревью | [dev/documentation.md](dev/documentation.md), [dev/code-review.md](dev/code-review.md) |
| какие сторонние инструменты рассмотрены и что подключено | [dev/tooling.md](dev/tooling.md), [dev/dependencies.md](dev/dependencies.md) |
| как поставить задачу сессии LLM | [templates/task-brief.md](templates/task-brief.md) |
| как описать новый компонент | [templates/component-spec.md](templates/component-spec.md) |

## 2. Термины

| Термин | Значение |
|---|---|
| `xm` | менеджер: один бинарник и его команды |
| Ядро | официальный бинарник Xray-core |
| Состояние | `state.json` — единственный источник правды об установке |
| Пресет | готовая комбинация «протокол + транспорт + защита» с именем |
| Профиль | клиентская учётная запись: имя и учётные данные |
| Артефакт | представление профиля для клиента: ссылка, QR, файл настроек |
| Экспортёр | код, строящий артефакт одного формата |
| Транзакция | изменение системы со снимком, контролем и откатом |
| Снимок | архив состояния и конфигурации для отката и восстановления |
| Дрейф | расхождение конфигурации на диске с последней применённой |
| Проверенный диапазон | версии Xray, на которых прошли тесты данной версии `xm` |
| Проверка | одно измерение диагностики с идентификатором |
| Наблюдение | результат проверки из одной точки наблюдения |
| Вывод | утверждение о причине с классом `fact`, `probable` или `hypothesis` |
| Точка наблюдения | откуда измерено: `local`, `probe`, `client` |
| Узел | управляемый VPS |
| Контракт | версионируемый формат машинного вывода |
| Редактор | фильтр, заменяющий чувствительные значения метками |
| Манифест прав | таблица путей, владельцев и прав на VPS |
| Цель REALITY | чужой сайт, под который маскируется рукопожатие |
