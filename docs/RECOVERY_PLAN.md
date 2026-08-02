# Application Recovery Plan

## Назначение

Application Recovery Plan задаёт порядок восстановления компонентов приложения
в его manifest-файле. Оркестратор не должен содержать отдельный жёстко заданный
порядок для Grafana, InfluxDB, Telegraf или NUT.

## Поле recovery_order

Пример:

```json
"recovery_order": [
  "configuration",
  "plugins",
  "database"
]
```

Каждый элемент должен соответствовать значению `kind` одного из компонентов
того же manifest-файла. Повторения запрещены.

## Текущий порядок

- Grafana: configuration, plugins, database
- InfluxDB: configuration, database
- Telegraf: configuration, state
- NUT: configuration, systemd, state

## Поведение планировщика

`build_application_recovery_plan()` получает имя приложения и список доступных
для восстановления компонентов. Результат содержит:

- компоненты в правильном порядке;
- отсутствующие компоненты;
- признак полноты плана.

На этом этапе модуль только строит план. Выполнение нескольких компонентов,
единый rollback и CLI-ключ `--all` будут добавлены следующими коммитами.
