# Multi-Application Recovery Plan

## Назначение

Модуль строит единый порядок восстановления нескольких приложений на основе
поля `dependencies` в application manifest-файлах.

Для текущего monitoring stack зависимости уже описаны так:

- InfluxDB не зависит от других поддерживаемых приложений;
- Telegraf зависит от InfluxDB;
- Grafana зависит от InfluxDB;
- NUT не зависит от monitoring stack.

## Поведение

`build_multi_application_plan()`:

1. Проверяет список выбранных приложений.
2. Автоматически включает их зависимости.
3. Строит стабильный топологический порядок.
4. Для каждого приложения вызывает существующий transaction planner.
5. Возвращает общий план без изменения файлов.

## Текущий этап

На этом коммите добавляется только планирование. Единый rollback, управление
службами и выполнение нескольких приложений будут добавлены следующим этапом.

## Multi-Application Transaction Executor

`execute_multi_application_transaction()` выполняет несколько приложений как
одну транзакцию.

Реализовано:

1. Один общий recovery lock.
2. Один rollback-пакет для всех изменяемых приложений.
3. Предварительная распаковка и проверка всех компонентов.
4. Остановка служб в обратном порядке зависимостей.
5. Установка приложений в порядке зависимостей.
6. Запуск служб в прямом порядке зависимостей.
7. Автоматический откат всех уже установленных компонентов в обратном порядке.
8. Сохранение завершённых приложений и компонентов в общем статусе.

Например, для запроса Grafana порядок приложений будет:

```text
InfluxDB -> Grafana
```

Остановка служб выполняется как:

```text
Grafana -> InfluxDB
```

Запуск служб выполняется как:

```text
InfluxDB -> Grafana
```

На этом этапе добавляется внутренний API без CLI.

## Multi-Application CLI

Пользовательский CLI использует параметр `--applications`.

Preview одного приложения с автоматическим включением зависимостей:

```bash
psb recover backup.psb --applications grafana
```

Preview нескольких приложений:

```bash
psb recover backup.psb --applications grafana,telegraf
```

Preview всех поддерживаемых transaction applications:

```bash
psb recover backup.psb --applications all
```

Выполнение:

```bash
psb recover backup.psb \
  --applications grafana \
  --execute \
  --rollback-destination /mnt/backup
```

Для выполнения требуется тройное подтверждение, включая точную фразу:

```text
RESTORE MULTI APPLICATIONS
```

`--applications` нельзя сочетать с `--application`, `--component` или `--all`.
Режимы `--json` и `--output` доступны только для Preview.
