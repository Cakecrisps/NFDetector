# API и хранимые данные

## Разделение доступа

| Область | Проверка |
| --- | --- |
| `/`, `/assets/*` | Публичные файлы панели; данные запрашиваются отдельно |
| `/health` | Публичная проверка API/БД |
| `/install/agent.py`, `/install/agent.tar` | Публичный код без рабочих ключей |
| `POST /v1/enroll` | `Authorization: Enrollment <одноразовый код>` |
| Остальные `/v1/*` | `Authorization: Bearer <индивидуальный ключ>` |
| `/admin/api/*` | Серверная веб-сессия; мутации дополнительно CSRF/Origin |

Агентский ключ не открывает административный доступ. Веб-cookie не заменяет
ключ загрузки. Интерактивные Swagger/OpenAPI endpoints отключены.

## Агентский контракт

| Метод и путь | Вход / результат |
| --- | --- |
| `POST /v1/streams` | UUID, `interface`, `started_at` Unix seconds; регистрация epoch |
| `PUT /v1/streams/{id}/chunks/{sequence}` | Бинарный PCAP/PCAPNG; первый sequence = 0 |
| `POST /v1/streams/{id}/seal` | `last_sequence`, полная непрерывная последовательность обязательна |
| `GET /v1/streams/{id}/status` | Статусы файлов и обработанного префикса |
| `POST /v1/heartbeat` | `capture_state`, `backlog_bytes/files`, `software_version`, `last_error` |
| `GET /v1/events?limit=100` | Инциденты, связанные с потоками данного агента; limit 1–1000 |

Upload требует `Content-Type: application/octet-stream`, `Content-Length`
и `X-Content-SHA256` в lowercase hex. Ответ содержит `stream_id`, `sequence`,
`sha256`, `stored`, `analysis_status`. HTTP `201` означает новый сохранённый
файл, `200` — повтор того же содержимого. ACK не подтверждает анализ.

`409` — конфликт sequence/содержимого, закрытого потока или времени;
`401` — недействительный ключ; чужой поток не раскрывается и даёт `404`;
`413` — размер; `429` — квота; `503` — временно занятый домен при регистрации.
Некорректное тело/поля могут дать `400`, `411`, `415`, `422`.
Агент повторяет сетевые ошибки, `429`, `503`/`5xx` с backoff и jitter;
он не реализует отдельное ожидание точного `Retry-After`.

Для одного `(stream_id, sequence)` сервер проверяет хеш и размер, а не имя
пользовательского файла. Идентичность агента определяется ключом. `/seal`
не следует использовать для принудительного пропуска отсутствующих файлов.

## Административный API

`/admin/api/session`, `/login`, `/logout`, `/password`, `/reauth` обслуживают
сессию. `/agents` и операции `/agents/{id}/rotate`, `/revoke`, `/installation`
управляют агентами. `/agents/{id}/streams` показывает потоки.
`/overview?hours=...`, `/traffic?hours=...`, `/events`, `/audit` дают данные панели.
Точные поля и проверки см. в `distributed/web.py`, `web_auth.py`, `web_metrics.py`.

Сводки поддерживают `hours=1`, `24`, `168`. `/traffic` возвращает `period`,
`summary`, `timeline`, `protocols`, `event_types` из одного read-only
REPEATABLE READ снимка. Границы приёма `[start, end)`, время UTC-aware.
Сохраняется имя поля `hour` в timeline даже при минутной детализации.

## Таблицы и файлы

| Данные | Место | Назначение |
| --- | --- | --- |
| Реестр агентов/потоков/файлов | `nf_agents`, `nf_streams`, `nf_chunks` | Идентичность, sequence, размер, пути и parser-статусы |
| Состояние детекторов | `nf_domains` | Lease, generation, checkpoint, прогресс и ошибка |
| Работники | `nf_workers` | Последняя связь процессов |
| Первичные срабатывания | `nf_events` | Ссылка на пакет и связь с инцидентом |
| Объединённые атаки | `nf_incidents`, `nf_incident_streams` | Длительность, правила, источники, участвующие потоки |
| Очередь уведомлений | `nf_incident_outbox`, старый `nf_outbox` | Устойчивое намерение доставки; отправщика нет |
| Веб-доступ | Таблицы `nf_web_*` | Пароли, сессии, лимиты входа, audit |
| Bootstrap | `nf_agent_installations` | Hash одноразового install-кода, срок, использование |
| Принятые файлы | `/data/captures/` | Полный PCAP |
| Результаты parser | `/data/parsed/` | JSONL с пакетами и payload для reducer |
| Временный приём | `/data/incoming/` | Файлы ещё не опубликованной загрузки |

Схема-источник — `distributed/schema.sql`. Файлы и БД содержат чувствительные
сетевые данные. Удаление/восстановление должны учитывать ссылки и checkpoints.
