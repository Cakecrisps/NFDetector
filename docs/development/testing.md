# Проверки разработчика

## Окружение

Python 3.10+; текущие полные прогоны выполнены на Python 3.12.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Без `NF_TEST_DATABASE_URL` интеграционные тесты пропускаются. Это не полный
успешный прогон. Тесты с БД создают собственные временные schemas, затем удаляют
их; используйте отдельную одноразовую БД, не production.

```bash
docker run -d --rm --name nfdetector-test-db \
  -e POSTGRES_DB=nfdetect -e POSTGRES_USER=nfdetect \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55439:5432 postgres:16-alpine
docker exec nfdetector-test-db pg_isready -U nfdetect -d nfdetect
NF_TEST_DATABASE_URL=postgresql://nfdetect@127.0.0.1:55439/nfdetect \
  .venv/bin/python -m pytest -q
docker stop nfdetector-test-db
```

Дождитесь положительного ответа `pg_isready` перед тестами. Trust-аутентификация
здесь относится только к временной БД на loopback и не является настройкой сервера.

## Покрываемые сценарии

| Файл | Что проверяет |
| --- | --- |
| `tests/test_streaming.py`, `test_regressions.py`, `_test.py` | Правила, окна, пороги, поведение локального монитора и regressions |
| `tests/test_agent.py` | Очередь/доставка агента и сбои |
| `tests/test_distributed.py` | Разные parser, обратный порядок файлов, несколько агентов, границы TCP, fencing, retry и ошибочные PCAP |
| `tests/test_flows.py` | Reassembly и распознавание прикладных сообщений |
| `tests/test_web.py` | Root/setup-код, смена пароля, сессии, CSRF/Origin, ключи, rate limit, audit |
| `tests/test_installation.py` | Install-коды, pin, содержимое пакета, адрес сервера, отзыв/повторы |
| `tests/test_incidents.py` | Час продолжающейся атаки, объединение сигналов/источников, длинная пауза, backfill |
| `tests/test_metrics.py` | Суммы графика/карточек/протоколов, границы периода, UTC/DST и единый снимок при конкурентной записи |

## Изолированный HTTPS smoke-test

```bash
python3 -m benchmarks.compose_smoke \
  --server https://localhost:8443 --key-file .local/test-agent.key \
  --ca .local/server.crt
```

Требуются отдельный Compose project и **новый домен**, защищаемый `192.168.1.1`,
пороги DDoS=3, HTTP=2, brute force HTTP Basic=2, HTTP Basic в `auth_proto`,
отключённый C2. Подключайте тестовые rules и ext отдельными override mounts;
рабочие настройки не изменяйте ради smoke-test. Нужно минимум два parser-worker. Скрипт генерирует синтетический
PCAP, проверяет разных владельцев parser, обратный порядок завершения файлов
и обнаружение правил через объединённые инциденты. Смену reducer и восстановление
checkpoint отдельно проверяют интеграционные тесты. Код: `benchmarks/compose_smoke.py`.

Нагрузочный микробенчмарк описан отдельно в [производительности](performance.md).
Тесты корректности не дают гарантии заданного packets/s и отсутствия capture loss.

## Документация

```bash
python3 -m pip install -r requirements-docs.txt
python3 scripts/build_docs.py
```

Сборка проверяет структуру навигации, локальные ссылки и anchors HTML;
удалённые сайты для неё не запрашиваются. См. [процесс сборки](documentation.md).
