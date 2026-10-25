# NFDetector

Пассивный анализатор сетевого трафика: агенты отправляют PCAP на сервер,
параллельные обработчики разбирают файлы, общий детектор объединяет историю
пакетов и формирует инциденты. Панель показывает агентов, трафик и события.
Есть отдельный локальный режим анализа PCAP и live-захвата.

Система обнаруживает признаки DDoS, SYN/HTTP flood, перебора и периодического
трафика. Она не блокирует атаки; SSH-приветствия не доказывают неудачные входы.

## Документация

Все исходные руководства находятся в **[docs/](docs/index.md)**.

- [Установка сервера и TLS](docs/getting-started/server.md)
- [Автоустановка и ручное подключение агента](docs/getting-started/agent.md)
- [Панель и первый вход](docs/guides/panel.md)
- [Архитектура и границы файлов](docs/architecture/overview.md)
- [Эксплуатация и диагностика](docs/guides/operations.md)
- [Что сделано и что отсутствует](docs/project/status.md)
- [Плюсы, ограничения и план работ](docs/project/assessment.md)

## Быстрый запуск сервера

Требуются Docker Engine и Compose v2. Сначала задайте IP целей в
`ext/protectips.txt`, правила в `rules.json`, создайте приватный `.env`
по инструкции установки. Затем:

```bash
docker compose up -d --build --scale parser-worker=3 --scale detector-worker=2 --wait
docker compose exec -T api python -m distributed setup-code
```

Панель открывается на HTTPS-порту 443. Для удалённого доступа задайте точный
`NF_PUBLIC_URL`. Первый вход: `root:root` и одноразовый код с сервера,
затем обязательная смена пароля. Настройка доверия TLS описана в инструкции.

**Перед длительной работой:** автоматической очистки серверных захватов нет;
квота сохранённых PCAP составляет 2 GiB на агента. Один медленный поток может
задержать анализ всего домена. Подробности — в статусе и ограничениях.

## Сборка HTML

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/python scripts/build_docs.py
python3 -m http.server 8080 --directory documentation --bind 127.0.0.1
```

Откройте `http://127.0.0.1:8080`. Руководство собирается MkDocs,
справочник Python — pydoctor только из `distributed/`, `general/` и `nfdetect.py`.
HTML в `documentation/` генерируется целиком; вручную его не редактируют.
Подробности: [как обновлять документацию](docs/development/documentation.md).

## Проверки

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

Без `NF_TEST_DATABASE_URL` интеграционные проверки пропускаются.
Полный прогон и отдельная тестовая БД описаны в [руководстве разработчика](docs/development/testing.md).
