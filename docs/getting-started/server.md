# Установка сервера

Нужны Docker Engine и Compose v2. Перед запуском укажите защищаемые адреса
в `ext/protectips.txt` и пороги в `rules.json`. Конфигурация монтируется read-only.

Указывайте IP **цели атаки**, который виден внутри захвата агента. Например,
если агент на `192.168.122.219` принимает тестовый трафик от `192.168.122.246`,
в списке должен быть `192.168.122.219`. Адрес отправителя в этот список для
такой проверки добавлять не нужно. Сам факт регистрации агента не добавляет
его IP в защищаемые адреса. Пакеты с другими адресами назначения сохраняются
и учитываются в статистике, но не вызывают тревоги детекторов защищаемых узлов.
Обычное подключение тоже не обязательно вызывает событие: нужны условия
и пороги соответствующего правила.

Настройте список до первого захвата. Изменение списка у уже обработанного
домена меняет hash конфигурации: одного перезапуска worker недостаточно;
нужен повторный анализ либо явная миграция checkpoint; см. [эксплуатацию](../guides/operations.md).

Создайте приватный `.env` с новым паролем PostgreSQL:

```bash
python3 - <<'PY'
from pathlib import Path
import secrets
path = Path('.env')
with path.open('x') as handle:
    handle.write('POSTGRES_PASSWORD=' + secrets.token_hex(24) + '\n')
path.chmod(0o600)
PY

docker compose up -d --build --scale parser-worker=3 --scale detector-worker=2 --wait
```

Сервисы: `lb`, `api`, `postgres`, `parser-worker`, `detector-worker`.
Наружу опубликован **один порт — TCP 443 у LB**. Агент отправляет PCAP по
`https://detector.example.com`. Один сертификат и его приватный ключ подключены
только к LB. Он завершает TLS и направляет запросы на `http://api:8000`
в Docker-сети. Сертификаты внутри API/worker/PostgreSQL не нужны.

```text
Агенты → HTTPS :443 → LB → HTTP api:8000 → PostgreSQL :5432
                                    └→ volume data ← parser / detector
                         Закрытая Docker-сеть backend
```

LB подключён к `edge` и `backend`. Остальные контейнеры подключены только
к `backend` с `internal: true`. Они обращаются к PostgreSQL как `postgres:5432`;
worker получают задания через БД и читают PCAP через общий Docker volume.
Портов API, БД и worker на хосте нет. Worker не ходят на внешний адрес LB.
Внутренний порт LB `8443` — деталь контейнера, агент использует внешний `443`.
Изоляция сети относится к контейнерам; администратор Docker-хоста имеет
доступ к контейнерной инфраструктуре.

### Существующий сертификат сервера

Для публичного домена задайте в `.env` реальные пути к сертификату с цепочкой
и приватному ключу; оба файла остаются на сервере:

```dotenv
NF_BIND=0.0.0.0
NF_PORT=443
NF_TLS_CERT=/etc/letsencrypt/live/detector.example.com/fullchain.pem
NF_TLS_KEY=/etc/letsencrypt/live/detector.example.com/privkey.pem
```

```bash
docker compose -f compose.yaml -f compose.tls.yaml up -d --build \
  --scale parser-worker=3 --scale detector-worker=2 --wait
```

`compose.tls.yaml` монтирует файлы read-only только в LB и отключает генерацию
самоподписанного сертификата. С доверенным сертификатом на агенте достаточно
`--server https://detector.example.com` и `--key-file ...`; параметр `--ca`
не нужен. Ключ агента разрешает загрузку; приватный TLS-ключ агенту не передаётся.

После обновления сертификата пересоздайте только LB: файловые bind mounts могут
ссылаться на прежний inode после замены сертификата/переключения symlink:

```bash
docker compose -f compose.yaml -f compose.tls.yaml up -d --no-deps --force-recreate lb
```

API, worker, БД и их состояние при этом продолжают работать.

### Локальная проверка без готового сертификата

Обычный `compose.yaml` генерирует один локальный самоподписанный сертификат
на LB и сохраняет его в volume `tls`. Для теста на той же машине установите
`NF_BIND=127.0.0.1`, `NF_PORT=8443`, `NF_TLS_HOST=localhost` в `.env`.
Скопируйте публичный сертификат для проверки агентом:

```bash
mkdir -p .local
docker compose cp lb:/etc/nf/tls/server.crt .local/server.crt
```

В этом режиме агент использует `https://localhost:8443` и
`--ca .local/server.crt`. Отдельные сертификаты для worker не создаются.
`.env`, `.local/`, ключи и новые PCAP исключены из Git. В репозитории остаются
исторические примеры `cap.pcap` и `out/`; новые рабочие захваты храните
в agent spool и серверном volume. Dockerfile копирует только исходники и
конфигурацию, а PCAP исключены из контекста сборки.


## Вход в панель

См. [первую настройку и веб-панель](../guides/panel.md).

## Публичный сертификат для автоустановки

LB копирует сертификат без приватного ключа в volume `tls-public`; API читает
его из `/run/nf-tls/server.crt` для генерации закреплённого fingerprint.
При обновлении старой установки пересоздайте `api` и `lb` с актуальным Compose.
Проверку и смену сертификата установленного агента см. в [руководстве агента](agent.md).
