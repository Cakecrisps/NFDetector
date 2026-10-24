# Запуск распределённого NFDetect

Реализован первый рабочий вариант: агент → HTTPS → очередь PostgreSQL →
N parser-worker → объединение событий по capture-времени → detector-worker.
Файлы одного агента могут разбираться разными worker и завершаться в обратном
порядке. TCP- и детекторное состояние сохраняется между файлами и процессами.

## Docker Compose

Нужны Docker Engine и Compose v2. Перед запуском укажите защищаемые адреса
в `ext/protectips.txt` и пороги в `rules.json`. Конфигурация монтируется read-only.

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

```mermaid
flowchart LR
    A[Внешний агент] -->|HTTPS :443 / ключ агента| LB[LB: сертификат сервера]
    subgraph Backend[Закрытая Docker-сеть backend]
        API[API :8000] --> PG[(PostgreSQL :5432)]
        W[Parser и detector workers] --> PG
        API --> V[(Общий volume PCAP)]
        V --> W
    end
    LB -->|HTTP внутри Docker| API
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
`.env`, `.local/`, ключи и PCAP не попадают в образ или Git.

## Ключ агента

Ключи создаются административной CLI внутри API-контейнера; публичного endpoint
для выпуска ключей нет. Секрет не печатается в консоль, в PostgreSQL хранится
его SHA-256. Выданный файл имеет права `0600`.

```bash
docker compose exec -T api python -m distributed issue-key \
  --name sensor-1 --domain office --key-file /tmp/sensor-1.key
docker compose cp api:/tmp/sensor-1.key .local/sensor-1.key
chmod 600 .local/sensor-1.key
```

Команда сообщает `agent_id`. Отзыв:

```bash
docker compose exec -T api python -m distributed revoke-key --agent-id AGENT_UUID
```

`domain` — единая история событий с согласованными часами. Несколько агентов
одного домена объединяются для DDoS и других правил. Используйте один домен
для сенсоров, наблюдающих неперекрывающиеся части трафика. Межсенсорная дедупликация
одного и того же пакета пока не реализована; повторная доставка одного файла
и повтор выполнения заданий дедуплицируются.

## Отправка существующих PCAP

На агентской машине нужен Python 3.10+ и агентские зависимости:

```bash
python3 -m pip install -r requirements-agent.txt
python3 -m distributed upload \
  --server https://detector.example.com \
  --key-file .local/sensor-1.key \
  --state .local/upload-state.json --interface eth0 \
  capture-001.pcap capture-002.pcapng
```

Пути перечисляются в capture-порядке. Один state-файл — одна последовательность.
При обрыве повторите ту же команду: UUID потока, sequence и подтверждения
восстановятся с диска. Исходные пользовательские файлы не удаляются.
После доставки всей последовательности агент вызывает `/seal`.
Для независимого нового захвата используйте другой state-файл.

Для исторического захвата создавайте отдельный домен replay: добавление источника
с начальным временем ниже уже обработанного watermark отвергается явно.
Это предотвращает незаметную потерю старых событий.

## Live-агент

Дополнительно нужен `dumpcap` и разрешённый ему захват выбранного интерфейса
(на Debian/Ubuntu пакет `wireshark-common`). Агент запускается на сенсоре;
серверным контейнерам доступ к сетевым интерфейсам сенсора не нужен.

```bash
python3 -m distributed capture \
  --server https://detector.example.com \
  --key-file /etc/nfdetect/agent.key \
  --state /var/lib/nfdetect/agent-state.json \
  --spool /var/lib/nfdetect/spool --interface eth0 \
  --filter 'not (host SERVER_IP and tcp port 443)' \
  --quota-mib 2048
```

Замените `SERVER_IP` реальным адресом. Фильтр обязателен, чтобы не захватывать
собственную отправку PCAP. Предпочтителен отдельный интерфейс управления.

Захват непрерывный через один `dumpcap`, с ротацией по 2 секундам или 16 MiB.
Закрытые файлы попадают в устойчивый manifest; активный файл не отправляется.
Подтверждение проверяется по stream ID, sequence и SHA-256. Только после
сохранения подтверждения принадлежащий spool файл удаляется. Подтверждённые
записи удаляются из live-очереди, её размер не растёт со сроком работы агента.

Сначала агент регистрирует поток, затем начинает захват. При старте нужна связь
с сервером; уже работающий агент переживает обрывы через spool и повторы
с backoff/jitter. Ключевые/неустранимые ошибки сохраняют очередь и завершают агент.

Отдельный watchdog следит за квотой даже во время заблокированной отправки.
При заполнении spool захват останавливается с явной ошибкой, неподтверждённые
файлы не перезаписываются. После перезапуска старый epoch доставляется и
закрывается, затем регистрируется новый. Обрыв захвата не выдаётся за непрерывный
поток. Остановка Ctrl+C закрывает последний файл и пытается доставить очередь.

## Наблюдение

```bash
docker compose ps
docker compose logs -f parser-worker detector-worker
```

С агентским ключом доступны:

- `POST /v1/streams` — идемпотентная регистрация UUID;
- `PUT /v1/streams/{id}/chunks/{sequence}` — бинарный PCAP/PCAPNG;
- `POST /v1/streams/{id}/seal` — закрытие полной последовательности;
- `GET /v1/streams/{id}/status` — статусы файлов, parser-владельцы,
  `processed_sequence`, время и ошибка детектора;
- `GET /v1/events?limit=100` — события, вызванные потоками этого агента.

Другой агент не может читать/изменять чужой поток. События и outbox фиксируются
в PostgreSQL вместе с checkpoint и прогрессом. Внешний доставщик уведомлений
пока не реализован; локальные `reaction.out` не отправляются сервером автоматически.

С ошибкой parser файл остаётся в статусе `error`, с ошибкой reducer останавливается
соответствующий домен. Ошибки и пробелы не обходятся молча. Для изменения правил
или повторного анализа создайте отдельный домен и отправьте исходники заново:
checkpoint содержит hash правил и не применяется к другой конфигурации.

## Гарантии порядка и восстановления

В заданиях parser есть lease, heartbeat и поколение владельца. Если старый worker
оживает после передачи задания, он не может опубликовать результат. Разобранный
файл атомарно публикуется как отсортированный JSONL-артефакт, затем фиксируется
в PostgreSQL.

Reducer объединяет готовые начала файлов всех зарегистрированных потоков домена.
Watermark ограничен самым медленным входом. Файл 42, готовый раньше файла 41,
ожидает недостающие данные; окна атак не сбрасываются на границе файлов.
Checkpoint содержит счётчики, TCP/IPv4 fragment state и byte-offset артефактов.
Его фиксация, alarms, outbox и прогресс потоков выполняются одной транзакцией.
Каждый batch восстанавливается из PostgreSQL, поэтому смена detector-worker
не теряет незавершённые сообщения и окна.

Сейчас один домен в каждый момент последовательно обрабатывается одним reducer.
Разные домены выполняются параллельно; N parser работают независимо по файлам.
Дальнейшее дробление одного домена на shards по целям пока не реализовано.

## Ограничения текущей версии

- Часы агентов одного домена должны быть согласованы. Timestamps внутри файла
  сортируются, а диапазоны последовательных файлов должны не убывать.
  Более ранний диапазон останавливает домен с ошибкой вместо отбрасывания пакетов.
- Отсутствующий/idle вход консервативно удерживает watermark. Длительная пауза
  одного live-агента задерживает итоговый анализ домена; автоматического idle
  timeout с потерей полноты нет. Завершённый поток нужно явно закрыть `/seal`.
- Parser поддерживает Ethernet/VLAN, raw IP, Linux SLL/SLL2, IPv4/IPv6,
  обычный PCAP и PCAPNG с одним интерфейсом и Enhanced Packet Blocks.
  Усечённые capture-кадры, другие PCAPNG layouts и IPv6 fragmentation
  отвергаются явно. IPv4 fragments и TCP-сегменты собираются между файлами.
- Потоковый прикладной decoder поддерживает HTTP/1.x, HTTP Basic, FTP-команды,
  TELNET prompts, SMB/SMB2 Session Setup. Это ограниченный decoder для детекторов,
  а не полный набор dissectors TShark. TLS, HTTP/2 и зашифрованная SSH-аутентификация
  не декодируются. Захват, начавшийся посередине сообщения, не восстанавливает
  отсутствующие байты.
- Некорректное прикладное сообщение или переполнение reassembly даёт событие
  `DECODE_WARNING`, очищает состояние затронутого flow и сохраняет L3/L4-анализ.
- Quota capture-хранилища — 2 GiB на агента (`NF_MAX_BACKLOG`), размер запроса —
  32 MiB, открытых потоков — 16 (`NF_MAX_STREAMS`). Исходники и артефакты пока
  не удаляются автоматически; при достижении квоты приём отвечает `429`.
  Для длительной эксплуатации нужны retention/архивирование и общий disk quota.
- Окна/reassembly/checkpoint ограничены по объёму; превышение checkpoint-лимита
  останавливает домен явно. Checkpoint — доверенный внутренний pickle в PostgreSQL;
  входящие файлы не десериализуются через pickle. Общий DB-доступ является
  административной привилегией.
- Compose на одном хосте сохраняет данные в volumes, но не даёт отказоустойчивости
  самого хоста/диска. Резервирование PostgreSQL и хранилища — отдельная задача.

## Проверки

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

Интеграционные тесты требуют disposable PostgreSQL. Каждый тест создаёт и удаляет
только свой временный schema; используйте отдельную тестовую БД:

```bash
NF_TEST_DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/TEST_DB python3 -m pytest -q
```

Проверены обратный порядок завершения двух parser, атака на границе файлов,
объединение двух агентов, HTTP Basic через разрезанный TCP-заголовок,
восстановление checkpoint после каждого пакета, fencing устаревших worker,
повтор загрузки после потери ответа, отзыв ключа, SHA-256 и ошибки захвата.

Отдельный HTTPS smoke-test для изолированного Compose:

```bash
python3 -m benchmarks.compose_smoke \
  --server https://localhost:8443 --key-file .local/test-agent.key \
  --ca .local/server.crt
```

Он требует **отдельный новый домен**, защищаемый `192.168.1.1`, лимиты DDoS=3,
HTTP=2, brute force HTTP Basic=2 и отключённый C2 для искусственного шумового
трафика. Не меняйте рабочие правила ради теста: используйте отдельный Compose
project и override mounts. Тест создаёт только искусственные пакеты.

В текущем прогоне 150004 пакета прошли через TLS и два parser. Малый второй файл
завершился раньше большого первого на другом worker. Сервер выдал три ожидаемых
события: DDoS, HTTP flood и HTTP Basic brute force. Окна и частичный HTTP-заголовок
сохранились при смене detector-worker между batch.

Сетевая схема использует стандартные механизмы
[Docker Compose networking](https://docs.docker.com/compose/how-tos/networking/) и
[TLS termination NGINX](https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/).
