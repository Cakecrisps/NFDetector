# Справочник Python

<a href="../api/index.html">Открыть сгенерированный справочник кода</a>

HTML-справочник создаёт pydoctor при общей сборке; в исходном Markdown
ссылка ведёт в результат сборки `documentation/api/index.html`.

| Модуль | Назначение |
| --- | --- |
| `distributed.api`, `web`, `web_auth`, `web_security` | Приём, веб-маршруты, сессии, защита ответов |
| `distributed.agent`, `service`, `installer`, `installation`, `tls` | Захват, управляемая служба, bootstrap, TLS pin |
| `distributed.capture`, `flows` | PCAP parser, TCP/IP и прикладное состояние |
| `distributed.store`, `workers`, `incidents`, `schema.sql` | Очереди, lease, reducer, инциденты, данные |
| `distributed.web_metrics`, `settings` | Статистика и конфигурация |
| `general.streaming`, `trafficanalyzer`, `authdetect` | Потоковые правила и распознавание аутентификации |
| `general.uTrafficMonitor`, `summarygen`, `AlarmClass`, `logs` | Локальный монитор и отчёты |
| `nfdetect` | Локальная CLI |

API-справочник объясняет классы и функции по docstrings. Он дополняет
[архитектуру](../architecture/overview.md) и [HTTP-контракт](../architecture/api.md),
а не заменяет инструкции оператора. UI assets и SQL описаны в руководстве,
поскольку pydoctor документирует Python.
