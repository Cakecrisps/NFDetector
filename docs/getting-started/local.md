# Локальный анализ без сервера

Это отдельный режим: результаты пишутся в `out/`, а не в панель/PostgreSQL.
Используйте Python 3.10+ и TShark. Серверный Compose использует Python 3.12.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python nfdetect.py file -f capture.pcap
.venv/bin/python nfdetect.py live -i eth0
```

Установите TShark средствами ОС. Для live-захвата настройте права захвата
интерфейса. При отсутствии `-i` команда сообщает доступные интерфейсы.

| Аргумент | По умолчанию | Назначение |
| --- | --- | --- |
| `-f`, `--file` | — | PCAP для режима `file` |
| `-i`, `--interface` | — | Интерфейс режима `live` |
| `-r`, `--rules` | `rules.json` | Правила |
| `-pi`, `--protected_ips` | `ext/protectips.txt` | Защищаемые цели, не исключения |
| `-o`, `--output` | `out` | Каталог отчётов |
| `-lf`, `--log_file` | Имя с текущей датой | Основной лог |
| `-d`, `--debug` | Выключено | Отладка live-режима |

```bash
.venv/bin/python nfdetect.py file -f incident.pcap \
  --rules rules.json --protected_ips ext/protectips.txt --output out/incident
```

Один монитор сохраняет окна между вызовами `analyze_file`. Отдельные запуски
CLI начинают независимый анализ. Временные метки должны не убывать;
серверный reducer не участвует в локальной CLI.

`reaction.out` используется локальным монитором: `PRINT`, `LOG`, либо домен
для устаревшей синхронной HTTP-отправки. Произвольные URL SIEM с путями,
HTTPS и авторизацией этот механизм не поддерживает. Серверный режим пишет
outbox отдельно; готовой интеграции SIEM сейчас нет.
