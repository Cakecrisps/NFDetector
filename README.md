# NetFreak Detector (NFDetect)

**NetFreak Detector** — интеллектуальная система мониторинга сети, предназначенная для обнаружения аномалий в вашей сети: необычных активностей, подозрительного поведения и потенциальных угроз, отклоняющихся от нормальных шаблонов трафика.

## 📋 Содержание

1. [Особенности системы](#особенности-системы)
2. [Требования](#требования)
3. [Установка](#установка)
4. [Быстрый старт](#быстрый-старт)
5. [Детальное руководство](#детальное-руководство)
   - [Режим Live-мониторинга](#режим-live-мониторинга)
   - [Режим анализа файлов](#режим-анализа-файлов)
6. [Конфигурация](#конфигурация)
   - [Файл правил (rules.json)](#файл-правил-rulesjson)
   - [Файл защищенных IP (protectips.txt)](#файл-защищенных-ip-protectipstxt)
   - [Файл подозрительных IP (suspips.txt)](#файл-подозрительных-ip-suspipstxt)
7. [Система обнаружения угроз](#система-обнаружения-угроз)
8. [Система уведомлений](#система-уведомлений)
9. [Структура выходных данных](#структура-выходных-данных)
10. [Примеры использования](#примеры-использования)
11. [Устранение неполадок](#устранение-неполадок)

## Особенности системы

NFDetect — это продвинутая система обнаружения сетевых аномалий с поддержкой:

- **Live-мониторинг в реальном времени** с отладкой
- **Анализ PCAP-файлов** для оффлайн-расследования
- **Обнаружение атак перебора** (Brute Force) по 5+ протоколам
- **Выявление DDoS атак** (одиночных и распределенных)
- **Детектирование SYN/HTTP флуда**
- **Анализ C2-трафика и биконирования**
- **Многоуровневые уведомления** (консоль, лог, внешние домены)

Текущий монитор использует потоковые счётчики и очереди меток времени:
пакет декодируется для детекторов один раз, полный обход окон на каждом пакете
не выполняется. Оповещения о превышении порога повторно разрешаются после
снижения счётчика ниже порога. PCAP читается одним проходом без сохранения
всех объектов PyShark в памяти.

- [Замеры и ограничения производительности](docs/performance.md)
- [Проект архитектуры: агенты с ключами → PCAP → сервер](docs/agent-server.md)

Распределённый режим реализован отдельно: [запуск Compose, выдача ключей и агент](docs/distributed.md).
Файлы одного потока разбираются параллельно; события объединяются перед детектированием.
Наружу опубликован только HTTPS-порт 443 у LB с одним сертификатом сервера.
API, PostgreSQL и worker общаются в закрытой Docker-сети; отдельных сертификатов им не нужно.
По тому же HTTPS-адресу доступна веб-панель: статистика, агенты, события и ключи.
Первый вход — `root:root` с одноразовым кодом с сервера и обязательной сменой пароля.
Команды ниже запускают локальный монитор. Потоковый анализ требует неубывающих временных меток пакетов.

## Требования

- Python 3.8 или выше
- Права администратора для live-захвата
- Установленный TShark (`sudo apt install tshark` для Debian/Ubuntu)
- Установленные зависимости:

```bash
pip install -r requirements.txt
# Дополнительные зависимости из requirements.txt
```

## Установка

1. Клонируйте репозиторий или скачайте файлы проекта:

```bash
git clone <repository-url>
cd NetFreak-Detector
```

2. Установите зависимости:

```bash
pip install -r requirements.txt
```

## Проверка тестами

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Тесты детекторов и монитора используют искусственные пакеты и не требуют TShark или прав администратора.

## Быстрый старт

### Мониторинг в реальном времени

```bash
python nfdetect.py live -i eth0
```

### Анализ захваченного трафика

```bash
python nfdetect.py file -f capture.pcap
```

### Полный мониторинг с отладкой

```bash
python nfdetect.py live -i eth0 -d --rules strict_rules.json --output daily_report
```

## Детальное руководство

### Режим Live-мониторинга

#### Просмотр доступных интерфейсов

```bash
python nfdetect.py live
# Система покажет список доступных интерфейсов
```

#### Базовый мониторинг

```bash
python nfdetect.py live -i eth0
```

#### Мониторинг с расширенными настройками

```bash
python nfdetect.py live -i wlan0 \
  -d \
  --rules custom_rules.json \
  --protected_ips ext/my_trusted_ips.txt \
  --output /var/log/nfdetect \
  --log_file security_monitor_$(date +%Y%m%d).log
```

### Режим анализа файлов

#### Анализ одиночного файла

```bash
python nfdetect.py file -f /path/to/capture.pcap
```

#### Пакетный анализ

```bash
for pcap in captures/*.pcap; do
  python nfdetect.py file -f "$pcap" --output "analysis_$(basename "$pcap" .pcap)"
done
```

#### Анализ с кастомными правилами

```bash
python nfdetect.py file -f incident.pcap \
  --rules incident_rules.json \
  --protected_ips ext/corporate_ips.txt
```

## Конфигурация

### Файл правил (rules.json)

```json
{
  "brute_force": {
    "enabled": true,
    "auth_proto": ["SMB", "SMB2", "SSH", "FTP", "TELNET"],
    "tryes_limit": 10.0,
    "tryes_limit_window": 20.0,
    "warn_tryes_limit_window": 100.0
  },
  "ddos": {
    "enabled": true,
    "1ip": {
      "request_limit": 1000.0,
      "request_limit_window": 1.0
    },
    "nip": {
      "request_limit": 5000.0,
      "request_limit_window": 1.0,
      "display_ips": 10
    }
  },
  "flood": {
    "enabled": true,
    "SYN": {
      "syn_only_limit": 50.0,
      "syn_only_window": 5.0
    },
    "HTTP": {
      "request_rate_limit": 80.0,
      "request_rate_window": 1.0
    }
  },
  "C2_analysys": {
    "enabled": true,
    "beaconing_detection": {
      "enabled": true,
      "jitter_sec": 5,
      "interval_min_sec": 10,
      "interval_max_sec": 300,
      "min_consistent_connections": 5
    }
  },
  "reaction": {
    "out": ["PRINT", "LOG", "example.com", "alerts.mydomain.com"]
  },
  "suspicious_ips": {
    "enabled": true,
    "files_of_susp_ip_list": ["ext/suspips.txt"]
  }
}
```

### Описание параметров правил

#### 1. **brute_force** - Обнаружение атак перебора
- `enabled`: Включить/выключить модуль
- `auth_proto`: Протоколы для мониторинга (SMB, SMB2, SSH, FTP, TELNET)
- `tryes_limit`: Максимальное количество попыток аутентификации
- `tryes_limit_window`: Временное окно для подсчета попыток (секунды)
- `warn_tryes_limit_window`: Окно для предупреждений о массовых попытках

#### 2. **ddos** - Обнаружение DDoS атак
- **1ip** (одиночный источник):
  - `request_limit`: Максимальное количество запросов
  - `request_limit_window`: Временное окно (секунды)
- **nip** (распределенная атака):
  - `request_limit`: Общий лимит пакетов от нескольких IP за временное окно
  - `request_limit_window`: Временное окно (секунды)
  - `display_ips`: Сколько IP показать в отчете

#### 3. **flood** - Обнаружение флуда
- **SYN flood**:
  - `syn_only_limit`: Лимит SYN-пакетов без ответов
  - `syn_only_window`: Временное окно (секунды)
- **HTTP flood**:
  - `request_rate_limit`: Лимит HTTP-запросов
  - `request_rate_window`: Временное окно (секунды)

#### 4. **C2_analysys** - Анализ C2-трафика
- `beaconing_detection`: Обнаружение биконирования (периодических соединений)
  - `jitter_sec`: Допустимый разброс интервала (секунды)
  - `interval_min_sec`: Минимальный интервал между соединениями
  - `interval_max_sec`: Максимальный интервал между соединениями
  - `min_consistent_connections`: Минимальное количество последовательных соединений

#### 5. **reaction** - Реакция системы
- `out`: Способы вывода уведомлений
  - `PRINT` - вывод в консоль (режим реального времени)
  - `LOG` - запись в лог-файл
  - `example.com` - отправка уведомлений на внешний домен (веб-хук)

#### 6. **suspicious_ips** - Работа со списком подозрительных IP
- `enabled`: Использовать ли список подозрительных IP
- `files_of_susp_ip_list`: Путь к файлу со списком IP

### Файл защищенных IP (protectips.txt)

```
# Корпоративные серверы
192.168.1.1      # Основной шлюз
192.168.1.10     # DNS сервер
#Укажите те ip которые будут анализириваться при ddos/brute/flodd etc...

```

### Файл подозрительных IP (suspips.txt)

```
# Известные сканеры Shodan
185.163.45.18
45.155.205.123
185.220.101.4

# Подозрительные хосты из черных списков
94.102.49.193
91.219.236.222
103.10.197.50

# Ботнет C&C серверы
198.51.100.23
203.0.113.45
```

## Система обнаружения угроз

### 1. Brute Force Detection
- **Протоколы**: SMB, SMB2, SSH, FTP, TELNET
- **Триггер**: >10 попыток за 20 секунд
- **Массовая атака**: >100 попыток за 100 секунд

### 2. DDoS Protection
- **Одиночный источник**: >1000 запросов/сек
- **Распределенная атака**: ≥5000 пакетов за окно от двух и более IP
- **Отображение**: Топ-10 атакующих IP

### 3. Flood Prevention
- **SYN Flood**: >50 SYN без ACK за 5 секунд
- **HTTP Flood**: >80 запросов/сек

### 4. C2 Beaconing Detection
- **Интервал**: 10-300 секунд с джиттером ±5с
- **Триггер**: 5+ последовательных соединений

## Система уведомлений

### Уровни уведомлений

```json
"reaction": {
  "out": ["PRINT", "LOG", "alerts.corp.com", "slack-webhook.com"]
}
```

#### 1. **PRINT** - Консольный вывод
```
[WARNING] Brute Force detected from 192.168.1.50
Protocol: SSH, Attempts: 15, Window: 20s
```

#### 2. **LOG** - Файловое логирование
```bash
cat out/log_2024-01-15_14-30-00.txt
```

#### 3. **Внешние домены** - Веб-хуки
- Отправка JSON уведомлений на указанные домены
- Поддержка REST API endpoints
- Интеграция с SIEM системами

### Пример конфигурации уведомлений

```json
"reaction": {
  "out": [
    "PRINT",
    "LOG",
    "alerts.corporation.com/api/v1/security",
    "123.com",
    "logserver.corp.com:514"
  ]
}
```

## Структура выходных данных

```
NetFreak-Detector/
├── nfdetect.py          # Основной скрипт
├── rules.json           # Конфигурация правил
├── requirements.txt     # Зависимости Python
├── ext/                # Конфигурационные файлы
│   ├── protectips.txt  # Защищенные IP
│   └── suspips.txt     # Подозрительные IP
├── out/                # Результаты анализа (по умолчанию)
│   ├── log_2024-01-15_14-30-00.txt # Логированные угрозы
│   ├── log_2024-01-15_14-30-00_full_report.json     # Полный json отчет
│   ├── log_2024-01-15_14-30-00_summary.txt # Статистика трафика
└── general/           # Модули системы
    └── uTrafficMonitor/
```

### Формат лог-файла

```
=== NFDetect Session Start ===
Время: 2024-01-15 14:30:00
Режим: live
Интерфейс: eth0
Отладка: Включена
Файл: N/A
==============================

[14:30:05] INFO: Начало захвата трафика
[14:30:15] WARNING: Brute Force - 192.168.1.50 -> SSH (12 попыток)
[14:30:20] ALERT: DDoS detected - 203.0.113.1 (1050 requests/sec)
[14:31:00] INFO: Отправка уведомления на alerts.corp.com
```

## Примеры использования

### Пример 1: Мониторинг корпоративной сети

```bash
sudo python nfdetect.py live -i enp3s0 \
  --rules corporate_rules.json \
  --protected_ips ext/corporate_ips.txt \
  --output /var/log/nfdetect/daily \
  --log_file $(date +%Y%m%d)_security.log
```

### Пример 2: Анализ инцидента безопасности

```bash
python nfdetect.py file -f incident_20240115.pcap \
  --rules forensic_rules.json \
  --protected_ips ext/trusted_assets.txt \
  --output incident_analysis \
  --log_file forensic_report.txt
```

### Пример 3: Интеграция с SIEM системой

```json
"reaction": {
  "out": [
    "PRINT",
    "LOG",
    "https://splunk.corp.com:8088/services/collector/event",
    "https://elastic.corp.com:9200/security-events/_doc"
  ]
}
```

```bash
python nfdetect.py live -i eth0 --rules siem_integration.json
```

### Пример 4: Мониторинг веб-инфраструктуры

```json
{
  "ddos": {
    "enabled": true,
    "1ip": {
      "request_limit": 5000.0,
      "request_limit_window": 1.0
    }
  },
  "flood": {
    "enabled": true,
    "HTTP": {
      "request_rate_limit": 1000.0,
      "request_rate_window": 1.0
    }
  },
  "reaction": {
    "out": ["PRINT", "LOG", "webhooks.ops-team.com"]
  }
}
```

## Устранение неполадок

### Ошибка: "Permission denied"
```bash
sudo python nfdetect.py live -i eth0
```

### Ошибка: "Файл не найден"
```bash
# Создайте обязательные файлы
touch ext/protectips.txt
touch ext/suspips.txt
cp rules.example.json rules.json
```

### Ошибка: "Interface not found"
```bash
# Список доступных интерфейсов
python nfdetect.py live
# или
ip link show
```

### Проблемы с отправкой уведомлений

```json
"reaction": {
  "out": ["PRINT", "LOG"]  # Временно отключите внешние домены
}
```

### Отладка модулей

```bash
python nfdetect.py live -i eth0 -d 2> debug.log
```

## Производительность

### Рекомендации по настройке

1. **Для высоконагруженных сетей**:
```json
{
  "ddos": {
    "1ip": {
      "request_limit": 10000.0
    }
  },
  "flood": {
    "HTTP": {
      "request_rate_limit": 5000.0
    }
  }
}
```

2. **Для чувствительных систем**:
```json
{
  "brute_force": {
    "tryes_limit": 3.0,
    "tryes_limit_window": 10.0
  },
  "C2_analysys": {
    "beaconing_detection": {
      "jitter_sec": 2,
      "min_consistent_connections": 3
    }
  }
}
```

**Важное примечание**: Используйте систему только на сетях, где у вас есть соответствующие разрешения на мониторинг трафика. Система предназначена для целей безопасности и защиты сетевой инфраструктуры.
