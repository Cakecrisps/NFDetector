import argparse
import sys
import os
import datetime
import psutil
from filescan import filescan
from livescan import livescan

def get_available_interfaces():
    """
    Получает список активных сетевых интерфейсов, исключая loopback и виртуальные интерфейсы.
    
    Returns:
        list: Список имен доступных сетевых интерфейсов
    
    Note:
        Фильтрует интерфейсы по префиксам (lo, docker, veth и др.) и проверяет наличие IPv4-адресов.
    """
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        if interface.startswith(('lo', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap')):
            continue
        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                interfaces.append(interface)
                break
    return list(set(interfaces))

def parse_arguments():
    """
    Парсит и валидирует аргументы командной строки.
    
    Returns:
        argparse.Namespace: Объект с обработанными аргументами
    
    Raises:
        SystemExit: При обнаружении некорректных аргументов
    
    Examples:
        $ python nfddetect.py live -i eth0
        $ python nfddetect.py live -i eth0 -d
        $ python nfddetect.py file -f traffic.pcap
    """
    parser = argparse.ArgumentParser(
        description='NFDetect - система детекции сетевых аномалий',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Примеры использования:\n"
               "  Live режим:  python nfddetect.py live -i eth0\n"
               "  Live режим с отладкой: python nfddetect.py live -i eth0 -d\n"
               "  File режим:  python nfddetect.py file -f /path/to/pcap.pcap"
    )
    
    parser.add_argument(
        'mode',
        choices=['live', 'file'],
        help='Режим работы системы'
    )
    
    parser.add_argument(
        '-i', '--interface',
        dest='interface',
        help='Сетевой интерфейс для мониторинга (требуется в live-режиме)'
    )
    
    parser.add_argument(
        '-f', '--file',
        dest='file_path',
        help='Путь к PCAP-файлу для анализа (требуется в file-режиме)'
    )
    
    parser.add_argument(
        '-d', '--debug',
        dest='debug_mode',
        action='store_true',
        help='Включить режим отладки для live-захвата (вывод детальной информации о пакетах)'
    )
    
    parser.add_argument(
        '-pi', '--protected_ips',
        dest='protected_ips',
        default='ext/protectips.txt',
        help='Файл с IP-адресами для исключения из анализа'
    )
    
    parser.add_argument(
        '-r', '--rules',
        dest='rules',
        default='rules.json',
        help='Файл с правилами детекции аномалий'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_dir',
        default='out',
        help='Директория для сохранения результатов'
    )
    
    safe_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    default_log_file = f"log_{safe_datetime}.txt"
    
    parser.add_argument(
        '-lf', '--log_file',
        dest='log_file',
        default=default_log_file,
        help='Имя файла логирования в выходной директории'
    )
    
    return parser.parse_args()

def validate_arguments(args):
    """
    Проводит комплексную валидацию аргументов перед запуском системы.
    
    Args:
        args (argparse.Namespace): Объект с аргументами командной строки
    
    Raises:
        SystemExit: При обнаружении критических ошибок конфигурации
    
    Side Effects:
        - Создает выходную директорию
        - Инициализирует лог-файл
        - Выводит диагностические сообщения в stdout
    """
    # Валидация режимов работы
    if args.mode == 'live' and not args.interface:
        print("Ошибка: для live-режима требуется указать интерфейс через -i")
        print(f"Доступные интерфейсы: {', '.join(get_available_interfaces())}")
        sys.exit(1)
        
    if args.mode == 'file' and not args.file_path:
        print("Ошибка: для file-режима требуется указать файл через -f")
        sys.exit(1)
    
    # Проверка существования файлов конфигурации
    for config_type, path in [('protected_ips', args.protected_ips), ('rules', args.rules)]:
        if not os.path.exists(path):
            print(f"Критическая ошибка: файл {config_type} не найден по пути {os.path.abspath(path)}")
            sys.exit(1)
    
    # Валидация целевого файла в file-режиме
    if args.mode == 'file' and not os.path.exists(args.file_path):
        print(f"Критическая ошибка: файл для анализа не существует: {os.path.abspath(args.file_path)}")
        sys.exit(1)
    
    # Настройка файловой системы
    os.makedirs(args.output_dir, exist_ok=True)
    abs_output_dir = os.path.abspath(args.output_dir)
    
    # Инициализация логирования
    log_path = os.path.join(abs_output_dir, args.log_file)
    header = (
        f"=== NFDetect Session Start ===\n"
        f"Время: {datetime.datetime.now()}\n"
        f"Режим: {args.mode}\n"
        f"Интерфейс: {args.interface if args.mode == 'live' else 'N/A'}\n"
        f"Отладка: {'Включена' if args.debug_mode and args.mode == 'live' else 'Выключена'}\n"
        f"Файл: {args.file_path if args.mode == 'file' else 'N/A'}\n"
        f"{'='*30}\n\n"
    )
    
    try:
        with open(log_path, 'a', encoding='utf-8') as log_file:
            log_file.write(header)
    except IOError as e:
        print(f"Ошибка записи лога: {e}")
        sys.exit(1)

def main():
    """
    Точка входа в приложение. Координирует процесс детекции аномалий.
    
    Workflow:
        1. Парсинг аргументов
        2. Валидация конфигурации
        3. Запуск выбранного режима работы
        4. Обработка системных прерываний
    
    Error Handling:
        - Перехватывает KeyboardInterrupt для graceful shutdown
        - Логирует неожиданные исключения с traceback
    
    Returns:
        None
    
    Raises:
        SystemExit: При критических ошибках или нормальном завершении
    """
    try:
        args = parse_arguments()
        validate_arguments(args)
        
        # Запуск выбранного режима
        if args.mode == 'live':
            print(f"[+] Запуск live-мониторинга на интерфейсе: {args.interface}")
            if args.debug_mode:
                print("[DEBUG] Режим отладки включен: будет выводиться информация о пакетах в live режиме")
            
            livescan(
                args.interface,
                args.output_dir,
                args.log_file,
                args.protected_ips,
                args.rules,
                args.debug_mode
            )
        else:
            print(f"[+] Запуск анализа файла: {args.file_path}")
            filescan(
                pcap_path=args.file_path,
                output_dir=args.output_dir,
                log_file=args.log_file,
                protected_ips=args.protected_ips,
                rules_file=args.rules
            )
            
    except KeyboardInterrupt:
        print("\n[!] Остановка по запросу пользователя")
        sys.exit(0)
    except Exception as e:
        print(f"[CRITICAL] Необработанное исключение: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":   
    main()