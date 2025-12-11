import argparse
import sys
import os
import datetime

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
        '-si', '--susp_ips',
        dest='susp_ips',
        default='ext/suspips.txt',
        help='Путь к файлу с подозрительными IP-адресами (по умолчанию: ext/suspips.txt)'
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
    
    # Проверка существования файла protected_ips
    if not os.path.exists(args.protected_ips):
        print(f"Предупреждение: файл с защищенными IP '{args.protected_ips}' не существует")
        exit(1)
    if not os.path.exists(args.susp_ips):
        print(f"Предупреждение: файл с подозрительными IP '{args.susp_ips}' не существует")
        exit(1)
    if not os.path.exists(args.rules):
        print(f"Предупреждение: файл с правилами '{args.rules}' не существует")
        exit(1)
    os.makedirs(args.output_dir, exist_ok=True)
    abs_output_dir = os.path.abspath(args.output_dir)
    
    # Создаем полный путь к файлу логов
    full_log_path = os.path.join(args.output_dir, args.log_file)
    
    if not os.path.exists(full_log_path):
        with open(full_log_path, "w") as f:
            f.write(f"Лог запуска: {datetime.datetime.now()}\n")
            f.write(f"Режим: {args.mode}\n")
    else:
        with open(full_log_path, "a",encoding="utf-8") as f:
            f.write(f"\n--- Новый запуск: {datetime.datetime.now()} ---\n")

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
        
        print("Параметры запуска:")
        print(f"  Режим: {args.mode}")
        print(f"  Защищенные IP: {args.protected_ips}")
        print(f"  Выходная директория: {args.output_dir}")
        print(f"  Файл логов: {args.log_file}")
        
        if args.mode == 'file' and args.file_path:
            print(f"  Анализируемый файл: {args.file_path}")
        
        # Здесь ваша основная логика
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