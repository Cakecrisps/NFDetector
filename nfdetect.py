#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import datetime
import psutil
from general.uTrafficMonitor import filescan, livescan


def get_available_interfaces():
    """
    Получает список активных сетевых интерфейсов.
    
    Returns:
        list: Список имен доступных сетевых интерфейсов
    """
    try:
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            if interface.startswith(('lo', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap')):
                continue
            for addr in addrs:
                if addr.family == 2:
                    interfaces.append(interface)
                    break
        return list(set(interfaces))
    except Exception as e:
        print(f"Ошибка при получении списка интерфейсов: {e}")
        return []


def parse_arguments():
    """
    Парсит аргументы командной строки.
    
    Returns:
        argparse.Namespace: Объект с обработанными аргументами
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
        help='Включить режим отладки для live-захвата'
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

    try:
        return parser.parse_args()
    except SystemExit:
        print("Ошибка парсинга аргументов")
        sys.exit(1)


def validate_arguments(args):
    """
    Проводит валидацию аргументов перед запуском системы.
    
    Args:
        args: Объект с аргументами командной строки
    
    Raises:
        ValueError: При ошибках валидации
        FileNotFoundError: При отсутствии файлов
    """
    if args.mode == 'live' and not args.interface:
        interfaces = get_available_interfaces()
        raise ValueError(
            f"Для live-режима требуется указать интерфейс через -i\n"
            f"Доступные интерфейсы: {', '.join(interfaces)}"
        )

    if args.mode == 'file' and not args.file_path:
        raise ValueError("Для file-режима требуется указать файл через -f")

    for config_type, path in [
        ('protected_ips', args.protected_ips),
        ('rules', args.rules)
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Файл {config_type} не найден: {path}")

    if args.mode == 'file' and not os.path.exists(args.file_path):
        raise FileNotFoundError(f"PCAP файл не найден: {args.file_path}")

    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        raise ValueError(f"Ошибка создания директории {args.output_dir}: {e}")

    log_path = os.path.join(args.output_dir, args.log_file)
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
    except OSError as e:
        raise ValueError(f"Ошибка записи лог-файла {log_path}: {e}")


def main():
    """
    Точка входа в приложение.
    """
    try:
        args = parse_arguments()
        validate_arguments(args)

        if args.mode == 'live':
            print(f"Запуск live-мониторинга на интерфейсе: {args.interface}")
            if args.debug_mode:
                print("Режим отладки включен")

            livescan(
                interface=args.interface,
                output_dir=args.output_dir,
                log_file=args.log_file,
                protected_ips=args.protected_ips,
                rules_file=args.rules,
                debug_mode=args.debug_mode
            )
        else:
            print(f"Запуск анализа файла: {args.file_path}")
            filescan(
                path_to_file=args.file_path,
                path_to_output_dir=args.output_dir,
                output_filename=args.log_file,
                path_to_prot_ips=args.protected_ips,
                path_to_rules=args.rules
            )

    except KeyboardInterrupt:
        print("\nОстановка по запросу пользователя")
        sys.exit(0)
    except ValueError as e:
        print(f"Ошибка валидации: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Файл не найден: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()