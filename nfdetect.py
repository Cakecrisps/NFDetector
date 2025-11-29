import argparse
import sys
import os

def parse_arguments():
    """
    Парсинг аргументов командной строки
    """
    parser = argparse.ArgumentParser(
        description='NFDetect - детектор сетевых аномалий',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Обязательный аргумент - режим работы
    parser.add_argument(
        'mode',
        choices=['live', 'file'],
        help='Режим работы: live - реальное время, file - анализ файла'
    )
    
    # Опциональные аргументы
    parser.add_argument(
        '-pi', '--protected_ips',
        dest='protected_ips',
        default='ext/protectips.txt',
        help='Путь к файлу с защищенными IP-адресами (по умолчанию: ext/protectips.txt)'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_dir',
        default='/out',
        help='Путь к папке для вывода результатов (по умолчанию: /out)'
    )
    
    # Дополнительный аргумент для пути к файлу (если режим file)
    parser.add_argument(
        'file_path',
        nargs='?',  # Делаем аргумент опциональным
        help='Путь к файлу для анализа (требуется в режиме file)'
    )
    
    return parser.parse_args()

def validate_arguments(args):
    """
    Валидация аргументов
    """
    # Проверка режима file
    if args.mode == 'file':
        if not args.file_path:
            print("Ошибка: в режиме 'file' необходимо указать путь к файлу")
            sys.exit(1)
        
        if not os.path.exists(args.file_path):
            print(f"Ошибка: файл '{args.file_path}' не существует")
            sys.exit(1)
    
    # Проверка существования файла protected_ips
    if not os.path.exists(args.protected_ips):
        print(f"Предупреждение: файл с защищенными IP '{args.protected_ips}' не существует")
    
    # Создание выходной директории, если её нет
    if not os.path.exists(args.output_dir):
        print(f"Создание выходной директории: {args.output_dir}")
        os.makedirs(args.output_dir, exist_ok=True)

def main():
    """
    Основная функция
    """
    try:
        # Парсинг аргументов
        args = parse_arguments()
        
        # Валидация аргументов
        validate_arguments(args)
        
        # Вывод полученных параметров
        print("Параметры запуска:")
        print(f"  Режим: {args.mode}")
        print(f"  Защищенные IP: {args.protected_ips}")
        print(f"  Выходная директория: {args.output_dir}")
        
        if args.mode == 'file' and args.file_path:
            print(f"  Анализируемый файл: {args.file_path}")
        
        # Здесь ваша основная логика
        if args.mode == 'live':
            print("Запуск в режиме реального времени...")
            # Ваш код для live режима
        else:
            print(f"Анализ файла: {args.file_path}")
            # Ваш код для file режима
            
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()