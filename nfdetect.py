import argparse
import sys
import os
import datetime
from filescan import filescan
def parse_arguments():
    """
    Парсинг аргументов командной строки
    """
    parser = argparse.ArgumentParser(
        description='NFDetect - детектор сетевых аномалий',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'mode',
        choices=['live', 'file'],
        help='Режим работы: live - реальное время, file - анализ файла'
    )
    parser.add_argument(
        '-pi', '--protected_ips',
        dest='protected_ips',
        default='ext/protectips.txt',
        help='Путь к файлу с защищенными IP-адресами (по умолчанию: ext/protectips.txt)'
    )
    parser.add_argument(
        '-r', '--rules',
        dest='rules',
        default='rules.json',
        help='Путь к файлу с правилами (по умолчанию: rules.json)'
    )
    parser.add_argument(
        '-o', '--output',
        dest='output_dir',
        default='out',
        help='Путь к папке для вывода результатов (по умолчанию: out)'
    )
    
    parser.add_argument(
        'file_path',
        nargs='?',  
        help='Путь к файлу для анализа (требуется в режиме file)'
    )
    
    # Исправлено: создаем корректное имя файла
    safe_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    default_log_file = f"log_{safe_datetime}.txt"
    
    parser.add_argument(
        '-lf', '--log_file',
        dest='log_file',
        default=default_log_file,
        help='Путь к файлу логирования (по умолчанию: log_YYYY-MM-DD_HH-MM-SS.txt)'
    )
    
    return parser.parse_args()

def validate_arguments(args):
    """
    Валидация аргументов
    """
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
        exit(1)
    if not os.path.exists(args.rules):
        print(f"Предупреждение: файл с правилами '{args.rules}' не существует")
        exit(1)
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"Выходная директория: {os.path.abspath(args.output_dir)}")
    
    # Создаем полный путь к файлу логов
    full_log_path = os.path.join(args.output_dir, args.log_file)
    
    if not os.path.exists(full_log_path):
        with open(full_log_path, "w",encoding="utf-8") as f:
            f.write(f"Лог запуска: {datetime.datetime.now()}\n")
            f.write(f"Режим: {args.mode}\n")
    else:
        with open(full_log_path, "a",encoding="utf-8") as f:
            f.write(f"\n--- Новый запуск: {datetime.datetime.now()} ---\n")

def main():
    """
    Основная функция
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
            filescan(args.file_path,args.output_dir,args.log_file,args.protected_ips,args.rules)
        
        # Здесь ваша основная логика
        if args.mode == 'live':
            print("Запуск в режиме реального времени...")
            # Ваш код для live режима
        else:
            print(f"Анализ файла: {args.file_path}")
            # Ваш код для file режима
            
    except Exception as e:
        print(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()