#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для работы с HTTP-логированием и валидацией доменных имен.
Предоставляет функции для логирования в файлы и отправки логов по HTTP.
"""

import requests
import json
import re
from typing import List


def is_valid_domain(domain_string: str) -> bool:
    """
    Проверяет, соответствует ли строка формату валидного доменного имени.
    
    Args:
        domain_string: Строка для проверки.
        
    Returns:
        True, если строка является валидным доменом, иначе False.
        
    Raises:
        TypeError: если domain_string не является строкой
    """
    if not isinstance(domain_string, str):
        raise TypeError(f"Ожидается строка, получен {type(domain_string)}")
    
    # Регулярное выражение для проверки доменных имен
    # Поддерживает: example.com, sub.example.com, example.co.uk
    # Не поддерживает: локальные домены без TLD
    regex_pattern = r"^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
    
    pattern = re.compile(regex_pattern, re.IGNORECASE)
    return bool(pattern.search(domain_string))


def log(msg: str, pathtofile: str) -> None:
    """
    Записывает сообщение в файл лога.
    
    Args:
        msg: Сообщение для записи в лог
        pathtofile: Путь к файлу лога
        
    Raises:
        PermissionError: если нет прав на запись в файл
        OSError: при ошибках файловой системы
        UnicodeEncodeError: при проблемах с кодировкой
    """
    try:
        # Создаем директорию, если она не существует
        directory = os.path.dirname(pathtofile)
        if directory:
            os.makedirs(directory, exist_ok=True)
        
        with open(pathtofile, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
            f.flush()
            
    except PermissionError as e:
        raise PermissionError(
            f"Нет прав на запись в файл {pathtofile}: {str(e)}"
        )
    except OSError as e:
        raise OSError(f"Ошибка файловой системы при записи в {pathtofile}: {str(e)}")
    except UnicodeEncodeError as e:
        raise UnicodeEncodeError(
            f"Ошибка кодировки при записи сообщения в {pathtofile}: {str(e)}"
        )
    except Exception as e:
        raise RuntimeError(f"Неожиданная ошибка при логировании: {str(e)}")


def log_http(msg: str, domains: List[str]) -> None:
    """
    Отправляет сообщение на указанные домены по HTTP.
    
    Args:
        msg: Сообщение для отправки
        domains: Список доменов для отправки
        
    Raises:
        ValueError: если домен невалидный
        requests.RequestException: при ошибках сетевых запросов
        json.JSONDecodeError: при ошибках сериализации данных
    """
    if not domains:
        print("Предупреждение: список доменов пуст")
        return
    
    for domain in domains:
        try:
            # Валидация домена
            if not is_valid_domain(domain):
                raise ValueError(f"'{domain}' не является валидным доменным именем")
            
            # Подготовка данных
            payload = json.dumps({"msg": msg})
            headers = {
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "TrafficAnalyzer/1.0"
            }
            
            # Отправка запроса
            url = f"http://{domain}/"
            response = requests.post(
                url, 
                data=payload, 
                headers=headers, 
                timeout=10
            )
            
            # Проверка статуса ответа
            if response.status_code not in range(200, 300):
                print(f"Внимание: запрос к {domain} вернул статус {response.status_code}")
                print(f"Ответ: {response.text[:100]}...")
            
        except ValueError as e:
            # Переподнимаем ValueError с информацией о домене
            raise ValueError(f"Ошибка валидации домена '{domain}': {str(e)}")
            
        except requests.Timeout:
            print(f"Таймаут при отправке лога на {domain}")
            
        except requests.ConnectionError:
            print(f"Ошибка подключения к {domain}")
            
        except requests.RequestException as e:
            print(f"Ошибка HTTP запроса к {domain}: {str(e)}")
            
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Ошибка сериализации данных для {domain}: {str(e)}",
                e.doc, 
                e.pos
            )
            
        except Exception as e:
            print(f"Неожиданная ошибка при отправке на {domain}: {str(e)}")


# Добавляем импорт os, который используется в функции log
import os


def setup_logging(config_path: str = "./config/logging.json") -> dict:
    """
    Загружает конфигурацию логирования из JSON файла.
    
    Args:
        config_path: Путь к файлу конфигурации
        
    Returns:
        Словарь с конфигурацией логирования
        
    Raises:
        FileNotFoundError: если файл конфигурации не найден
        json.JSONDecodeError: если файл содержит невалидный JSON
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        # Валидация обязательных полей
        required_fields = ["log_file", "http_domains"]
        for field in required_fields:
            if field not in config:
                raise KeyError(f"Отсутствует обязательное поле '{field}' в конфигурации")
        
        return config
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл конфигурации не найден: {config_path}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Ошибка парсинга JSON в файле {config_path}: {str(e)}",
            e.doc, 
            e.pos
        )
