#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
from typing import List, Optional
from .logs import log, log_http


class Alarm:
    def __init__(self, reason: str, ipdst: str, ipsrc: str, is_prot: bool):
        """
        Инициализация объекта предупреждения.
        
        Args:
            reason: Причина срабатывания предупреждения
            ipdst: IP адрес назначения
            ipsrc: IP адрес источника
            is_prot: Флаг защищенности IP адреса
        """
        self.reason = reason
        self.ipdst = ipdst
        self.ipsrc = ipsrc
        self.is_prot = is_prot
        self.timestamp = datetime.datetime.now()
        
        # Создание форматированного сообщения
        self.message = f"{self.timestamp} || {reason} || {ipdst} -> {ipsrc} || {is_prot}"

    def __str__(self):
        """Возвращает строковое представление предупреждения."""
        return self.message

    def log(self, logfile: str, logtypes: List[str]) -> List[Optional[Exception]]:
        """
        Логирует предупреждение указанными способами.
        
        Args:
            logfile: Путь к файлу для записи лога
            logtypes: Список типов логирования:
                - "print": вывод в консоль
                - "log": запись в файл
                - доменное имя: отправка по HTTP
                
        Returns:
            Список ошибок (или None при успехе) для каждого типа логирования
        """
        errors = []
        
        # Нормализация и удаление дубликатов типов логирования
        normalized_types = {x.lower() for x in logtypes.copy()}
        
        # Обработка вывода в консоль
        if "print" in normalized_types:
            try:
                print(self.message)
                errors.append(None)
            except Exception as print_error:
                print(f"Ошибка при выводе в консоль: {print_error}")
                errors.append(print_error)
        
        # Обработка записи в файл
        if "log" in normalized_types:
            try:
                log(self.message, logfile)
                errors.append(None)
            except Exception as log_error:
                print(f"Ошибка при записи в файл: {log_error}")
                errors.append(log_error)
        
        # Обработка HTTP логирования
        http_domains = [x for x in normalized_types if x not in ["print", "log"]]
        if http_domains:
            try:
                log_http(self.message, http_domains)
                errors.append(None)
            except Exception as http_error:
                print(f"Ошибка при HTTP логировании: {http_error}")
                errors.append(http_error)
        
        return errors