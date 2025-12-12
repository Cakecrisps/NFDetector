#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Модуль для мониторинга трафика + создание плавающих окон и сбор поверхностной статистики.

"""


import json
import pyshark
from typing import List, Dict, Any, Set, Optional
import math
import datetime
import os
import threading
import time
import asyncio
from general.trafficanalyzer import TrafficAnalyzer
from general.AlarmClass import Alarm
from general.summarygen import generate_summary, generate_full_json_summary

from pyshark.packet.packet import Packet


class NetworkTrafficMonitor:
    """
    Монитор сетевого трафика с поддержкой временных окон для обнаружения аномалий.
    
    Класс обеспечивает захват и анализ сетевого трафика в реальном времени или из файлов PCAP,
    используя систему временных окон для обнаружения различных типов атак (DDoS, brute force,
    flood атаки, C2-коммуникации и др.).

    Attributes:
        rules_path (str): Путь к файлу с правилами обнаружения аномалий.
        protected_ips_path (str): Путь к файлу с защищенными IP-адресами.
        output_dir (str): Директория для сохранения отчетов и логов.
        log_path (str): Полный путь к файлу лога.
        debug_mode (bool): Флаг режима отладки.
        alarms (List): Список обнаруженных тревог.
        rules (Dict): Загруженные правила обнаружения.
        suspicious_ips (Set): Множество подозрительных IP-адресов.
        protected_ips (Set): Множество защищенных IP-адресов.
        statistics (Dict): Статистика по анализируемому трафику.
        windows (Dict): Словарь временных окон для разных типов анализа.
        analyzer (TrafficAnalyzer): Анализатор трафика.
        stop_flag (bool): Флаг для остановки захвата трафика.
        capture_thread (threading.Thread): Поток захвата трафика.

    Args:
        rules_path (str): Путь к JSON-файлу с правилами обнаружения.
        protected_ips_path (str): Путь к файлу со списком защищенных IP.
        output_dir (str): Директория для выходных файлов.
        log_filename (str): Имя файла лога.
        debug_mode (bool): Включить режим отладки (по умолчанию False).

    Raises:
        FileNotFoundError: Если не найден файл с правилами или защищенными IP.
        ValueError: Если файл правил содержит невалидный JSON.
        RuntimeError: При ошибках инициализации компонентов монитора.
    """

    def __init__(
        self,
        rules_path: str,
        protected_ips_path: str,
        output_dir: str,
        log_filename: str,
        debug_mode: bool = False
    ):
        self.rules_path = rules_path
        self.protected_ips_path = protected_ips_path
        self.output_dir = output_dir
        self.log_path = os.path.join(output_dir, log_filename)
        self.debug_mode = debug_mode
        self.alarms = []

        try:
            self._load_configuration()
            self.statistics = self._init_statistics()
            self.windows = self._init_windows()
            self.analyzer = TrafficAnalyzer(rules_path, protected_ips_path)
            self.stop_flag = False
            self.capture_thread = None
            os.makedirs(output_dir, exist_ok=True)
            self._init_log_file()
        except Exception as e:
            raise RuntimeError(f"Ошибка инициализации монитора: {e}")

    def _load_configuration(self):
        """Загружает правила и списки IP-адресов из файлов."""
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                self.rules = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл правил не найден: {self.rules_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Неверный формат JSON в файле: {self.rules_path}")

        self.suspicious_ips = set()
        self.suspicious_ips_sources = []

        susp_ips_config = self.rules.get("suspicious_ips", {})
        if susp_ips_config.get("enabled", False):
            files_list = susp_ips_config.get("files_of_susp_ip_list", [])
            for file_path in files_list:
                self.suspicious_ips_sources.append(file_path)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                self.suspicious_ips.add(ip)
                        if self.debug_mode:
                            print(f"Загружено {len(self.suspicious_ips)} подозрительных IP")
                except FileNotFoundError as e:
                    print(f"Файл с подозрительными IP не найден: {file_path}")
                except Exception as e:
                    print(f"Ошибка загрузки подозрительных IP: {e}")

        try:
            self.protected_ips = set()
            with open(self.protected_ips_path, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.protected_ips.add(ip)
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл с защищенными IP не найден: {self.protected_ips_path}")
        except Exception as e:
            raise RuntimeError(f"Ошибка загрузки защищенных IP: {e}")

    def _init_statistics(self) -> Dict[str, Any]:
        """
        Инициализирует структуру для сбора статистики.

        Returns:
            Dict[str, Any]: Словарь с начальной структурой статистики.
        """
        return {
            "total": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "protos": {},
            "src_ips": {},
            "dst_ips": {},
            "dns": {},
            "suspicious_ips": {
                "total_packets": 0,
                "src_count": 0,
                "dst_count": 0,
                "src_ips": {},
                "dst_ips": {}
            }
        }

    def _init_windows(self) -> Dict[str, Dict]:
        """
        Инициализирует временные окна для всех правил.

        Returns:
            Dict[str, Dict]: Словарь временных окон для различных типов анализа.
        """
        windows = {}

        if self.rules.get("brute_force", {}).get("enabled", False):
            window_sec = self.rules["brute_force"].get("tryes_limit_window", 20.0)
            windows["brute_force_tryes_limit"] = {
                "packets": [],
                "window_sec": window_sec,
                "last_analysis": 0
            }

        if self.rules.get("ddos", {}).get("enabled", False):
            ddos_rules = self.rules["ddos"]

            if "1ip" in ddos_rules:
                window_sec = ddos_rules["1ip"].get("request_limit_window", 1.0)
                windows["ddos_1ip"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}

            if "nip" in ddos_rules:
                window_sec = ddos_rules["nip"].get("request_limit_window", 1.0)
                windows["ddos_nip"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}

        if self.rules.get("flood", {}).get("enabled", False):
            flood_rules = self.rules["flood"]

            if "SYN" in flood_rules:
                window_sec = flood_rules["SYN"].get("syn_only_window", 5.0)
                windows["flood_SYN"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}

            if "HTTP" in flood_rules:
                window_sec = flood_rules["HTTP"].get("request_rate_window", 1.0)
                windows["flood_HTTP"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}

        if self.rules.get("C2_analysys", {}).get("enabled", False):
            c2_rules = self.rules["C2_analysys"]
            if c2_rules.get("beaconing_detection", {}).get("enabled", False):
                min_interval = c2_rules["beaconing_detection"].get("interval_min_sec", 10)
                max_interval = c2_rules["beaconing_detection"].get("interval_max_sec", 300)

                windows["C2_min_interval"] = {
                    "packets": [],
                    "window_sec": min_interval,
                    "last_analysis": 0
                }
                windows["C2_max_interval"] = {
                    "packets": [],
                    "window_sec": max_interval,
                    "last_analysis": 0
                }

        return windows

    def _init_log_file(self):
        """Инициализирует лог-файл заголовком сессии."""
        try:
            header = (
                f"=== NFDetect Session Start ===\n"
                f"Время: {datetime.datetime.now()}\n"
                f"Отладка: {'Включена' if self.debug_mode else 'Выключена'}\n"
                f"{'='*30}\n\n"
            )

            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(header)
        except Exception as e:
            print(f"Ошибка инициализации лог-файла: {e}")

    def process_packet(self, packet: Packet):
        """
        Обрабатывает один сетевой пакет.

        Обновляет статистику и проверяет наличие аномалий во всех активных
        временных окнах. Пакет добавляется во все окна, после чего для каждого
        окна выполняется анализ при необходимости.

        Args:
            packet (Packet): Сетевой пакет для обработки.

        Note:
            В случае ошибок при обработке пакета, информация выводится только
            в режиме отладки.
        """
        try:
            packet_time = float(packet.sniff_timestamp)
            self._update_statistics(packet, packet_time)

            for window_type, window in self.windows.items():
                if not window:
                    continue

                window_sec = window["window_sec"]
                window_start = packet_time - window_sec
                window["packets"] = [
                    p for p in window["packets"]
                    if float(p.sniff_timestamp) >= window_start
                ]
                window["packets"].append(packet)
                self._analyze_window_if_needed(window_type, window, packet_time)
        except Exception as e:
            if self.debug_mode:
                print(f"Ошибка обработки пакета: {e}")

    def _update_statistics(self, packet: Packet, packet_time: float):
        """Обновляет статистику на основе нового пакета."""
        if self.statistics["start_time"] is None:
            self.statistics["start_time"] = packet_time

        self.statistics["end_time"] = packet_time
        self.statistics["total"] += 1

        try:
            self.statistics["total_bytes"] += int(packet.length)
        except (AttributeError, ValueError):
            pass

        self._update_protocol_stats(packet)
        src_ip = self._get_src_ip(packet)
        dst_ip = self._get_dst_ip(packet)

        if src_ip:
            self.statistics["src_ips"][src_ip] = self.statistics["src_ips"].get(src_ip, 0) + 1
        if dst_ip:
            self.statistics["dst_ips"][dst_ip] = self.statistics["dst_ips"].get(dst_ip, 0) + 1

        self._update_dns_stats(packet)
        self._update_suspicious_ip_stats(packet, src_ip, dst_ip)

    def _analyze_window_if_needed(self, window_type: str, window: Dict, current_time: float):
        """
        Анализирует окно если прошло достаточно времени.
        """
        try:
            window_sec = window["window_sec"]
            if window_sec < 5.0:
                self._analyze_window(window_type, window["packets"])
                window["last_analysis"] = current_time
                return

            time_since_last_analysis = current_time - window["last_analysis"]
            if time_since_last_analysis >= 1.0:
                self._analyze_window(window_type, window["packets"])
                window["last_analysis"] = current_time
        except Exception as e:
            if self.debug_mode:
                print(f"Ошибка анализа окна {window_type}: {e}")

    def _analyze_window(self, window_type: str, packets: List[Packet]):
        """
        Анализирует временное окно для конкретного правила.
        """
        if not packets:
            return

        try:
            if "brute_force" in window_type:
                alarm = self.analyzer.analyze_bruteforce(packets)
            elif "ddos_1ip" in window_type:
                alarm = self.analyzer.analyze_ddos_single_ip(packets)
            elif "ddos_nip" in window_type:
                alarm = self.analyzer.analyze_ddos_multi_ip(packets)
            elif "flood_HTTP" in window_type:
                alarm = self.analyzer.analyze_http_flood(packets)
            elif "flood_SYN" in window_type:
                alarm = self.analyzer.analyze_syn_flood(packets)
            elif "C2" in window_type:
                alarm = self.analyzer.analyze_c2_beaconing(packets)
            else:
                return

            if not alarm:
                return

            self.alarms.append(alarm[0])

            Alarm(alarm[0][0], alarm[0][1], alarm[0][2], alarm[0][3]).log(
                self.log_path,
                self.rules["reaction"]["out"]
            )

            if self.debug_mode:
                print(f"Alert: {alarm[0][1]} в окне {window_type}")
        except Exception as e:
            if self.debug_mode:
                print(f"Error in analyze {window_type}: {e}")

    def analyze_file(self, pcap_path: str) -> Dict[str, Any]:
        """
        Анализирует PCAP-файл полностью в синхронном режиме.

        Args:
            pcap_path (str): Путь к файлу PCAP для анализа.

        Returns:
            Dict[str, Any]: Результаты анализа, включая статистику и окна.

        Raises:
            FileNotFoundError: Если указанный PCAP-файл не существует.
            RuntimeError: При ошибках во время анализа файла.
        """
        print(f"Начало анализа файла: {pcap_path}")

        try:
            capture = pyshark.FileCapture(pcap_path)
            for packet in capture:
                self.process_packet(packet)
            capture.close()
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP файл не найден: {pcap_path}")
        except Exception as e:
            raise RuntimeError(f"Ошибка анализа файла: {e}")

        self._analyze_all_windows()
        self._generate_reports(pcap_path)

        print("Анализ файла завершен")
        return self._get_results()

    def _analyze_all_windows(self):
        """Принудительно анализирует все окна перед завершением."""
        for window_type, window in self.windows.items():
            if window["packets"]:
                self._analyze_window(window_type, window["packets"])

    def start_live_capture(self, interface: str, duration: int = 0):
        """
        Запускает live-захват сетевого трафика в отдельном потоке.

        Args:
            interface (str): Имя сетевого интерфейса для захвата.
            duration (int, optional): Длительность захвата в секундах.
                Если 0 - захват продолжается до ручной остановки. По умолчанию 0.

        Note:
            Для остановки захвата используйте метод stop_live_capture() или нажмите Ctrl+C.
        """
        print(f"Запуск live-мониторинга на интерфейсе: {interface}")
        if self.debug_mode:
            print("Режим отладки включен")

        self.stop_flag = False
        self.capture_thread = threading.Thread(
            target=self._live_capture_worker,
            args=(interface, duration),
            daemon=True
        )
        self.capture_thread.start()

        print("Live-захват запущен (нажмите Ctrl+C для остановки)")

    def _live_capture_worker(self, interface: str, duration: int):
        """Рабочая функция для live-захвата в отдельном потоке."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        start_time = time.time()

        try:
            capture = pyshark.LiveCapture(
                interface=interface,
                eventloop=loop
            )

            for packet in capture.sniff_continuously():
                if self.stop_flag:
                    break

                if duration > 0 and (time.time() - start_time) >= duration:
                    print(f"Достигнуто время захвата: {duration} сек")
                    break

                self.process_packet(packet)

                if self.debug_mode and self.statistics["total"] % 100 == 0:
                    src = self._get_src_ip(packet) or "N/A"
                    dst = self._get_dst_ip(packet) or "N/A"
                    print(f"Пакет #{self.statistics['total']}: {src} -> {dst}")

        except Exception as e:
            print(f"Ошибка захвата трафика: {e}")
        finally:
            loop.close()
            if 'capture' in locals():
                try:
                    capture.close()
                except Exception as e:
                    if self.debug_mode:
                        print(f"Ошибка закрытия захвата: {e}")
            print("Live-захват остановлен")

    def stop_live_capture(self):
        """
        Останавливает live-захват и генерирует финальные отчеты.

        Note:
            Метод завершает поток захвата, выполняет финальный анализ
            всех временных окон и генерирует итоговые отчеты.
        """
        print("Остановка live-захвата...")
        self.stop_flag = True

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)

        self._analyze_all_windows()
        self._generate_reports("live_capture")

        print("Live-мониторинг завершен")

    def _generate_reports(self, source: str):
        """Генерирует отчеты по результатам анализа."""
        try:
            susp_ips_source = self.suspicious_ips_sources[0] if self.suspicious_ips_sources else "отключены"
            generate_full_json_summary(
                self.statistics,
                self.analyzer.stats,
                self.alarms,
                source,
                self.output_dir,
                os.path.basename(self.log_path),
                self.protected_ips_path,
                susp_ips_source,
                self.rules_path,
                len(self.protected_ips),
                len(self.suspicious_ips),
                self.rules
            )
            generate_summary(
                self.statistics,
                self.analyzer.get_statistics(),
                source,
                self.output_dir,
                os.path.basename(self.log_path),
                self.protected_ips_path,
                susp_ips_source,
                self.rules_path,
                len(self.protected_ips),
                len(self.suspicious_ips)
            )
        except Exception as e:
            print(f"Ошибка генерации отчетов: {e}")

    def _get_results(self) -> Dict[str, Any]:
        """
        Возвращает результаты анализа.

        Returns:
            Dict[str, Any]: Словарь с результатами анализа, содержащий:
                - windows: текущие состояния временных окон
                - statistics: собранная статистика
        """
        return {
            "windows": {k: v["packets"] for k, v in self.windows.items()},
            "statistics": self.statistics,
        }

    def _update_protocol_stats(self, packet: Packet):
        try:
            if hasattr(packet, 'highest_layer'):
                proto = packet.highest_layer
                self.statistics["protos"][proto] = self.statistics["protos"].get(proto, 0) + 1

            if hasattr(packet, 'transport_layer'):
                transport = packet.transport_layer
                self.statistics["protos"][transport] = self.statistics["protos"].get(transport, 0) + 1
        except (AttributeError, ValueError):
            pass

    def _get_src_ip(self, packet: Packet) -> str:
        try:
            if hasattr(packet, 'ip'):
                return packet.ip.src
            elif hasattr(packet, 'ipv6'):
                return packet.ipv6.src
        except (AttributeError, ValueError):
            pass
        return ""

    def _get_dst_ip(self, packet: Packet) -> str:
        try:
            if hasattr(packet, 'ip'):
                return packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                return packet.ipv6.dst
        except (AttributeError, ValueError):
            pass
        return ""

    def _update_dns_stats(self, packet: Packet):
        try:
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                query = str(packet.dns.qry_name)
                if query:
                    self.statistics["dns"][query] = self.statistics["dns"].get(query, 0) + 1
        except (AttributeError, ValueError):
            pass

    def _update_suspicious_ip_stats(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str
    ):
        is_suspicious = False

        if src_ip and src_ip in self.suspicious_ips:
            is_suspicious = True
            self.statistics["suspicious_ips"]["src_count"] += 1
            self.statistics["suspicious_ips"]["src_ips"][src_ip] = \
                self.statistics["suspicious_ips"]["src_ips"].get(src_ip, 0) + 1

        if dst_ip and dst_ip in self.suspicious_ips:
            is_suspicious = True
            self.statistics["suspicious_ips"]["dst_count"] += 1
            self.statistics["suspicious_ips"]["dst_ips"][dst_ip] = \
                self.statistics["suspicious_ips"]["dst_ips"].get(dst_ip, 0) + 1

        if is_suspicious:
            self.statistics["suspicious_ips"]["total_packets"] += 1


def filescan(
    path_to_file: str,
    path_to_output_dir: str,
    output_filename: str,
    path_to_prot_ips: str,
    path_to_rules: str
) -> Dict[str, Any]:
    """
    Анализирует PCAP-файл на наличие сетевых аномалий.

    Args:
        path_to_file (str): Путь к файлу PCAP для анализа.
        path_to_output_dir (str): Директория для сохранения отчетов.
        output_filename (str): Имя файла лога.
        path_to_prot_ips (str): Путь к файлу с защищенными IP-адресами.
        path_to_rules (str): Путь к файлу с правилами обнаружения.

    Returns:
        Dict[str, Any]: Результаты анализа или пустой словарь в случае ошибки.

    Note:
        Функция создает экземпляр NetworkTrafficMonitor, анализирует файл
        и возвращает результаты анализа.
    """
    try:
        monitor = NetworkTrafficMonitor(
            rules_path=path_to_rules,
            protected_ips_path=path_to_prot_ips,
            output_dir=path_to_output_dir,
            log_filename=output_filename
        )
        return monitor.analyze_file(path_to_file)
    except Exception as e:
        print(f"Ошибка при анализе файла: {e}")
        return {}


def livescan(
    interface: str,
    output_dir: str,
    log_file: str,
    protected_ips: str,
    rules_file: str,
    debug_mode: bool = False,
    duration: int = 0
) -> None:
    """
    Запускает live-мониторинг сетевого трафика.

    Args:
        interface (str): Имя сетевого интерфейса для захвата трафика.
        output_dir (str): Директория для сохранения отчетов.
        log_file (str): Имя файла лога.
        protected_ips (str): Путь к файлу с защищенными IP-адресами.
        rules_file (str): Путь к файлу с правилами обнаружения.
        debug_mode (bool, optional): Включить режим отладки. По умолчанию False.
        duration (int, optional): Длительность захвата в секундах. 0 - бесконечно.

    Note:
        Функция запускает мониторинг и работает до ручной остановки (Ctrl+C)
        или до истечения указанной длительности.
    """
    try:
        monitor = NetworkTrafficMonitor(
            rules_path=rules_file,
            protected_ips_path=protected_ips,
            output_dir=output_dir,
            log_filename=log_file,
            debug_mode=debug_mode
        )

        monitor.start_live_capture(interface, duration)

        while monitor.capture_thread and monitor.capture_thread.is_alive():
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("Остановка по запросу пользователя")
        time.sleep(3)
    except Exception as e:
        print(f"Ошибка при запуске live-мониторинга: {e}")
    finally:
        if 'monitor' in locals():
            monitor.stop_live_capture()