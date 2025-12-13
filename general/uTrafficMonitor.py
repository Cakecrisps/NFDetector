#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль для мониторинга трафика с созданием плавающих окон и сбором статистики.
"""

import json
import pyshark
from typing import List, Dict, Any, Set, Optional
import datetime
import os
import threading
import time
from collections import defaultdict
import re
import asyncio
from general.trafficanalyzer import TrafficAnalyzer
from general.AlarmClass import Alarm
from general.summarygen import generate_summary, generate_full_json_summary
from general.authdetect import is_auth_attempt

from pyshark.packet.packet import Packet


class TrafficWindow:
    """Класс для управления плавающим окном трафика."""

    def __init__(self, window_sec: float):
        """
        Инициализирует окно трафика.

        Args:
            window_sec: Размер окна в секундах
        """
        self.window_sec = window_sec
        self.packets = []
        self.last_analysis = 0

    def add_packet(self, packet: Packet, timestamp: float) -> None:
        """
        Добавляет пакет в окно.

        Args:
            packet: Пакет для добавления
            timestamp: Временная метка пакета
        """
        self.packets.append((packet, timestamp))

    def cleanup_old(self, current_time: float) -> None:
        """
        Удаляет устаревшие пакеты из окна.

        Args:
            current_time: Текущее время для определения устаревших пакетов
        """
        cutoff_time = current_time - self.window_sec
        self.packets = [(pkt, ts) for pkt, ts in self.packets if ts >= cutoff_time]

    def size(self) -> int:
        """Возвращает количество пакетов в окне."""
        return len(self.packets)

    def get_packets(self) -> List[Packet]:
        """Возвращает список пакетов в окне."""
        return [pkt for pkt, _ in self.packets]

    def clear(self) -> None:
        """Очищает окно от всех пакетов."""
        self.packets.clear()


class NetworkTrafficMonitor:
    """Основной класс для мониторинга сетевого трафика."""

    def __init__(
        self,
        rules_path: str,
        protected_ips_path: str,
        output_dir: str,
        log_filename: str,
        debug_mode: bool = False
    ):
        """
        Инициализирует монитор трафика.

        Args:
            rules_path: Путь к файлу правил
            protected_ips_path: Путь к файлу защищенных IP
            output_dir: Директория для вывода
            log_filename: Имя файла лога
            debug_mode: Режим отладки

        Raises:
            FileNotFoundError: Если файлы конфигурации не найдены
            RuntimeError: При ошибках инициализации
        """
        self.rules_path = rules_path
        self.protected_ips_path = protected_ips_path
        self.output_dir = output_dir
        self.log_path = os.path.join(output_dir, log_filename)
        self.debug_mode = debug_mode
        self.alarms = []
        self.http_requests = []
        self.downloaded_files = []
        self.auth_attempts_raw = []

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

    def _load_configuration(self) -> None:
        """Загружает конфигурацию из файлов правил и защищенных IP."""
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
                except FileNotFoundError:
                    pass
                except Exception:
                    pass

        try:
            self.protected_ips = set()
            with open(self.protected_ips_path, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.protected_ips.add(ip)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Файл с защищенными IP не найден: {self.protected_ips_path}"
            )
        except Exception as e:
            raise RuntimeError(f"Ошибка загрузки защищенных IP: {e}")

    def _init_statistics(self) -> Dict[str, Any]:
        """Инициализирует структуру статистики."""
        return {
            "total": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "protos": defaultdict(int),
            "src_ips": defaultdict(int),
            "dst_ips": defaultdict(int),
            "dns": defaultdict(int),
            "http_endp": [],
            "downloaded_files": [],
            "suspicious_ips": {
                "total_packets": 0,
                "src_count": 0,
                "dst_count": 0,
                "src_ips": defaultdict(int),
                "dst_ips": defaultdict(int)
            },
            "auth_attempts": {
                "total": 0,
                "by_protocol": defaultdict(int),
                "by_src_ip": defaultdict(int),
                "by_dst_ip": defaultdict(int),
                "successful": 0,
                "failed": 0,
                "details": []
            }
        }

    def _init_windows(self) -> Dict[str, TrafficWindow]:
        """Инициализирует окна мониторинга на основе правил."""
        windows = {}

        if self.rules.get("brute_force", {}).get("enabled", False):
            window_sec = self.rules["brute_force"].get("tryes_limit_window", 20.0)
            windows["brute_force_tryes_limit"] = TrafficWindow(window_sec)

        if self.rules.get("ddos", {}).get("enabled", False):
            ddos_rules = self.rules["ddos"]

            if "1ip" in ddos_rules:
                window_sec = ddos_rules["1ip"].get("request_limit_window", 1.0)
                windows["ddos_1ip"] = TrafficWindow(window_sec)

            if "nip" in ddos_rules:
                window_sec = ddos_rules["nip"].get("request_limit_window", 1.0)
                windows["ddos_nip"] = TrafficWindow(window_sec)

        if self.rules.get("flood", {}).get("enabled", False):
            flood_rules = self.rules["flood"]

            if "SYN" in flood_rules:
                window_sec = flood_rules["SYN"].get("syn_only_window", 5.0)
                windows["flood_SYN"] = TrafficWindow(window_sec)

            if "HTTP" in flood_rules:
                window_sec = flood_rules["HTTP"].get("request_rate_window", 1.0)
                windows["flood_HTTP"] = TrafficWindow(window_sec)

        if self.rules.get("C2_analysys", {}).get("enabled", False):
            c2_rules = self.rules["C2_analysys"]
            if c2_rules.get("beaconing_detection", {}).get("enabled", False):
                min_interval = c2_rules["beaconing_detection"].get("interval_min_sec", 10)
                max_interval = c2_rules["beaconing_detection"].get("interval_max_sec", 300)

                windows["C2_min_interval"] = TrafficWindow(min_interval)
                windows["C2_max_interval"] = TrafficWindow(max_interval)

        return windows

    def _init_log_file(self) -> None:
        """Инициализирует файл лога."""
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

    def _get_src_ip(self, packet: Packet) -> str:
        """Извлекает исходный IP из пакета."""
        try:
            if hasattr(packet, 'ip'):
                return packet.ip.src
            elif hasattr(packet, 'ipv6'):
                return packet.ipv6.src
        except:
            pass
        return ""

    def _get_dst_ip(self, packet: Packet) -> str:
        """Извлекает целевой IP из пакета."""
        try:
            if hasattr(packet, 'ip'):
                return packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                return packet.ipv6.dst
        except:
            pass
        return ""

    def _extract_http_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Извлекает HTTP информацию из пакета."""
        try:
            if hasattr(packet, 'http'):
                http_layer = packet.http

                http_info = {
                    'src_ip': self._get_src_ip(packet),
                    'dst_ip': self._get_dst_ip(packet),
                    'timestamp': float(packet.sniff_timestamp),
                    'method': getattr(http_layer, 'request_method', 'UNKNOWN'),
                    'uri': getattr(http_layer, 'request_uri', '/'),
                    'version': getattr(http_layer, 'request_version', 'HTTP/1.1'),
                    'host': getattr(http_layer, 'host', ''),
                    'user_agent': getattr(http_layer, 'user_agent', ''),
                    'referer': getattr(http_layer, 'referer', ''),
                    'content_type': getattr(http_layer, 'content_type', ''),
                    'content_length': getattr(http_layer, 'content_length', '0'),
                    'status_code': getattr(http_layer, 'response_code', ''),
                    'response_phrase': getattr(http_layer, 'response_phrase', ''),
                    'full_url': '',
                    'packet_length': int(packet.length) if hasattr(packet, 'length') else 0
                }

                if http_info['host'] and http_info['uri']:
                    scheme = 'https' if hasattr(packet, 'tls') else 'http'
                    http_info['full_url'] = f"{scheme}://{http_info['host']}{http_info['uri']}"

                try:
                    dt = datetime.datetime.fromtimestamp(http_info['timestamp'])
                    http_info['time_str'] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                except:
                    http_info['time_str'] = str(http_info['timestamp'])

                if hasattr(http_layer, 'content_disposition'):
                    content_disp = str(http_layer.content_disposition)
                    http_info['content_disposition'] = content_disp

                    filename = self._extract_filename_from_content_disposition(content_disp)
                    if filename:
                        http_info['filename'] = filename

                return http_info
        except Exception as e:
            if self.debug_mode:
                print(f"Ошибка извлечения HTTP информации: {e}")
        return None

    def _extract_filename_from_content_disposition(self, content_disposition: str) -> Optional[str]:
        """Извлекает имя файла из заголовка Content-Disposition."""
        try:
            patterns = [
                r'filename="([^"]+)"',
                r"filename='([^']+)'",
                r'filename=([^\s;]+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, content_disposition, re.IGNORECASE)
                if match:
                    filename = match.group(1)
                    filename = filename.replace('\\"', '"').replace("\\'", "'")
                    return filename

            if 'attachment' in content_disposition.lower():
                utf8_pattern = r"filename\*=UTF-8''([^\s;]+)"
                match = re.search(utf8_pattern, content_disposition, re.IGNORECASE)
                if match:
                    import urllib.parse
                    filename_encoded = match.group(1)
                    try:
                        filename = urllib.parse.unquote(filename_encoded)
                        return filename
                    except:
                        return filename_encoded

        except:
            pass
        return None

    def _extract_filename_from_uri(self, uri: str) -> Optional[str]:
        """Извлекает имя файла из URI."""
        try:
            path = uri.split('?')[0] if '?' in uri else uri

            filename = path.split('/')[-1]

            if filename and '.' in filename and not filename.endswith('/'):
                file_extensions = [
                    '.exe', '.dll', '.zip', '.rar', '.7z', '.tar', '.gz',
                    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                    '.mp3', '.mp4', '.avi', '.mkv', '.mov',
                    '.txt', '.log', '.csv', '.json', '.xml',
                    '.iso', '.img', '.bin',
                    '.msi', '.bat', '.sh', '.ps1', '.py', '.js', '.html', '.php'
                ]

                if any(filename.lower().endswith(ext) for ext in file_extensions):
                    return filename

                if '.' in filename and len(filename.split('.')[-1]) > 0:
                    return filename

        except:
            pass
        return None

    def _is_file_download(self, http_info: Dict[str, Any]) -> bool:
        """Проверяет, является ли HTTP запрос загрузкой файла."""
        if http_info.get('filename'):
            return True

        if http_info.get('status_code') == '200':
            content_type = http_info.get('content_type', '').lower()
            file_content_types = [
                'application/', 'image/', 'video/', 'audio/',
                'text/plain', 'text/html', 'text/xml', 'application/json',
                'application/zip', 'application/x-rar-compressed',
                'application/x-7z-compressed',
                'application/x-tar', 'application/gzip',
                'application/pdf', 'application/msword',
                'application/vnd.openxmlformats',
                'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
                'application/x-msdownload',
                'application/x-msi',
            ]

            if any(ct in content_type for ct in file_content_types):
                uri = http_info.get('uri', '')
                if self._extract_filename_from_uri(uri):
                    return True

        if http_info.get('method') == 'GET':
            uri = http_info.get('uri', '')
            if self._extract_filename_from_uri(uri):
                return True

        if http_info.get('method') in ['POST', 'PUT']:
            try:
                content_length = int(http_info.get('content_length', 0))
                if content_length > 10240:
                    return True
            except:
                pass

        return False

    def _analyze_auth_attempt(self, packet: Packet, packet_time: float) -> None:
        """Анализирует пакет на предмет попыток аутентификации."""
        try:
            is_auth, protocol = is_auth_attempt(packet)
            if is_auth:
                src_ip = self._get_src_ip(packet)
                dst_ip = self._get_dst_ip(packet)

                auth_record_raw = {
                    "timestamp": packet_time,
                    "time_str": datetime.datetime.fromtimestamp(packet_time).strftime(
                        "%Y-%m-%d %H:%M:%S.%f"
                    )[:-3],
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "status": "unknown",
                    "details": {},
                    "raw_packet": str(packet)
                }

                self.auth_attempts_raw.append(auth_record_raw)

                if len(self.auth_attempts_raw) > 5000:
                    self.auth_attempts_raw = self.auth_attempts_raw[-2500:]

                self.statistics["auth_attempts"]["total"] += 1
                self.statistics["auth_attempts"]["by_protocol"][protocol] += 1

                if src_ip:
                    self.statistics["auth_attempts"]["by_src_ip"][src_ip] += 1
                if dst_ip:
                    self.statistics["auth_attempts"]["by_dst_ip"][dst_ip] += 1

                auth_record = {
                    "timestamp": packet_time,
                    "time_str": datetime.datetime.fromtimestamp(packet_time).strftime(
                        "%Y-%m-%d %H:%M:%S.%f"
                    )[:-3],
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "status": "unknown",
                    "details": {}
                }

                if protocol == "FTP" and hasattr(packet, 'ftp'):
                    if hasattr(packet.ftp, 'request_command'):
                        auth_record["details"]["command"] = packet.ftp.request_command
                    if hasattr(packet.ftp, 'request_arg'):
                        auth_record["details"]["argument"] = packet.ftp.request_arg

                elif protocol == "SSH" and hasattr(packet, 'ssh'):
                    if hasattr(packet.ssh, 'message_type'):
                        auth_record["details"]["message_type"] = packet.ssh.message_type

                elif protocol in ["SMB", "SMB2"]:
                    try:
                        if hasattr(packet, 'smb') and hasattr(packet.smb, 'nt_status'):
                            status = packet.smb.nt_status
                            if status == '0x00000000':
                                auth_record["status"] = "successful"
                                self.statistics["auth_attempts"]["successful"] += 1
                            else:
                                auth_record["status"] = "failed"
                                self.statistics["auth_attempts"]["failed"] += 1
                        elif hasattr(packet, 'smb2') and hasattr(packet.smb2, 'nt_status'):
                            status = packet.smb2.nt_status
                            if status == '0x00000000':
                                auth_record["status"] = "successful"
                                self.statistics["auth_attempts"]["successful"] += 1
                            else:
                                auth_record["status"] = "failed"
                                self.statistics["auth_attempts"]["failed"] += 1
                    except:
                        pass

                self.statistics["auth_attempts"]["details"].append(auth_record)
                if len(self.statistics["auth_attempts"]["details"]) > 1000:
                    self.statistics["auth_attempts"]["details"] = (
                        self.statistics["auth_attempts"]["details"][-500:]
                    )

        except Exception as e:
            if self.debug_mode:
                print(f"Ошибка анализа аутентификации: {e}")

    def process_packet(self, packet: Packet) -> None:
        """Обрабатывает один пакет."""
        try:
            packet_time = float(packet.sniff_timestamp)
            self._update_statistics(packet, packet_time)

            self._analyze_auth_attempt(packet, packet_time)

            for window_type, window in self.windows.items():
                window.add_packet(packet, packet_time)
                window.cleanup_old(packet_time)

                current_time = time.time()
                time_since_last_analysis = current_time - window.last_analysis

                if window.window_sec < 5.0:
                    analysis_interval = 0.5
                else:
                    analysis_interval = 1.0

                if time_since_last_analysis >= analysis_interval and window.size() > 0:
                    self._analyze_window(window_type, window.get_packets())
                    window.last_analysis = current_time

        except Exception as e:
            if self.debug_mode:
                print(f"Ошибка обработки пакета: {e}")

    def _update_statistics(self, packet: Packet, packet_time: float) -> None:
        """Обновляет статистику на основе пакета."""
        if self.statistics["start_time"] is None:
            self.statistics["start_time"] = packet_time

        self.statistics["end_time"] = packet_time
        self.statistics["total"] += 1

        try:
            self.statistics["total_bytes"] += int(packet.length)
        except:
            pass

        self._update_protocol_stats(packet)
        src_ip = self._get_src_ip(packet)
        dst_ip = self._get_dst_ip(packet)

        if src_ip:
            self.statistics["src_ips"][src_ip] += 1
        if dst_ip:
            self.statistics["dst_ips"][dst_ip] += 1

        self._update_dns_stats(packet)
        self._update_http_stats(packet, packet_time, src_ip, dst_ip)
        self._update_file_stats(packet, packet_time, src_ip, dst_ip)
        self._update_suspicious_ip_stats(packet, src_ip, dst_ip)

    def _update_http_stats(
        self,
        packet: Packet,
        packet_time: float,
        src_ip: str,
        dst_ip: str
    ) -> None:
        """Обновляет статистику HTTP запросов."""
        http_info = self._extract_http_info(packet)
        if http_info:
            self.statistics["protos"]["HTTP"] += 1

            http_record = {
                "src_ip": src_ip or http_info['src_ip'],
                "dst_ip": dst_ip or http_info['dst_ip'],
                "time": http_info['time_str'],
                "timestamp": packet_time,
                "method": http_info['method'],
                "uri": http_info['uri'],
                "host": http_info['host'],
                "full_url": http_info['full_url'],
                "user_agent": http_info['user_agent'],
                "referer": http_info['referer'],
                "content_type": http_info['content_type'],
                "content_length": (
                    int(http_info['content_length'])
                    if http_info['content_length'].isdigit()
                    else 0
                ),
                "status_code": http_info['status_code'],
                "response_phrase": http_info['response_phrase'],
                "packet_length": http_info['packet_length']
            }

            if 'filename' in http_info:
                http_record['filename'] = http_info['filename']
            if 'content_disposition' in http_info:
                http_record['content_disposition'] = http_info['content_disposition']

            self.http_requests.append(http_record)
            if len(self.http_requests) > 1000:
                self.http_requests = self.http_requests[-500:]

            self.statistics["http_endp"].append(http_record)

    def _update_file_stats(
        self,
        packet: Packet,
        packet_time: float,
        src_ip: str,
        dst_ip: str
    ) -> None:
        """Обновляет статистику загруженных файлов."""
        try:
            if hasattr(packet, 'http'):
                http_info = self._extract_http_info(packet)
                if http_info and self._is_file_download(http_info):

                    filename = None

                    if 'filename' in http_info:
                        filename = http_info['filename']

                    if not filename and http_info.get('uri'):
                        filename = self._extract_filename_from_uri(http_info['uri'])

                    if filename:
                        file_type = self._get_file_type(filename)

                        file_record = {
                            "src_ip": src_ip or http_info['src_ip'],
                            "dst_ip": dst_ip or http_info['dst_ip'],
                            "time": http_info['time_str'],
                            "timestamp": packet_time,
                            "filename": filename,
                            "file_type": file_type,
                            "url": (
                                http_info['full_url']
                                if http_info['full_url']
                                else http_info['uri']
                            ),
                            "method": http_info['method'],
                            "content_type": http_info['content_type'],
                            "content_length": (
                                int(http_info['content_length'])
                                if http_info['content_length'].isdigit()
                                else 0
                            ),
                            "status_code": http_info['status_code'],
                            "user_agent": http_info.get('user_agent', ''),
                            "direction": self._get_file_direction(http_info, src_ip, dst_ip)
                        }

                        self.downloaded_files.append(file_record)

                        if len(self.downloaded_files) > 500:
                            self.downloaded_files = self.downloaded_files[-250:]

                        self.statistics["downloaded_files"].append(file_record)
        except:
            pass

    def _get_file_type(self, filename: str) -> str:
        """Определяет тип файла по его имени."""
        filename_lower = filename.lower()

        executables = [
            '.exe', '.dll', '.so', '.bat', '.cmd', '.ps1', '.sh', '.bin', '.msi'
        ]
        if any(filename_lower.endswith(ext) for ext in executables):
            return "executable"

        archives = [
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img'
        ]
        if any(filename_lower.endswith(ext) for ext in archives):
            return "archive"

        documents = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'
        ]
        if any(filename_lower.endswith(ext) for ext in documents):
            return "document"

        images = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp'
        ]
        if any(filename_lower.endswith(ext) for ext in images):
            return "image"

        videos = ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm']
        if any(filename_lower.endswith(ext) for ext in videos):
            return "video"

        audios = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma']
        if any(filename_lower.endswith(ext) for ext in audios):
            return "audio"

        scripts = [
            '.py', '.js', '.php', '.html', '.htm', '.css', '.java', '.cpp', '.c', '.cs'
        ]
        if any(filename_lower.endswith(ext) for ext in scripts):
            return "script"

        data_files = [
            '.log', '.csv', '.json', '.xml', '.yml', '.yaml', '.ini', '.cfg', '.conf'
        ]
        if any(filename_lower.endswith(ext) for ext in data_files):
            return "data"

        return "other"

    def _get_file_direction(
        self,
        http_info: Dict[str, Any],
        src_ip: str,
        dst_ip: str
    ) -> str:
        """Определяет направление передачи файла."""
        method = http_info.get('method', '').upper()
        status_code = http_info.get('status_code', '')

        if status_code == '200':
            return 'download'

        if method in ['POST', 'PUT']:
            return 'upload'

        return 'download'

    def _analyze_window(self, window_type: str, packets: List[Packet]) -> None:
        """Анализирует содержимое окна."""
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

            Alarm(
                alarm[0][0],
                alarm[0][1],
                alarm[0][2],
                alarm[0][3]
            ).log(
                self.log_path,
                self.rules["reaction"]["out"]
            )

            if self.debug_mode:
                print(f"Alert: {alarm[0][1]} в окне {window_type}")
        except Exception as e:
            if self.debug_mode:
                print(f"Error in analyze {window_type}: {e}")

    def _get_packet_count(self, pcap_path: str) -> int:
        try:
            cap = pyshark.FileCapture(pcap_path, keep_packets=False)
            count = 0
            try:
                for _ in cap:
                    count += 1
            except:
                # Если файл поврежден, просто возвращаем текущий счетчик
                pass
            return count
        except:
            return 0
        finally:
            cap.close()

    def analyze_file(self, pcap_path: str) -> Dict[str, Any]:
        """
        Анализирует трафик из PCAP файла.

        Args:
            pcap_path: Путь к PCAP файлу

        Returns:
            Словарь с результатами анализа

        Raises:
            FileNotFoundError: Если файл не найден
            RuntimeError: При ошибках анализа
        """
        print(f"Начало анализа файла: {pcap_path}")

        total_packets = self._get_packet_count(pcap_path)
        print(f"Приблизительное количество пакетов: {total_packets:,}")

        http_count = 0
        file_count = 0
        auth_count = 0

        try:
            capture = pyshark.FileCapture(pcap_path,debug=self.debug_mode)
            packets_processed = 0
            start_time = time.time()
            last_update_time = start_time

            print("\n[Прогресс анализа]")
            print("┌────────────────────────────────────────────────────────────┐")
            zz = 0
            for packet in capture:
                try:
                    zz += 1
                    if self.stop_flag:
                        break

                    self.process_packet(packet)
                    packets_processed += 1

                    if hasattr(packet, 'http'):
                        http_count += 1

                    file_count = len(self.downloaded_files)
                    auth_count = self.statistics["auth_attempts"]["total"]

                    current_time = time.time()
                    if current_time - last_update_time >= 0.5 or packets_processed % 100 == 0:

                        if total_packets > 0:
                            percent = min(100, int((packets_processed / total_packets) * 100))
                        else:
                            percent = 0

                        elapsed_time = current_time - start_time
                        if packets_processed > 0 and elapsed_time > 0:
                            speed = packets_processed / elapsed_time
                            if total_packets > 0 and percent < 100:
                                remaining_packets = total_packets - packets_processed
                                remaining_time = remaining_packets / speed if speed > 0 else 0

                                if remaining_time < 60:
                                    time_str = f"{remaining_time:.1f} сек"
                                elif remaining_time < 3600:
                                    minutes = remaining_time / 60
                                    time_str = f"{minutes:.1f} мин"
                                else:
                                    hours = remaining_time / 3600
                                    time_str = f"{hours:.1f} час"
                            else:
                                time_str = "завершается..."
                                speed_str = f"{speed:.0f} пак/сек"
                        else:
                            time_str = "расчет..."
                            speed_str = "---"

                        bar_width = 50
                        filled = int(bar_width * percent / 100)
                        bar = "█" * filled + "░" * (bar_width - filled)

                        packets_str = f"{packets_processed:,}"
                        if total_packets > 0:
                            total_str = f"{total_packets:,}"
                            percent_str = f"{percent:3d}%"
                        else:
                            total_str = "???"
                            percent_str = "??%"

                        print(
                            f"\r│[{bar}] {percent_str} │ {packets_str}/{total_str} пакетов │",
                            end=""
                        )
                        print(
                            f" HTTP: {http_count:,} │ Auth: {auth_count} │ Файлы: {file_count} ",
                            end=""
                        )

                        last_update_time = current_time

                    if packets_processed >= total_packets and total_packets > 0:
                        break
                except:
                    print(Exception)

            capture.close()

            print("\n└────────────────────────────────────────────────────────────┘")

            elapsed_time = time.time() - start_time
            print(f"\n✓ Обработано пакетов: {packets_processed:,}")
            print(f"✓ HTTP запросов: {http_count:,}")
            print(f"✓ Попыток аутентификации: {auth_count}")
            print(f"✓ Обнаружено файлов: {file_count:,}")
            print(f"✓ Время анализа: {elapsed_time:.2f} сек")
            if packets_processed > 0:
                print(f"✓ Скорость обработки: {packets_processed/elapsed_time:.1f} пак/сек")

        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP файл не найден: {pcap_path}")
        except Exception as e:
            raise RuntimeError(f"Ошибка анализа файла: {e}")

        self._analyze_all_windows()

        self._generate_reports(pcap_path)

        print("✓ Анализ файла завершен")
        return self._get_results()

    def _analyze_all_windows(self) -> None:
        """Анализирует все окна трафика."""
        for window_type, window in self.windows.items():
            if window.size() > 0:
                self._analyze_window(window_type, window.get_packets())

    def start_live_capture(self, interface: str, duration: int = 0) -> threading.Thread:
        """
        Запускает live-мониторинг трафика.

        Args:
            interface: Сетевой интерфейс
            duration: Продолжительность захвата в секундах (0 - бесконечно)

        Returns:
            Поток захвата трафика
        """
        print(f"Запуск live-мониторинга на интерфейсе: {interface}")
        if self.debug_mode:
            print("Режим отладки включен")

        self.stop_flag = False
        self.capture_thread = threading.Thread(
            target=self._live_capture_worker,
            args=(interface, duration),
            daemon=True,
            name="LiveCaptureThread"
        )
        self.capture_thread.start()

        print("Live-захват запущен (нажмите Ctrl+C для остановки)")
        return self.capture_thread

    def _live_capture_worker(self, interface: str, duration: int) -> None:
        """Рабочая функция для live-захвата трафика."""
        start_time = time.time()
        last_stats_time = time.time()
        http_count = 0
        file_count = 0
        auth_count = 0
        capture = None

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            capture = pyshark.LiveCapture(interface=interface)

            print("\n[Live мониторинг]")
            print("┌────────────────────────────────────────────────────────────┐")

            for packet in capture.sniff_continuously():
                if self.stop_flag:
                    break

                if duration > 0 and (time.time() - start_time) >= duration:
                    print(f"\n✓ Достигнуто время захвата: {duration} сек")
                    break

                self.process_packet(packet)

                if hasattr(packet, 'http'):
                    http_count += 1

                file_count = len(self.downloaded_files)
                auth_count = self.statistics["auth_attempts"]["total"]

                current_time = time.time()
                if current_time - last_stats_time >= 2.0:
                    elapsed = current_time - start_time

                    stats_line = (
                        f"\r│ Пакеты: {self.statistics['total']:,} │ "
                        f"HTTP: {http_count:,} │ Auth: {auth_count} │ "
                        f"Файлы: {file_count:,} │ Тревоги: {len(self.alarms)} "
                    )

                    if elapsed > 0:
                        speed = self.statistics['total'] / elapsed
                        stats_line += f"│ {speed:.0f} пак/сек "

                    if duration > 0:
                        remaining = duration - elapsed
                        if remaining > 0:
                            if remaining < 60:
                                stats_line += f"│ Осталось: {remaining:.0f} сек "
                            else:
                                stats_line += f"│ Осталось: {remaining/60:.1f} мин "

                    print(stats_line + " ", end="")

                    last_stats_time = current_time

                if self.debug_mode and self.statistics["total"] % 100 == 0:
                    src = self._get_src_ip(packet) or "N/A"
                    dst = self._get_dst_ip(packet) or "N/A"
                    print(f"\n│ Пакет #{self.statistics['total']}: {src} → {dst}")

        except Exception as e:
            print(f"\n✗ Ошибка захвата трафика: {e}")
        finally:
            if capture is not None:
                capture.close()
            print("\n└────────────────────────────────────────────────────────────┘")
            print("Live-захват остановлен")

    def stop_live_capture(self) -> None:
        """Останавливает live-мониторинг трафика."""
        print("\nОстановка live-захвата...")
        self.stop_flag = True

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)

        self._analyze_all_windows()
        self._generate_reports("live_capture")

        print("✓ Live-мониторинг завершен")

    def _generate_reports(self, source: str) -> None:
        """Генерирует отчеты по результатам анализа."""
        try:
            susp_ips_source = (
                self.suspicious_ips_sources[0]
                if self.suspicious_ips_sources
                else "отключены"
            )

            if source == "live_capture":
                safe_source = "live_capture"
            else:
                base_name = os.path.basename(source)
                safe_source = os.path.splitext(base_name)[0]
                safe_source = re.sub(r'[<>:"/\\|?*]', '_', safe_source)

            self.statistics["http_summary"] = {
                "total_requests": len(self.http_requests),
                "unique_hosts": len(
                    set(r.get('host', '') for r in self.http_requests if r.get('host'))
                ),
                "sample_requests": self.http_requests[:100] if self.http_requests else []
            }

            self.statistics["files_summary"] = {
                "total_files": len(self.downloaded_files),
                "file_types": self._get_file_type_distribution(),
                "top_files": self._get_top_files(20),
                "sample_files": self.downloaded_files[:50] if self.downloaded_files else []
            }

            self.statistics["auth_summary"] = self.get_auth_summary()

            generate_full_json_summary(
                self.statistics,
                self.analyzer.stats,
                self.alarms,
                safe_source,
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
                safe_source,
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

    def _get_file_type_distribution(self) -> Dict[str, int]:
        """Возвращает распределение типов файлов."""
        distribution = defaultdict(int)
        for file_record in self.downloaded_files:
            file_type = file_record.get('file_type', 'unknown')
            distribution[file_type] += 1
        return dict(distribution)

    def _get_top_files(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Возвращает топ-N наиболее часто встречающихся файлов."""
        file_counts = defaultdict(int)
        for file_record in self.downloaded_files:
            filename = file_record.get('filename', '')
            if filename:
                file_counts[filename] += 1

        sorted_files = sorted(
            file_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]

        result = []
        for filename, count in sorted_files:
            for file_record in self.downloaded_files:
                if file_record.get('filename') == filename:
                    result.append({
                        "filename": filename,
                        "count": count,
                        "file_type": file_record.get('file_type', 'unknown'),
                        "last_seen": file_record.get('time', ''),
                        "last_src": file_record.get('src_ip', ''),
                        "last_dst": file_record.get('dst_ip', '')
                    })
                    break

        return result

    def get_auth_summary(self) -> Dict[str, Any]:
        """
        Возвращает сводку по попыткам аутентификации.

        Returns:
            Словарь со статистикой аутентификации
        """
        auth_stats = self.statistics["auth_attempts"]

        top_src_ips = sorted(
            auth_stats["by_src_ip"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        top_protocols = sorted(
            auth_stats["by_protocol"].items(),
            key=lambda x: x[1],
            reverse=True
        )

        suspicious_ips = []
        for ip, count in auth_stats["by_src_ip"].items():
            if count > 10:
                suspicious_ips.append({
                    "ip": ip,
                    "attempts": count,
                    "protocols": list(set([
                        r["protocol"] for r in auth_stats["details"]
                        if r["src_ip"] == ip
                    ]))[:5]
                })

        total_attempts = auth_stats["total"]
        successful = auth_stats.get("successful", 0)
        success_rate = successful / total_attempts * 100 if total_attempts > 0 else 0

        return {
            "total_attempts": total_attempts,
            "successful_attempts": successful,
            "failed_attempts": auth_stats.get("failed", 0),
            "success_rate": success_rate,
            "top_protocols": top_protocols,
            "top_source_ips": top_src_ips,
            "suspicious_ips": suspicious_ips,
            "protocol_distribution": dict(auth_stats["by_protocol"]),
            "recent_attempts": auth_stats["details"][-20:] if auth_stats["details"] else [],
            "raw_attempts_count": len(self.auth_attempts_raw)
        }

    def _get_results(self) -> Dict[str, Any]:
        """Возвращает результаты анализа."""
        return {
            "windows": {k: v.get_packets() for k, v in self.windows.items()},
            "statistics": self.statistics,
            "http_requests": self.http_requests[:200],
            "downloaded_files": self.downloaded_files[:200],
            "auth_attempts_raw": self.auth_attempts_raw[:500],
        }

    def _update_protocol_stats(self, packet: Packet) -> None:
        """Обновляет статистику протоколов."""
        try:
            if hasattr(packet, 'highest_layer'):
                proto = packet.highest_layer
                self.statistics["protos"][proto] += 1

            if hasattr(packet, 'transport_layer'):
                transport = packet.transport_layer
                self.statistics["protos"][transport] += 1
        except:
            pass

    def _update_dns_stats(self, packet: Packet) -> None:
        """Обновляет DNS статистику."""
        try:
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                query = str(packet.dns.qry_name)
                if query:
                    self.statistics["dns"][query] += 1
        except:
            pass

    def _update_suspicious_ip_stats(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str
    ) -> None:
        """Обновляет статистику по подозрительным IP."""
        is_suspicious = False

        if src_ip and src_ip in self.suspicious_ips:
            is_suspicious = True
            self.statistics["suspicious_ips"]["src_count"] += 1
            self.statistics["suspicious_ips"]["src_ips"][src_ip] += 1

        if dst_ip and dst_ip in self.suspicious_ips:
            is_suspicious = True
            self.statistics["suspicious_ips"]["dst_count"] += 1
            self.statistics["suspicious_ips"]["dst_ips"][dst_ip] += 1

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
    Анализирует трафик из PCAP файла.

    Args:
        path_to_file: Путь к PCAP файлу
        path_to_output_dir: Директория для вывода
        output_filename: Имя файла вывода
        path_to_prot_ips: Путь к файлу защищенных IP
        path_to_rules: Путь к файлу правил

    Returns:
        Результаты анализа
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
    Запускает live-мониторинг трафика.

    Args:
        interface: Сетевой интерфейс
        output_dir: Директория для вывода
        log_file: Имя файла лога
        protected_ips: Путь к файлу защищенных IP
        rules_file: Путь к файлу правил
        debug_mode: Режим отладки
        duration: Продолжительность захвата
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
        print("\n✓ Остановка по запросу пользователя")
        time.sleep(1)
    except Exception as e:
        print(f"Ошибка при запуске live-мониторинга: {e}")
    finally:
        if 'monitor' in locals():
            monitor.stop_live_capture()