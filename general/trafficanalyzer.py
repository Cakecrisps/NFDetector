#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Модуль для анализа трафика и скользящих окон.

"""
import json
from typing import Dict, List, Tuple, Optional, Set
import time
from datetime import datetime


class TrafficAnalyzer:
    """
    Анализатор сетевого трафика для обнаружения угроз безопасности.
    
    Attributes:
        rules (Dict): Загруженные правила обнаружения угроз из JSON файла.
        protectips (List[str]): Список защищаемых IP-адресов.
        stats (Dict): Словарь со статистикой анализа.
        suspicious_ips (Set[str]): Множество подозрительных IP-адресов.
        pending_syns (Dict): Словарь для отслеживания полуоткрытых соединений.
    """
    
    def __init__(self, rules_file: str, protectips: str):
        """
        Инициализация анализатора трафика.
        
        Args:
            rules_file: Путь к файлу с правилами (JSON)
            protectips: Путь к файлу с IP для мониторинга
            
        Raises:
            FileNotFoundError: Если не найден файл правил или файл с IP
            ValueError: Если файл правил имеет неверный формат JSON
        """
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                self.rules = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл правил не найден: {rules_file}")
        except json.JSONDecodeError:
            raise ValueError(f"Неверный формат JSON в файле: {rules_file}")
        
        try:
            with open(protectips, 'r', encoding='utf-8') as f:
                self.protectips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл с защищаемыми IP не найден: {protectips}")
        
        self.stats = {
            "total": 0,
            "alarms": {
                "ddos": 0,
                "flood": 0,
                "bruteforce": 0,
                "susp_ips": 0,
                "c2": 0
            },
            "susp_ips": {},
            "c2_mb": [],
            "connections": {},
            "auth_attempts": {}
        }
        
        self.suspicious_ips = set()
        if self.rules.get("suspicious_ips", {}).get("enabled", False):
            susp_files = self.rules["suspicious_ips"]["files_of_susp_ip_list"]
            for filepath in susp_files:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                self.suspicious_ips.add(ip)
                except FileNotFoundError:
                    print(f"Файл с подозрительными IP не найден: {filepath}")
        
        self.pending_syns = {}
    
    def _increment_counter(self, counter_dict: dict, key: str) -> None:
        """
        Увеличивает счетчик в словаре.
        
        Args:
            counter_dict (dict): Словарь с счетчиками
            key (str): Ключ для инкремента
        """
        if key in counter_dict:
            counter_dict[key] += 1
        else:
            counter_dict[key] = 1
    
    def _get_packet_info(self, packet) -> Dict:
        """
        Извлекает информацию из пакета pyshark.
        
        Args:
            packet: Пакет для анализа
            
        Returns:
            Dict: Словарь с информацией о пакете или пустой словарь в случае ошибки
            
        Note:
            Ожидается, что пакет имеет атрибуты pyshark
        """
        try:
            if not hasattr(packet, 'ip'):
                return {}
            
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            if hasattr(packet, 'sniff_time'):
                timestamp = packet.sniff_time.timestamp()
            else:
                timestamp = time.time()
            
            protocol = "UNKNOWN"
            if hasattr(packet, 'tcp'):
                protocol = "TCP"
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                protocol = "UDP"
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
            else:
                src_port = None
                dst_port = None
            
            tcp_flags = None
            is_syn = False
            is_syn_ack = False
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                tcp_flags = packet.tcp.flags
                is_syn = 'SYN' in tcp_flags and 'ACK' not in tcp_flags
                is_syn_ack = 'SYN' in tcp_flags and 'ACK' in tcp_flags
            
            is_http = hasattr(packet, 'http')
            
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "timestamp": timestamp,
                "protocol": protocol,
                "is_syn": is_syn,
                "is_syn_ack": is_syn_ack,
                "is_http": is_http,
                "packet": packet
            }
        except Exception as e:
            print(f"Ошибка при получении информации о пакете: {e}")
            return {}
    
    def _get_connection_id(self, src_ip: str, dst_ip: str, src_port: str, dst_port: str) -> str:
        """
        Генерирует уникальный идентификатор соединения.
        
        Args:
            src_ip (str): IP-адрес источника
            dst_ip (str): IP-адрес назначения
            src_port (str): Порт источника
            dst_port (str): Порт назначения
            
        Returns:
            str: Уникальный идентификатор соединения в формате "src_ip:src_port-dst_ip:dst_port"
        """
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def analyze_ddos_single_ip(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ DDoS атаки от одного IP-адреса.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Правило должно быть включено в конфигурации. По умолчанию лимит: 1000 пакетов
        """
        alarms = []
        if not self.rules.get("ddos", {}).get("enabled", False):
            return alarms
        
        try:
            ddos_config = self.rules["ddos"]
            rule_1ip = ddos_config.get("1ip", {})
            request_limit = rule_1ip.get("request_limit", 1000)
            
            src_counts = {}
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                
                if dst_ip in self.protectips:
                    self._increment_counter(src_counts, src_ip)
                    self.stats["total"] += 1
            
            for src_ip, count in src_counts.items():
                if count >= request_limit:
                    reason = f"DDoS_SINGLE_IP: {src_ip} sent {count} packets (limit: {request_limit})"
                    alarms.append((reason, f"PROTECTED_NETWORK:{dst_ip}", src_ip, True))
                    self.stats["alarms"]["ddos"] += 1
        except Exception as e:
            print(f"Ошибка при анализе DDoS от одного IP: {e}")
        
        return alarms
    
    def analyze_ddos_multi_ip(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ DDoS атаки от множества IP-адресов.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Правило должно быть включено в конфигурации. По умолчанию лимит: 5000 пакетов
        """
        alarms = []
        if not self.rules.get("ddos", {}).get("enabled", False):
            return alarms
        
        try:
            ddos_config = self.rules["ddos"]
            rule_nip = ddos_config.get("nip", {})
            total_limit = rule_nip.get("request_limit", 5000)
            display_count = rule_nip.get("display_ips", 10)
            
            src_counts = {}
            total_protected_packets = 0
            target_ips = set()
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                
                if dst_ip in self.protectips:
                    self._increment_counter(src_counts, src_ip)
                    total_protected_packets += 1
                    target_ips.add(dst_ip)
                    self.stats["total"] += 1
            
            if total_protected_packets >= total_limit:
                sorted_ips = sorted(
                    src_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:display_count]
                
                top_ips = [f"{ip}({count})" for ip, count in sorted_ips]
                top_ips_str = ", ".join(top_ips)
                
                for ip, count in sorted_ips:
                    target_ip_str = ", ".join(target_ips) if target_ips else "PROTECTED_NETWORK"
                    reason = f"DDoS_MULTI_IP: {ip} sent {count} packets, total: {total_protected_packets} (limit: {total_limit})"
                    alarms.append((reason, target_ip_str, ip, True))
                    self.stats["alarms"]["ddos"] += 1
                
                if sorted_ips:
                    target_ip_str = ", ".join(target_ips) if target_ips else "PROTECTED_NETWORK"
                    reason = f"DDoS_MULTI_IP: Total {total_protected_packets} packets (limit: {total_limit}), top attackers: {top_ips_str}"
        except Exception as e:
            print(f"Ошибка при анализе DDoS от множества IP: {e}")
        
        return alarms
    
    def analyze_syn_flood(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ SYN flood атаки.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Правило должно быть включено в конфигурации. По умолчанию лимит: 50 полуоткрытых соединений
        """
        alarms = []
        if not self.rules.get("flood", {}).get("enabled", False):
            return alarms
        
        try:
            flood_config = self.rules["flood"]
            if "SYN" not in flood_config:
                return alarms
            
            syn_config = flood_config["SYN"]
            syn_limit = syn_config.get("syn_only_limit", 50)
            current_time = time.time()
            timeout = 5.0
            
            expired_syns = []
            for conn_id, syn_time in self.pending_syns.items():
                if current_time - syn_time > timeout:
                    expired_syns.append(conn_id)
            
            for conn_id in expired_syns:
                del self.pending_syns[conn_id]
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                src_port = packet_info.get("src_port")
                dst_port = packet_info.get("dst_port")
                
                if dst_ip not in self.protectips:
                    continue
                
                self.stats["total"] += 1
                is_syn = packet_info.get("is_syn", False)
                is_syn_ack = packet_info.get("is_syn_ack", False)
                
                if is_syn and src_port and dst_port:
                    conn_id = self._get_connection_id(src_ip, dst_ip, src_port, dst_port)
                    self.pending_syns[conn_id] = packet_info["timestamp"]
                elif is_syn_ack and src_port and dst_port:
                    conn_id = self._get_connection_id(dst_ip, src_ip, dst_port, src_port)
                    if conn_id in self.pending_syns:
                        del self.pending_syns[conn_id]
            
            src_half_open_counts = {}
            
            for conn_id, syn_time in self.pending_syns.items():
                parts = conn_id.split('-')
                if len(parts) == 2:
                    src_part = parts[0]
                    src_ip = src_part.split(':')[0]
                    self._increment_counter(src_half_open_counts, src_ip)
            
            for src_ip, count in src_half_open_counts.items():
                if count >= syn_limit:
                    reason = f"SYN_FLOOD_HALF_OPEN: {src_ip} has {count} half-open connections (limit: {syn_limit})"
                    alarms.append((reason, f"PROTECTED_NETWORK:{dst_ip}", src_ip, True))
                    self.stats["alarms"]["flood"] += 1
        except Exception as e:
            print(f"Ошибка при анализе SYN flood: {e}")
        
        return alarms
    
    def analyze_http_flood(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ HTTP flood атаки.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Правило должно быть включено в конфигурации. По умолчанию лимит: 80 HTTP запросов
        """
        alarms = []
        if not self.rules.get("flood", {}).get("enabled", False):
            return alarms
        
        try:
            flood_config = self.rules["flood"]
            if "HTTP" not in flood_config:
                return alarms
            
            http_config = flood_config["HTTP"]
            http_limit = http_config.get("request_rate_limit", 80)
            
            src_counts = {}
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                is_http = packet_info.get("is_http", False)
                
                if dst_ip in self.protectips and is_http:
                    self._increment_counter(src_counts, src_ip)
                    self.stats["total"] += 1
            
            for src_ip, count in src_counts.items():
                if count >= http_limit:
                    reason = f"HTTP_FLOOD: {src_ip} sent {count} HTTP requests (limit: {http_limit})"
                    alarms.append((reason, f"PROTECTED_NETWORK::{dst_ip}", src_ip, True))
                    self.stats["alarms"]["flood"] += 1
        except Exception as e:
            print(f"Ошибка при анализе HTTP flood: {e}")
        
        return alarms
    
    def analyze_bruteforce(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ brute-force атак на аутентификацию.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Требуется модуль general.authdetect. По умолчанию лимит: 10 попыток
        """
        alarms = []
        if not self.rules.get("brute_force", {}).get("enabled", False):
            return alarms
        
        try:
            bf_config = self.rules["brute_force"]
            proto_list = bf_config.get("auth_proto", [])
            tryes_limit = bf_config.get("tryes_limit", 10)
            
            try:
                from general.authdetect import is_auth_attempt
            except ImportError:
                print("Не удалось импортировать is_auth_attempt из general.authdetect")
                return alarms
            
            auth_attempts_by_key = {}
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                
                if dst_ip not in self.protectips:
                    continue
                
                is_auth, protocol = is_auth_attempt(packet)
                
                if is_auth and protocol in proto_list:
                    self.stats["total"] += 1
                    key = f"{src_ip}_{dst_ip}_{protocol}"
                    
                    if key not in auth_attempts_by_key:
                        auth_attempts_by_key[key] = []
                    
                    auth_attempts_by_key[key].append(packet_info["timestamp"])
                    
                    if key not in self.stats["auth_attempts"]:
                        self.stats["auth_attempts"][key] = []
                    
                    self.stats["auth_attempts"][key].append({
                        "timestamp": packet_info["timestamp"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol
                    })
            
            for key, timestamps in auth_attempts_by_key.items():
                src_ip, dst_ip, protocol = key.split("_", 2)
                
                if len(timestamps) >= tryes_limit:
                    reason = f"BRUTEFORCE_{protocol}: {src_ip} -> {dst_ip} ({len(timestamps)} attempts, limit: {tryes_limit})"
                    alarms.append((reason, dst_ip, src_ip, True))
                    self.stats["alarms"]["bruteforce"] += 1
        except Exception as e:
            print(f"Ошибка при анализе brute-force атак: {e}")
        
        return alarms
    
    def analyze_c2_beaconing(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ C2 beaconing (командно-контрольного трафика).
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Обнаруживает периодические соединения с малым джиттером
        """
        alarms = []
        if not self.rules.get("C2_analysys", {}).get("enabled", False):
            return alarms
        
        try:
            c2_config = self.rules.get("C2_analysys", {}).get("beaconing_detection", {})
            if not c2_config.get("enabled", False):
                return alarms
            
            jitter_sec = c2_config.get("jitter_sec", 5)
            interval_min = c2_config.get("interval_min_sec", 10)
            interval_max = c2_config.get("interval_max_sec", 300)
            min_connections = c2_config.get("min_consistent_connections", 5)
            
            connections_by_pair = {}
            
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                timestamp = packet_info.get("timestamp")
                
                if dst_ip not in self.protectips:
                    continue
                
                self.stats["total"] += 1
                pair_key = f"{src_ip}_{dst_ip}"
                
                if pair_key not in connections_by_pair:
                    connections_by_pair[pair_key] = []
                
                connections_by_pair[pair_key].append(timestamp)
                
                if pair_key not in self.stats["connections"]:
                    self.stats["connections"][pair_key] = []
                
                self.stats["connections"][pair_key].append(timestamp)
            
            for pair_key, timestamps in connections_by_pair.items():
                if len(timestamps) < min_connections:
                    continue
                
                src_ip, dst_ip = pair_key.split("_", 1)
                timestamps.sort()
                
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = timestamps[i] - timestamps[i-1]
                    intervals.append(interval)
                
                if len(intervals) >= 2:
                    avg_interval = sum(intervals) / len(intervals)
                    min_interval = min(intervals)
                    max_interval = max(intervals)
                    jitter = max_interval - min_interval
                    
                    if (interval_min <= avg_interval <= interval_max and 
                        jitter <= jitter_sec):
                        
                        reason = f"C2_BEACONING: {src_ip} -> {dst_ip} (interval: {avg_interval:.1f}s, jitter: {jitter:.1f}s, conns: {len(timestamps)})"
                        alarms.append((reason, dst_ip, src_ip, True))
                        
                        self.stats["c2_mb"].append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "avg_interval": avg_interval,
                            "jitter": jitter,
                            "connections": len(timestamps)
                        })
                        self.stats["alarms"]["c2"] += 1
        except Exception as e:
            print(f"Ошибка при анализе C2 beaconing: {e}")
        
        return alarms
    
    def analyze_suspicious_ips(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ трафика с участием подозрительных IP-адресов.
        
        Args:
            window_packets: Список пакетов в анализируемом временном окне
            
        Returns:
            List[Tuple[str, str, str, bool]]: Список триггеров атак в формате 
            (причина, цель, источник, является_ли_защищаемым)
            
        Note:
            Проверяет как источник, так и назначение на наличие в списке подозрительных IP
        """
        alarms = []
        if not self.rules.get("suspicious_ips", {}).get("enabled", False):
            return alarms
        
        try:
            for packet in window_packets:
                packet_info = self._get_packet_info(packet)
                if not packet_info:
                    continue
                
                src_ip = packet_info.get("src_ip")
                dst_ip = packet_info.get("dst_ip")
                
                self.stats["total"] += 1
                
                if dst_ip not in self.protectips:
                    continue
                
                if src_ip in self.suspicious_ips:
                    reason = f"SUSPICIOUS_SOURCE_IP: {src_ip} (threat intel) -> {dst_ip}"
                    alarms.append((reason, dst_ip, src_ip, True))
                    self._increment_counter(self.stats["susp_ips"], src_ip)
                    self.stats["alarms"]["susp_ips"] += 1
                
                if dst_ip in self.suspicious_ips:
                    reason = f"SUSPICIOUS_DEST_IP: {src_ip} -> {dst_ip} (protected IP in threat intel)"
                    alarms.append((reason, dst_ip, src_ip, True))
                    self._increment_counter(self.stats["susp_ips"], dst_ip)
                    self.stats["alarms"]["susp_ips"] += 1
        except Exception as e:
            print(f"Ошибка при анализе подозрительных IP: {e}")
        
        return alarms
    
    def get_statistics(self) -> Dict:
        """
        Возвращает текущую статистику анализа.
        
        Returns:
            Dict: Словарь со статистикой, включая общее количество пакетов,
                  количество срабатываний по типам атак, подозрительные IP и т.д.
        """
        return self.stats
    
    def get_rules(self) -> Dict:
        """
        Возвращает загруженные правила обнаружения.
        
        Returns:
            Dict: Правила обнаружения угроз в формате словаря
        """
        return self.rules
    
    def get_protectips(self) -> List[str]:
        """
        Возвращает список защищаемых IP-адресов.
        
        Returns:
            List[str]: Список IP-адресов, которые находятся под защитой
        """
        return self.protectips