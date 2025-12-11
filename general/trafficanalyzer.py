import json
from typing import Dict, List, Tuple, Optional, Set
import time
from datetime import datetime


class TrafficAnalyzer:
    """
    Анализатор сетевого трафика для обнаружения угроз безопасности.
    Включает анализ: DDoS, Flood (SYN и HTTP), Brute-force, C2 beaconing, подозрительных IP.
    """
    
    def __init__(self, rules_file: str, protectips: str):
        """
        Инициализация анализатора трафика.
        
        Parameters
        ----------
        rules_file : str
            Путь к файлу с правилами (JSON)
        protectips : str
            Путь к файлу с IP для мониторинга
        """
        # Загрузка правил
        with open(rules_file, 'r') as f:
            self.rules = json.load(f)
        
        # Загрузка защищаемых IP
        with open(protectips, 'r') as f:
            self.protectips = [line.strip() for line in f if line.strip()]
        
        # Статистика - только необходимые поля
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
        
        # Загрузка подозрительных IP
        self.suspicious_ips = set()
        if self.rules.get("suspicious_ips", {}).get("enabled", False):
            susp_files = self.rules["suspicious_ips"]["files_of_susp_ip_list"]
            for filepath in susp_files:
                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                self.suspicious_ips.add(ip)
                except FileNotFoundError:
                    print(f"⚠️ Suspicious IP file not found: {filepath}")
        
        # Хранилище для отслеживания SYN соединений
        self.pending_syns = {}  # {conn_id: timestamp} - ожидающие SYN-ACK
    
    def _increment_counter(self, counter_dict: dict, key: str) -> None:
        """Увеличивает счетчик в словаре."""
        if key in counter_dict:
            counter_dict[key] += 1
        else:
            counter_dict[key] = 1
    
    def _get_packet_info(self, packet) -> Dict:
        """
        Извлекает информацию из пакета pyshark.
        
        Parameters
        ----------
        packet : pyshark.packet.packet.Packet
            Пакет для анализа
            
        Returns
        -------
        Dict
            Словарь с информацией о пакете
        """
        try:
            if not hasattr(packet, 'ip'):
                return {}
            
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Получаем временную метку
            if hasattr(packet, 'sniff_time'):
                timestamp = packet.sniff_time.timestamp()
            else:
                timestamp = time.time()
            
            # Определяем протокол
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
            
            # Анализируем TCP флаги
            tcp_flags = None
            is_syn = False
            is_syn_ack = False
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                tcp_flags = packet.tcp.flags
                is_syn = 'SYN' in tcp_flags and 'ACK' not in tcp_flags
                is_syn_ack = 'SYN' in tcp_flags and 'ACK' in tcp_flags
            
            # Проверяем на HTTP запрос
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
            
        except Exception:
            return {}
    
    def _get_connection_id(self, src_ip: str, dst_ip: str, src_port: str, dst_port: str) -> str:
        """Генерирует уникальный идентификатор соединения."""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def analyze_ddos_single_ip(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ DDoS от одного IP (правило 1ip).
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для правила 1ip
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        if not self.rules.get("ddos", {}).get("enabled", False):
            return alarms
        
        ddos_config = self.rules["ddos"]
        
        # Правило 1: запросы от 1 IP
        rule_1ip = ddos_config.get("1ip", {})
        request_limit = rule_1ip.get("request_limit", 1000)
        
        # Фильтруем только пакеты к защищаемым IP
        src_counts = {}
        
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            # Проверяем, что цель защищается
            if dst_ip in self.protectips:
                self._increment_counter(src_counts, src_ip)
                self.stats["total"] += 1
        
        # Проверяем превышение лимита
        for src_ip, count in src_counts.items():
            if count >= request_limit:
                reason = f"DDoS_SINGLE_IP: {src_ip} sent {count} packets (limit: {request_limit})"
                alarms.append((reason, "PROTECTED_NETWORK", src_ip, True))
                self.stats["alarms"]["ddos"] += 1
        
        return alarms
    
    def analyze_ddos_multi_ip(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ DDoS от множества IP (правило nip).
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для правила nip
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        if not self.rules.get("ddos", {}).get("enabled", False):
            return alarms
        
        ddos_config = self.rules["ddos"]
        
        # Правило 2: общее количество запросов
        rule_nip = ddos_config.get("nip", {})
        total_limit = rule_nip.get("request_limit", 5000)
        display_count = rule_nip.get("display_ips", 10)
        
        # Фильтруем только пакеты к защищаемым IP
        src_counts = {}
        total_protected_packets = 0
        
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            # Проверяем, что цель защищается
            if dst_ip in self.protectips:
                self._increment_counter(src_counts, src_ip)
                total_protected_packets += 1
                self.stats["total"] += 1
        
        if total_protected_packets >= total_limit:
            # Находим топ IP по количеству пакетов
            sorted_ips = sorted(
                src_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:display_count]
            
            top_ips = [f"{ip}({count})" for ip, count in sorted_ips]
            top_ips_str = ", ".join(top_ips)
            
            reason = f"DDoS_MULTI_IP: {total_protected_packets} total packets (limit: {total_limit}), top: {top_ips_str}"
            alarms.append((reason, "PROTECTED_NETWORK", "MULTIPLE", True))
            self.stats["alarms"]["ddos"] += 1
        return alarms
    
    def analyze_syn_flood(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ SYN flood атаки с проверкой разорванных (полуоткрытых) соединений.
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для анализа SYN flood
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        
        if not self.rules.get("flood", {}).get("enabled", False):
            return alarms
        
        flood_config = self.rules["flood"]
        
        if "SYN" not in flood_config:
            return alarms
        
        syn_config = flood_config["SYN"]
        syn_limit = syn_config.get("syn_only_limit", 50)
        
        current_time = time.time()
        
        # Очищаем старые ожидающие SYN (старше 5 секунд)
        timeout = 5.0
        expired_syns = []
        for conn_id, syn_time in self.pending_syns.items():
            if current_time - syn_time > timeout:
                expired_syns.append(conn_id)
        
        for conn_id in expired_syns:
            del self.pending_syns[conn_id]
        
        # Анализируем пакеты в окне
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            src_port = packet_info.get("src_port")
            dst_port = packet_info.get("dst_port")
            
            # Проверяем, что цель защищается
            if dst_ip not in self.protectips:
                continue
            
            self.stats["total"] += 1
            
            # Анализируем TCP флаги
            is_syn = packet_info.get("is_syn", False)
            is_syn_ack = packet_info.get("is_syn_ack", False)
            
            if is_syn and src_port and dst_port:
                # Клиент отправил SYN - сохраняем
                conn_id = self._get_connection_id(src_ip, dst_ip, src_port, dst_port)
                self.pending_syns[conn_id] = packet_info["timestamp"]
                
            elif is_syn_ack and src_port and dst_port:
                # Сервер ответил SYN-ACK - проверяем, был ли SYN
                # Для SYN-ACK источник и назначение меняются местами
                conn_id = self._get_connection_id(dst_ip, src_ip, dst_port, src_port)
                
                if conn_id in self.pending_syns:
                    # Нашли парный SYN-ACK - соединение установлено, удаляем из ожидания
                    del self.pending_syns[conn_id]
        
        # После обработки окна подсчитываем полуоткрытые соединения для каждого источника
        src_half_open_counts = {}
        
        for conn_id, syn_time in self.pending_syns.items():
            # conn_id = "src_ip:src_port-dst_ip:dst_port"
            parts = conn_id.split('-')
            if len(parts) == 2:
                src_part = parts[0]  # "src_ip:src_port"
                src_ip = src_part.split(':')[0]
                
                self._increment_counter(src_half_open_counts, src_ip)
        
        # Проверяем превышение лимита полуоткрытых соединений
        for src_ip, count in src_half_open_counts.items():
            if count >= syn_limit:
                reason = f"SYN_FLOOD_HALF_OPEN: {src_ip} has {count} half-open connections (limit: {syn_limit})"
                alarms.append((reason, "PROTECTED_NETWORK", src_ip, True))
                self.stats["alarms"]["flood"] += 1
        
        return alarms
    
    def analyze_http_flood(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ HTTP flood атаки.
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для анализа HTTP flood
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        if not self.rules.get("flood", {}).get("enabled", False):
            return alarms
        
        flood_config = self.rules["flood"]
        
        if "HTTP" not in flood_config:
            return alarms
        
        http_config = flood_config["HTTP"]
        http_limit = http_config.get("request_rate_limit", 80)
        
        # Фильтруем только HTTP запросы к защищаемым IP
        src_counts = {}
        
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            is_http = packet_info.get("is_http", False)
            
            # Проверяем, что цель защищается и это HTTP запрос
            if dst_ip in self.protectips and is_http:
                self._increment_counter(src_counts, src_ip)
                self.stats["total"] += 1
        
        # Проверяем превышение лимита
        for src_ip, count in src_counts.items():
            if count >= http_limit:
                reason = f"HTTP_FLOOD: {src_ip} sent {count} HTTP requests (limit: {http_limit})"
                alarms.append((reason, "PROTECTED_NETWORK", src_ip, True))
                self.stats["alarms"]["flood"] += 1
        return alarms
    
    def analyze_bruteforce(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ brute-force атак.
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для анализа brute-force
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        
        if not self.rules.get("brute_force", {}).get("enabled", False):
            return alarms
        
        bf_config = self.rules["brute_force"]
        proto_list = bf_config.get("auth_proto", [])
        tryes_limit = bf_config.get("tryes_limit", 10)
        
        # Импортируем функцию is_auth_attempt из общего модуля
        try:
            from general.authdetect import is_auth_attempt
        except ImportError:
            print("⚠️ Could not import is_auth_attempt from general.authdetect")
            return alarms
        
        # Собираем попытки аутентификации
        auth_attempts_by_key = {}
        
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            # Проверяем, что цель защищается
            if dst_ip not in self.protectips:
                continue
            
            # Определяем, является ли пакет попыткой аутентификации
            is_auth, protocol = is_auth_attempt(packet)
            
            if is_auth and protocol in proto_list:
                self.stats["total"] += 1
                
                # Группируем по источнику, цели и протоколу
                key = f"{src_ip}_{dst_ip}_{protocol}"
                
                if key not in auth_attempts_by_key:
                    auth_attempts_by_key[key] = []
                
                auth_attempts_by_key[key].append(packet_info["timestamp"])
                
                # Обновляем глобальную статистику
                if key not in self.stats["auth_attempts"]:
                    self.stats["auth_attempts"][key] = []
                
                self.stats["auth_attempts"][key].append({
                    "timestamp": packet_info["timestamp"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol
                })
        
        # Проверяем превышение лимита
        for key, timestamps in auth_attempts_by_key.items():
            src_ip, dst_ip, protocol = key.split("_", 2)
            
            if len(timestamps) >= tryes_limit:
                reason = f"BRUTEFORCE_{protocol}: {src_ip} -> {dst_ip} ({len(timestamps)} attempts, limit: {tryes_limit})"
                alarms.append((reason, dst_ip, src_ip, True))
                self.stats["alarms"]["bruteforce"] += 1
        
        return alarms
    
    def analyze_c2_beaconing(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ C2 beaconing.
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для анализа C2 beaconing
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        
        if not self.rules.get("C2_analysys", {}).get("enabled", False):
            return alarms
        
        c2_config = self.rules.get("C2_analysys", {}).get("beaconing_detection", {})
        if not c2_config.get("enabled", False):
            return alarms
        
        jitter_sec = c2_config.get("jitter_sec", 5)
        interval_min = c2_config.get("interval_min_sec", 10)
        interval_max = c2_config.get("interval_max_sec", 300)
        min_connections = c2_config.get("min_consistent_connections", 5)
        
        # Собираем соединения
        connections_by_pair = {}
        
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            timestamp = packet_info.get("timestamp")
            
            # Проверяем, что цель защищается
            if dst_ip not in self.protectips:
                continue
            
            self.stats["total"] += 1
            
            # Группируем по паре источник-цель
            pair_key = f"{src_ip}_{dst_ip}"
            
            if pair_key not in connections_by_pair:
                connections_by_pair[pair_key] = []
            
            connections_by_pair[pair_key].append(timestamp)
            
            # Обновляем глобальную статистику
            if pair_key not in self.stats["connections"]:
                self.stats["connections"][pair_key] = []
            
            self.stats["connections"][pair_key].append(timestamp)
        
        # Анализируем регулярность
        for pair_key, timestamps in connections_by_pair.items():
            if len(timestamps) < min_connections:
                continue
            
            src_ip, dst_ip = pair_key.split("_", 1)
            
            # Сортируем временные метки
            timestamps.sort()
            
            # Вычисляем интервалы
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if len(intervals) >= 2:
                avg_interval = sum(intervals) / len(intervals)
                min_interval = min(intervals)
                max_interval = max(intervals)
                jitter = max_interval - min_interval
                
                # Проверяем условия beaconing
                if (interval_min <= avg_interval <= interval_max and 
                    jitter <= jitter_sec):
                    
                    reason = f"C2_BEACONING: {src_ip} -> {dst_ip} (interval: {avg_interval:.1f}s, jitter: {jitter:.1f}s, conns: {len(timestamps)})"
                    alarms.append((reason, dst_ip, src_ip, True))
                    
                    # Сохраняем в статистику
                    self.stats["c2_mb"].append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "avg_interval": avg_interval,
                        "jitter": jitter,
                        "connections": len(timestamps)
                    })
                    self.stats["alarms"]["c2"] += 1
        
        return alarms
    
    def analyze_suspicious_ips(self, window_packets: List) -> List[Tuple[str, str, str, bool]]:
        """
        Анализ подозрительных IP.
        
        Parameters
        ----------
        window_packets : List[pyshark.packet.packet.Packet]
            Окно пакетов для анализа подозрительных IP
            
        Returns
        -------
        List[Tuple[str, str, str, bool]]
            Список кортежей (reason, ipdst, ipsrc, is_prot) для создания Alarm
        """
        alarms = []
        
        if not self.rules.get("suspicious_ips", {}).get("enabled", False):
            return alarms
        
        # Проверяем каждый пакет
        for packet in window_packets:
            packet_info = self._get_packet_info(packet)
            if not packet_info:
                continue
            
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            self.stats["total"] += 1
            
            # Проверяем, что цель защищается
            if dst_ip not in self.protectips:
                continue
            
            # Проверяем источник на подозрительность
            if src_ip in self.suspicious_ips:
                reason = f"SUSPICIOUS_SOURCE_IP: {src_ip} (threat intel) -> {dst_ip}"
                alarms.append((reason, dst_ip, src_ip, True))
                self._increment_counter(self.stats["susp_ips"], src_ip)
                self.stats["alarms"]["susp_ips"] += 1
            
            # Проверяем цель на подозрительность
            if dst_ip in self.suspicious_ips:
                reason = f"SUSPICIOUS_DEST_IP: {src_ip} -> {dst_ip} (protected IP in threat intel)"
                alarms.append((reason, dst_ip, src_ip, True))
                self._increment_counter(self.stats["susp_ips"], dst_ip)
                self.stats["alarms"]["susp_ips"] += 1
        
        return alarms
    
    def get_statistics(self) -> Dict:
        """
        Возвращает текущую статистику.
        
        Returns
        -------
        Dict
            Текущая статистика
        """
        return self.stats
    
    def get_rules(self) -> Dict:
        """
        Возвращает загруженные правила.
        
        Returns
        -------
        Dict
            Правила обнаружения
        """
        return self.rules
    
    def get_protectips(self) -> List[str]:
        """
        Возвращает список защищаемых IP.
        
        Returns
        -------
        List[str]
            Список защищаемых IP
        """
        return self.protectips