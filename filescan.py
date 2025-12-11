import json
import pyshark
from typing import List, Dict, Any, Set
import math
import datetime
import os
from general.trafficanalyzer import TrafficAnalyzer
from general.logs import log
from general.AlarmClass import Alarm
from general.summarygen import generate_summary,generate_full_json_summary

def format_top_ips(ip_dict: Dict[str, int], top_n: int = 5) -> str:
    """Форматирует топ-N IP адресов из словаря"""
    if not ip_dict:
        return "  Нет данных"
    
    sorted_ips = sorted(ip_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return "\n".join([f"  {ip}: {count} пакетов" for ip, count in sorted_ips])

def format_dns_queries(dns_dict: Dict[str, int], top_n: int = 5) -> str:
    """Форматирует топ-N DNS запросов"""
    if not dns_dict:
        return "  Нет данных"
    
    sorted_dns = sorted(dns_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return "\n".join([f"  {domain}: {count} запросов" for domain, count in sorted_dns])

def filescan(
    path_to_file: str,
    path_to_output_dir: str,
    output_filename: str,
    path_to_prot_ips: str,
    path_to_susp_ips: str,
    path_to_rules: str
) -> Dict[str, Any]:
    """
    Анализирует pcap файл и создает списки пакетов, соответствующие временным окнам из правил.
    Также подсчитывает общую статистику по всем пакетам, включая статистику по подозрительным IP.
    Генерирует короткую сводку в формате .txt.
    
    Args:
        path_to_file: путь к pcap файлу
        path_to_output_dir: путь к директории для вывода результатов
        output_filename: имя файла для записи тревог (с расширением .txt)
        path_to_prot_ips: путь к файлу с защищенными IP
        path_to_susp_ips: путь к файлу с подозрительными IP
        path_to_rules: путь к файлу с правилами
    
    Returns:
        Словарь с двумя ключами:
        - "windows": словарь с временными окнами для каждого правила
        - "statistics": общая статистика по всем пакетам, включая статистику по подозрительным IP
    """
    
    # Загрузка правил
    with open(path_to_rules, 'r') as f:
        rules = json.load(f)
    
    # Загрузка подозрительных IP
    suspicious_ips: Set[str] = set()
    try:
        with open(path_to_susp_ips, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):  # Игнорируем пустые строки и комментарии
                    suspicious_ips.add(ip)
    except Exception as e:
        print(f"Ошибка при чтении файла подозрительных IP {path_to_susp_ips}: {str(e)}")
    
    # Загрузка защищенных IP (для информации в сводке)
    protected_ips: Set[str] = set()
    try:
        with open(path_to_prot_ips, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):  # Игнорируем пустые строки и комментарии
                    protected_ips.add(ip)
    except Exception as e:
        print(f"Ошибка при чтении файла защищенных IP {path_to_prot_ips}: {str(e)}")
    
    # Загрузка pcap файла
    capture = pyshark.FileCapture(path_to_file)
    all_packets = list(capture)
    capture.close()
    
    # 1. Подсчет общей статистики по всем пакетам, включая статистику по подозрительным IP
    statistics = _calculate_statistics(all_packets, suspicious_ips)
    
    # 2. Создание временных окон для правил
    windows_dict = _create_windows_for_rules(all_packets, rules)
    
    NFDetector = TrafficAnalyzer(path_to_rules, path_to_prot_ips)

    alarms = [NFDetector.analyze_bruteforce(x) for x in windows_dict["brute_force_tryes_limit"]]
    alarms +=  [NFDetector.analyze_ddos_multi_ip(x) for x in windows_dict["ddos_nip"]]
    alarms += [NFDetector.analyze_ddos_multi_ip(x) for x in windows_dict["ddos_1ip"]]
    alarms += [NFDetector.analyze_ddos_multi_ip(x) for x in windows_dict["flood_HTTP"]]
    alarms += [NFDetector.analyze_syn_flood(x) for x in windows_dict["flood_SYN"]]
    alarms += [NFDetector.analyze_c2_beaconing(x) for x in windows_dict["C2_min_interval"] + windows_dict["C2_max_interval"]]
    
    for alarm in alarms:
        if len(alarm) == 0:continue
        Alarm(alarm[0], alarm[1], alarm[2], alarm[3]).log(
            path_to_output_dir + output_filename,
            rules["reaction"]["out"]
        )

    gs = generate_summary(statistics,NFDetector.get_statistics(),path_to_file,path_to_output_dir,output_filename,path_to_prot_ips,path_to_susp_ips,path_to_rules,len(protected_ips),len(suspicious_ips))
    gjs = generate_full_json_summary(statistics,NFDetector.get_statistics(),alarms,path_to_file,path_to_output_dir,output_filename,path_to_prot_ips,path_to_susp_ips,path_to_rules,len(protected_ips),len(suspicious_ips),rules)
    
    print(gs,gjs)
        
    return statistics

def _calculate_statistics(packets: List[pyshark.packet.packet.Packet], suspicious_ips: Set[str]) -> Dict[str, Any]:
    """Подсчитывает общую статистику по всем пакетам, включая статистику по подозрительным IP."""
    
    stats = {
        "total": 0,
        "total_bytes": 0,
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
    
    if not packets:
        return stats
    
    for packet in packets:
        # Общее количество пакетов
        stats["total"] += 1
        
        # Общий объем данных (в байтах)
        try:
            if hasattr(packet, 'length'):
                packet_length = int(packet.length)
                stats["total_bytes"] += packet_length
        except (AttributeError, ValueError):
            pass
        
        # Статистика по протоколам
        _update_protocol_stats(packet, stats["protos"])
        
        # Статистика по исходным IP
        src_ip = _get_src_ip(packet)
        if src_ip:
            stats["src_ips"][src_ip] = stats["src_ips"].get(src_ip, 0) + 1
        
        # Статистика по целевым IP
        dst_ip = _get_dst_ip(packet)
        if dst_ip:
            stats["dst_ips"][dst_ip] = stats["dst_ips"].get(dst_ip, 0) + 1
        
        # Статистика по DNS запросам
        _update_dns_stats(packet, stats["dns"])
        
        # ===== НОВАЯ ЧАСТЬ: Статистика по подозрительным IP =====
        is_suspicious = False
        
        # Проверка source IP
        if src_ip and src_ip in suspicious_ips:
            is_suspicious = True
            stats["suspicious_ips"]["src_count"] += 1
            stats["suspicious_ips"]["src_ips"][src_ip] = stats["suspicious_ips"]["src_ips"].get(src_ip, 0) + 1
        
        # Проверка destination IP
        if dst_ip and dst_ip in suspicious_ips:
            is_suspicious = True
            stats["suspicious_ips"]["dst_count"] += 1
            stats["suspicious_ips"]["dst_ips"][dst_ip] = stats["suspicious_ips"]["dst_ips"].get(dst_ip, 0) + 1
        
        # Общий счетчик пакетов с подозрительными IP
        if is_suspicious:
            stats["suspicious_ips"]["total_packets"] += 1
    
    return stats


def _update_protocol_stats(packet: pyshark.packet.packet.Packet, protos_dict: Dict[str, int]) -> None:
    """Обновляет статистику по протоколам."""
    try:
        # Используем highest_layer как основной протокол
        if hasattr(packet, 'highest_layer'):
            proto = packet.highest_layer
            protos_dict[proto] = protos_dict.get(proto, 0) + 1
        
        # Также считаем транспортные протоколы
        if hasattr(packet, 'transport_layer'):
            transport = packet.transport_layer
            protos_dict[transport] = protos_dict.get(transport, 0) + 1
    except (AttributeError, ValueError):
        pass


def _get_src_ip(packet: pyshark.packet.packet.Packet) -> str:
    """Извлекает исходный IP адрес из пакета."""
    try:
        if hasattr(packet, 'ip'):
            return packet.ip.src
        elif hasattr(packet, 'ipv6'):
            return packet.ipv6.src
        elif hasattr(packet, 'eth'):
            return packet.eth.src
    except (AttributeError, ValueError):
        pass
    return ""


def _get_dst_ip(packet: pyshark.packet.packet.Packet) -> str:
    """Извлекает целевой IP адрес из пакета."""
    try:
        if hasattr(packet, 'ip'):
            return packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            return packet.ipv6.dst
        elif hasattr(packet, 'eth'):
            return packet.eth.dst
    except (AttributeError, ValueError):
        pass
    return ""


def _update_dns_stats(packet: pyshark.packet.packet.Packet, dns_dict: Dict[str, Any]) -> None:
    """Обновляет статистику по DNS запросам."""
    try:
        if hasattr(packet, 'dns'):
            # DNS запросы
            if hasattr(packet.dns, 'qry_name'):
                query = str(packet.dns.qry_name)
                if query:
                    dns_dict[query] = dns_dict.get(query, 0) + 1
    except (AttributeError, ValueError):
        pass


def _create_windows_for_rules(packets: List[pyshark.packet.packet.Packet], 
                              rules: Dict[str, Any]) -> Dict[str, List[List[pyshark.packet.packet.Packet]]]:
    """Создает временные окна для всех правил."""
    
    windows_dict = {}
    
    # 1. Обработка brute_force правил - добавляем всегда, даже если отключены
    if rules.get("brute_force", {}).get("enabled", False):
        brute_force_rules = rules["brute_force"]
        
        # Для tryes_limit_window
        window_seconds = brute_force_rules.get("tryes_limit_window", 20.0)
        window_packets = _create_time_windows(packets, window_seconds)
        windows_dict["brute_force_tryes_limit"] = window_packets
    else:
        # Если правило отключено - пустой список
        windows_dict["brute_force_tryes_limit"] = []
    
    # 2. Обработка DDoS правил
    if rules.get("ddos", {}).get("enabled", False):
        ddos_rules = rules["ddos"]
        
        # Для 1ip правило
        if "1ip" in ddos_rules:
            window_seconds = ddos_rules["1ip"].get("request_limit_window", 1.0)
            window_packets = _create_time_windows(packets, window_seconds)
            windows_dict["ddos_1ip"] = window_packets
        else:
            windows_dict["ddos_1ip"] = []
        
        # Для nip правило
        if "nip" in ddos_rules:
            window_seconds = ddos_rules["nip"].get("request_limit_window", 1.0)
            window_packets = _create_time_windows(packets, window_seconds)
            windows_dict["ddos_nip"] = window_packets
        else:
            windows_dict["ddos_nip"] = []
    else:
        # Если все ddos отключены
        windows_dict["ddos_1ip"] = []
        windows_dict["ddos_nip"] = []
    
    # 3. Обработка flood правил
    if rules.get("flood", {}).get("enabled", False):
        flood_rules = rules["flood"]
        
        # Для SYN flood
        if "SYN" in flood_rules:
            window_seconds = flood_rules["SYN"].get("syn_only_window", 5.0)
            # Фильтруем только SYN пакеты
            syn_packets = _filter_syn_packets(packets)
            window_packets = _create_time_windows(syn_packets, window_seconds)
            windows_dict["flood_SYN"] = window_packets
        else:
            windows_dict["flood_SYN"] = []
        
        # Для HTTP flood
        if "HTTP" in flood_rules:
            window_seconds = flood_rules["HTTP"].get("request_rate_window", 1.0)
            # Фильтруем HTTP пакеты
            http_packets = _filter_http_packets(packets)
            window_packets = _create_time_windows(http_packets, window_seconds)
            windows_dict["flood_HTTP"] = window_packets
        else:
            windows_dict["flood_HTTP"] = []
    else:
        # Если все flood отключены
        windows_dict["flood_SYN"] = []
        windows_dict["flood_HTTP"] = []
    
    # 4. Обработка C2 анализа
    if rules.get("C2_analysys", {}).get("enabled", False):
        c2_rules = rules["C2_analysys"]
        
        if c2_rules.get("beaconing_detection", {}).get("enabled", False):
            beaconing_config = c2_rules["beaconing_detection"]
            
            # Для beaconing detection создаем окна на основе минимального интервала
            min_interval = beaconing_config.get("interval_min_sec", 10)
            window_packets = _create_time_windows(packets, min_interval)
            windows_dict["C2_min_interval"] = window_packets
            
            # Также создаем окна на основе максимального интервала
            max_interval = beaconing_config.get("interval_max_sec", 300)
            max_window_packets = _create_time_windows(packets, max_interval)
            windows_dict["C2_max_interval"] = max_window_packets
        else:
            windows_dict["C2_min_interval"] = []
            windows_dict["C2_max_interval"] = []
    else:
        # Если C2 анализ отключен
        windows_dict["C2_min_interval"] = []
        windows_dict["C2_max_interval"] = []

    return windows_dict


def _create_time_windows(
    packets: List[pyshark.packet.packet.Packet], 
    window_seconds: float
) -> List[List[pyshark.packet.packet.Packet]]:
    """
    Создает списки пакетов, сгруппированных по временным окнам.
    """
    if not packets:
        return []
    
    # Сортируем пакеты по времени
    sorted_packets = sorted(packets, key=lambda x: float(x.sniff_timestamp))
    
    # Получаем время первого пакета
    start_time = float(sorted_packets[0].sniff_timestamp)
    
    # Инициализируем результат
    windows = []
    current_window = []
    current_window_end = start_time + window_seconds
    
    for packet in sorted_packets:
        packet_time = float(packet.sniff_timestamp)
        
        # Если пакет в текущем окне, добавляем его
        if packet_time < current_window_end:
            current_window.append(packet)
        else:
            # Сохраняем текущее окно и начинаем новое
            if current_window:
                windows.append(current_window)
            
            # Создаем новое окно
            current_window = [packet]
            
            # Обновляем конец окна
            window_start = math.floor((packet_time - start_time) / window_seconds) * window_seconds + start_time
            current_window_end = window_start + window_seconds
    
    # Добавляем последнее окно
    if current_window:
        windows.append(current_window)
    
    return windows


def _filter_syn_packets(packets: List[pyshark.packet.packet.Packet]) -> List[pyshark.packet.packet.Packet]:
    """Фильтрует только SYN пакеты (без ACK)."""
    syn_packets = []
    for packet in packets:
        try:
            if hasattr(packet, 'tcp'):
                flags = getattr(packet.tcp, 'flags', '')
                flags_str = str(flags).upper()
                if 'SYN' in flags_str and 'ACK' not in flags_str:
                    syn_packets.append(packet)
        except AttributeError:
            continue
    return syn_packets


def _filter_http_packets(packets: List[pyshark.packet.packet.Packet]) -> List[pyshark.packet.packet.Packet]:
    """Фильтрует HTTP/HTTPS пакеты."""
    http_packets = []
    for packet in packets:
        try:
            # Проверяем HTTP протокол
            if hasattr(packet, 'http'):
                http_packets.append(packet)
            # Или стандартные порты HTTP/HTTPS
            elif hasattr(packet, 'tcp'):
                src_port = int(getattr(packet.tcp, 'srcport', 0))
                dst_port = int(getattr(packet.tcp, 'dstport', 0))
                if src_port in [80, 443, 8080, 8443] or dst_port in [80, 443, 8080, 8443]:
                    http_packets.append(packet)
        except (AttributeError, ValueError):
            continue
    return http_packets