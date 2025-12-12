#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для генерации отчетов о анализе сетевого трафика.
Генерирует текстовые и JSON-отчеты с возможностью настройки путей.
"""

import json
import datetime
import os
from typing import Dict, Any, List, Tuple


def format_top_ips(ip_dict: dict, top_n: int = 5) -> str:
    """
    Форматирует топ-N IP адресов из словаря для вывода.
    
    Args:
        ip_dict: Словарь {ip: количество_пакетов}
        top_n: Количество IP для вывода (по умолчанию 5)
        
    Returns:
        Отформатированная строка с IP и количеством пакетов
    """
    if not ip_dict:
        return "  Нет данных"
    
    sorted_ips = sorted(ip_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return "\n".join([f"  {ip}: {count} пакетов" for ip, count in sorted_ips])


def format_dns_queries(dns_dict: dict, top_n: int = 5) -> str:
    """
    Форматирует топ-N DNS запросов для вывода.
    
    Args:
        dns_dict: Словарь {домен: количество_запросов}
        top_n: Количество доменов для вывода (по умолчанию 5)
        
    Returns:
        Отформатированная строка с доменами и количеством запросов
    """
    if not dns_dict:
        return "  Нет данных"
    
    sorted_dns = sorted(dns_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return "\n".join([f"  {domain}: {count} запросов" for domain, count in sorted_dns])


def generate_summary(
    statistics: dict,
    threat_statistics: dict,
    path_to_file: str,
    path_to_output_dir: str,
    output_filename: str,
    path_to_prot_ips: str,
    path_to_susp_ips: str,
    path_to_rules: str,
    protected_ips_count: int,
    suspicious_ips_count: int
) -> str:
    """
    Генерирует короткую текстовую сводку по анализу трафика.
    
    Args:
        statistics: словарь со статистикой по пакетам
        threat_statistics: словарь со статистикой по угрозам
        path_to_file: путь к анализируемому pcap файлу
        path_to_output_dir: директория для сохранения результатов
        output_filename: имя файла для тревог (с расширением)
        path_to_prot_ips: путь к файлу защищенных IP
        path_to_susp_ips: путь к файлу подозрительных IP
        path_to_rules: путь к файлу правил
        protected_ips_count: количество загруженных защищенных IP
        suspicious_ips_count: количество загруженных подозрительных IP
    
    Returns:
        Путь к созданному файлу сводки или строка с ошибкой
    
    Raises:
        OSError: при ошибках работы с файловой системой
        IOError: при ошибках записи файла
    """
    try:
        base_filename = os.path.splitext(output_filename)[0]
        summary_filename = f"{base_filename}_summary.txt"
        summary_path = os.path.join(path_to_output_dir, summary_filename)
        
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary_content = f"""
КРАТКАЯ СВОДКА ПО АНАЛИЗУ ТРАФИКА
=================================
Дата и время анализа: {current_time}
Файл трафика: {path_to_file}

ОБЩАЯ СТАТИСТИКА:
  Всего пакетов: {statistics['total']}
  Всего байт: {statistics['total_bytes']}
  Уникальных source IP: {len(statistics['src_ips'])}
  Уникальных destination IP: {len(statistics['dst_ips'])}

ТОП-5 SOURCE IP:
{format_top_ips(statistics['src_ips'])}

ТОП-5 DESTINATION IP:
{format_top_ips(statistics['dst_ips'])}

ПОДОЗРИТЕЛЬНЫЕ IP (suspicious_ips):
  Всего пакетов с подозрительными IP: {statistics['suspicious_ips']['total_packets']}
  Пакетов с подозрительными source IP: {statistics['suspicious_ips']['src_count']}
  Пакетов с подозрительными destination IP: {statistics['suspicious_ips']['dst_count']}
  
  Топ-5 подозрительных source IP:
{format_top_ips(statistics['suspicious_ips']['src_ips'])}
  
  Топ-5 подозрительных destination IP:
{format_top_ips(statistics['suspicious_ips']['dst_ips'])}

DNS СТАТИСТИКА (топ-5 доменов):
{format_dns_queries(statistics['dns'])}

ЗАГРУЖЕННЫЕ ФАЙЛЫ:
  Файл защищенных IP: {path_to_prot_ips} ({protected_ips_count} IP)
  Файл подозрительных IP: {path_to_susp_ips} ({suspicious_ips_count} IP)
  Файл правил: {path_to_rules}

СТАТИСТИКА ПО УГРОЗАМ:
{json.dumps(threat_statistics, indent=2, ensure_ascii=False)}
"""

        # Убедимся, что директория существует
        os.makedirs(path_to_output_dir, exist_ok=True)
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary_content)
        
        print(f"Сводка успешно сохранена в: {summary_path}")
        return summary_path
        
    except OSError as e:
        error_msg = f"Ошибка файловой системы при сохранении сводки: {str(e)}"
        print(error_msg)
        return error_msg
    except IOError as e:
        error_msg = f"Ошибка ввода/вывода при сохранении сводки: {str(e)}"
        print(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при сохранении сводки: {str(e)}"
        print(error_msg)
        return error_msg


def generate_full_json_summary(
    statistics: Dict[str, Any],
    threat_statistics: Dict[str, Any],
    alarms: List[Tuple],
    path_to_file: str,
    path_to_output_dir: str,
    output_filename: str,
    path_to_prot_ips: str,
    path_to_susp_ips: str,
    path_to_rules: str,
    protected_ips_count: int,
    suspicious_ips_count: int,
    rules_config: Dict[str, Any]
) -> str:
    """
    Генерирует полную сводку в формате JSON.
    
    Args:
        statistics: общая статистика по трафику
        threat_statistics: статистика по обнаруженным угрозам
        alarms: список сработавших тревог
        path_to_file: путь к анализируемому pcap файлу
        path_to_output_dir: директория для сохранения результатов
        output_filename: имя файла для тревог
        path_to_prot_ips: путь к файлу защищенных IP
        path_to_susp_ips: путь к файлу подозрительных IP
        path_to_rules: путь к файлу правил
        protected_ips_count: количество загруженных защищенных IP
        suspicious_ips_count: количество загруженных подозрительных IP
        rules_config: конфигурация правил анализа
        
    Returns:
        Путь к созданному JSON файлу или строка с ошибкой
    
    Raises:
        OSError: при ошибках работы с файловой системой
        IOError: при ошибках записи файла
        json.JSONEncodeError: при ошибках сериализации JSON
    """
    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Расчет длительности анализа с обработкой возможного отсутствия ключей
        try:
            analysis_duration = round(
                float(statistics.get('last_packet_time', 0)) - 
                float(statistics.get('first_packet_time', 0)), 
                2
            )
        except (KeyError, ValueError, TypeError):
            analysis_duration = 0
        
        # Формирование структуры JSON
        full_summary = {
            "raw_stats": statistics,
            "metadata": {
                "analysis_time": current_time,
                "traffic_file": path_to_file,
                "analysis_duration_seconds": analysis_duration
            },
            "files": {
                "protected_ips": {
                    "path": path_to_prot_ips,
                    "count": protected_ips_count,
                    "content_sample": list(statistics['src_ips'].keys())[:3] 
                    if statistics.get('src_ips') else []
                },
                "suspicious_ips": {
                    "path": path_to_susp_ips,
                    "count": suspicious_ips_count,
                    "content_sample": list(statistics['suspicious_ips']['src_ips'].keys())[:3] 
                    if 'suspicious_ips' in statistics else []
                },
                "rules": {
                    "path": path_to_rules,
                    "content": rules_config
                }
            },
            "traffic_statistics": {
                "total_packets": statistics['total'],
                "total_bytes": statistics['total_bytes'],
                "protocols_distribution": statistics['protos'],
                "top_source_ips_formatted": format_top_ips(statistics['src_ips'], 10),
                "top_destination_ips_formatted": format_top_ips(statistics['dst_ips'], 10),
                "dns_statistics_formatted": format_dns_queries(statistics['dns'], 10),
                "packet_size_average": round(statistics['total_bytes'] / statistics['total'], 2) 
                if statistics['total'] > 0 else 0
            },
            "suspicious_activity": {
                "total_suspicious_packets": statistics['suspicious_ips']['total_packets'],
                "suspicious_sources_formatted": format_top_ips(
                    statistics['suspicious_ips']['src_ips'], 10
                ),
                "suspicious_destinations_formatted": format_top_ips(
                    statistics['suspicious_ips']['dst_ips'], 10
                ),
                "threat_correlation": []
            },
            "detailed_threat_analysis": {
                "brute_force": {
                    "detected": threat_statistics.get('brute_force', {}).get('detected', False),
                    "attempts_count": threat_statistics.get('brute_force', {}).get('attempts', 0),
                    "target_ips": threat_statistics.get('brute_force', {}).get('target_ips', []),
                    "source_ips": threat_statistics.get('brute_force', {}).get('source_ips', []),
                    "time_window": rules_config.get('brute_force', {}).get('tryes_limit_window', 20.0)
                },
                "ddos_attacks": {
                    "multi_ip": {
                        "detected": threat_statistics.get('ddos_nip', {}).get('detected', False),
                        "source_ips": threat_statistics.get('ddos_nip', {}).get('source_ips', []),
                        "target_ips": threat_statistics.get('ddos_nip', {}).get('target_ips', []),
                        "packet_rate": threat_statistics.get('ddos_nip', {}).get('packet_rate', 0),
                        "threshold": rules_config.get('ddos', {}).get('nip', {}).get('request_limit', 100)
                    },
                    "single_ip": {
                        "detected": threat_statistics.get('ddos_1ip', {}).get('detected', False),
                        "source_ip": threat_statistics.get('ddos_1ip', {}).get('source_ip', ""),
                        "target_ips": threat_statistics.get('ddos_1ip', {}).get('target_ips', []),
                        "packet_rate": threat_statistics.get('ddos_1ip', {}).get('packet_rate', 0),
                        "threshold": rules_config.get('ddos', {}).get('1ip', {}).get('request_limit', 1000)
                    },
                    "http_flood": {
                        "detected": threat_statistics.get('flood_HTTP', {}).get('detected', False),
                        "source_ips": threat_statistics.get('flood_HTTP', {}).get('source_ips', []),
                        "request_rate": threat_statistics.get('flood_HTTP', {}).get('request_rate', 0),
                        "threshold": rules_config.get('flood', {}).get('HTTP', {}).get('request_rate_limit', 100)
                    }
                },
                "flood_attacks": {
                    "syn_flood": {
                        "detected": threat_statistics.get('flood_SYN', {}).get('detected', False),
                        "source_ips": threat_statistics.get('flood_SYN', {}).get('source_ips', []),
                        "syn_ack_ratio": threat_statistics.get('flood_SYN', {}).get('syn_ack_ratio', 0),
                        "threshold": rules_config.get('flood', {}).get('SYN', {}).get('syn_ack_ratio_limit', 0.3)
                    }
                },
                "c2_activity": {
                    "detected": threat_statistics.get('c2_beaconing', {}).get('detected', False),
                    "beaconing_ips": threat_statistics.get('c2_beaconing', {}).get('beaconing_ips', []),
                    "interval_seconds": threat_statistics.get('c2_beaconing', {}).get('interval_seconds', 0),
                    "min_interval": rules_config.get('C2_analysys', {}).get('beaconing_detection', {}).get('interval_min_sec', 10),
                    "max_interval": rules_config.get('C2_analysys', {}).get('beaconing_detection', {}).get('interval_max_sec', 300)
                }
            },
            "alarms_summary": {
                "total_alarms": len(alarms),
                "alarms_by_type": {},
                "raw_alarms": []
            }
        }
        
        # Подсчет тревог по типам
        for alarm in alarms:
            if isinstance(alarm, tuple):
                alarm_type = alarm[0] if len(alarm) > 0 else "unknown"
                full_summary["alarms_summary"]["alarms_by_type"][alarm_type] = \
                    full_summary["alarms_summary"]["alarms_by_type"].get(alarm_type, 0) + 1
        
        # Преобразование тревог в сериализуемый формат
        for alarm in alarms:
            if isinstance(alarm, tuple):
                full_summary["alarms_summary"]["raw_alarms"].append({
                    "type": alarm[0] if len(alarm) > 0 else "",
                    "source": alarm[1] if len(alarm) > 1 else "",
                    "destination": alarm[2] if len(alarm) > 2 else "",
                    "details": str(alarm[3]) if len(alarm) > 3 else ""
                })
        
        # Корреляция подозрительных IP с угрозами (только если есть данные)
        if 'suspicious_ips' in statistics and 'src_ips' in statistics['suspicious_ips']:
            for ip in list(statistics['suspicious_ips']['src_ips'].keys())[:5]:
                related_alarms = [
                    a for a in full_summary["alarms_summary"]["raw_alarms"] 
                    if ip in a.get("source", "") or ip in a.get("destination", "")
                ]
                full_summary["suspicious_activity"]["threat_correlation"].append({
                    "ip": ip,
                    "packet_count": statistics['suspicious_ips']['src_ips'][ip],
                    "related_threats": related_alarms[:3]
                })
        
        # Формирование пути к файлу
        base_filename = os.path.splitext(output_filename)[0]
        json_filename = f"{base_filename}_full_report.json"
        json_path = os.path.join(path_to_output_dir, json_filename)
        
        # Создание директории и сохранение файла
        os.makedirs(path_to_output_dir, exist_ok=True)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(full_summary, f, indent=2, ensure_ascii=False)
        
        print(f"Полная JSON сводка успешно сохранена в: {json_path}")
        return json_path
        
    except OSError as e:
        error_msg = f"Ошибка файловой системы при сохранении JSON: {str(e)}"
        print(error_msg)
        return error_msg
    except IOError as e:
        error_msg = f"Ошибка ввода/вывода при сохранении JSON: {str(e)}"
        print(error_msg)
        return error_msg
    except json.JSONEncodeError as e:
        error_msg = f"Ошибка кодирования JSON: {str(e)}"
        print(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при сохранении JSON: {str(e)}"
        print(error_msg)
        return error_msg