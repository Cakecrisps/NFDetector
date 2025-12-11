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
from general.summarygen import generate_summary,generate_full_json_summary

# Импорт правильного типа Packet из pyshark
from pyshark.packet.packet import Packet

class NetworkTrafficMonitor:
    """
    Простой монитор трафика с классическими временными окнами.
    
    Особенности:
    - Загружает подозрительные IP из файла правил
    - Исправлена проблема с event loop в потоках
    - Нет перекрытия окон - каждое окно имеет строгую длительность
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
        # Загружаем конфигурацию
        self._load_configuration()
        
        # Инициализируем структуры данных
        self.statistics = self._init_statistics()
        self.windows = self._init_windows()
        self.analyzer = TrafficAnalyzer(rules_path, protected_ips_path)
        
        # Для live-режима
        self.stop_flag = False
        self.capture_thread = None
        
        # Создаем директорию вывода
        os.makedirs(output_dir, exist_ok=True)
        self._init_log_file()
    
    def _load_configuration(self):
        """Загружает правила и списки IP-адресов из файлов."""
        # Загрузка правил
        with open(self.rules_path, 'r') as f:
            self.rules = json.load(f)
        
        # Загрузка подозрительных IP из правил
        self.suspicious_ips = set()
        self.suspicious_ips_sources = []
        
        susp_ips_config = self.rules.get("suspicious_ips", {})
        if susp_ips_config.get("enabled", False):
            files_list = susp_ips_config.get("files_of_susp_ip_list", [])
            for file_path in files_list:
                self.suspicious_ips_sources.append(file_path)
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                self.suspicious_ips.add(ip)
                        if self.debug_mode:
                            print(f"[DEBUG] Загружено {len(self.suspicious_ips)} подозрительных IP из {file_path}")
                except Exception as e:
                    print(f"Ошибка загрузки подозрительных IP из {file_path}: {e}")
        else:
            if self.debug_mode:
                print("[DEBUG] Загрузка подозрительных IP отключена в правилах")
        
        # Загрузка защищенных IP
        self.protected_ips = set()
        try:
            with open(self.protected_ips_path, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.protected_ips.add(ip)
        except Exception as e:
            print(f"Ошибка загрузки защищенных IP {self.protected_ips_path}: {e}")
    
    def _init_statistics(self) -> Dict[str, Any]:
        """Инициализирует структуру для сбора статистики."""
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
        """
        windows = {}
        
        # Brute force windows
        if self.rules.get("brute_force", {}).get("enabled", False):
            window_sec = self.rules["brute_force"].get("tryes_limit_window", 20.0)
            windows["brute_force_tryes_limit"] = {
                "packets": [],
                "window_sec": window_sec,
                "last_analysis": 0
            }
        
        # DDoS windows
        if self.rules.get("ddos", {}).get("enabled", False):
            ddos_rules = self.rules["ddos"]
            
            if "1ip" in ddos_rules:
                window_sec = ddos_rules["1ip"].get("request_limit_window", 1.0)
                windows["ddos_1ip"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}
            
            if "nip" in ddos_rules:
                window_sec = ddos_rules["nip"].get("request_limit_window", 1.0)
                windows["ddos_nip"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}
        
        # Flood windows
        if self.rules.get("flood", {}).get("enabled", False):
            flood_rules = self.rules["flood"]
            
            if "SYN" in flood_rules:
                window_sec = flood_rules["SYN"].get("syn_only_window", 5.0)
                windows["flood_SYN"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}
            
            if "HTTP" in flood_rules:
                window_sec = flood_rules["HTTP"].get("request_rate_window", 1.0)
                windows["flood_HTTP"] = {"packets": [], "window_sec": window_sec, "last_analysis": 0}
        
        # C2 windows
        if self.rules.get("C2_analysys", {}).get("enabled", False):
            c2_rules = self.rules["C2_analysys"]
            if c2_rules.get("beaconing_detection", {}).get("enabled", False):
                min_interval = c2_rules["beaconing_detection"].get("interval_min_sec", 10)
                max_interval = c2_rules["beaconing_detection"].get("interval_max_sec", 300)
                
                windows["C2_min_interval"] = {"packets": [], "window_sec": min_interval, "last_analysis": 0}
                windows["C2_max_interval"] = {"packets": [], "window_sec": max_interval, "last_analysis": 0}
        
        return windows
    
    def _init_log_file(self):
        """Инициализирует лог-файл заголовком сессии."""
        header = (
            f"=== NFDetect Session Start ===\n"
            f"Время: {datetime.datetime.now()}\n"
            f"Подозрительные IP: {', '.join(self.suspicious_ips_sources) if self.suspicious_ips_sources else 'отключены'}\n"
            f"Отладка: {'Включена' if self.debug_mode else 'Выключена'}\n"
            f"{'='*30}\n\n"
        )
        
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(header)
    
    def process_packet(self, packet: Packet):
        """
        Обрабатывает один пакет.
        """
        packet_time = float(packet.sniff_timestamp)
        
        # Обновляем общую статистику
        self._update_statistics(packet, packet_time)
        
        # Обрабатываем каждое окно
        for window_type, window in self.windows.items():
            if not window:
                continue
            
            window_sec = window["window_sec"]
            window_start = packet_time - window_sec
            
            # Удаляем старые пакеты
            window["packets"] = [
                p for p in window["packets"]
                if float(p.sniff_timestamp) >= window_start
            ]
            
            # Добавляем новый пакет
            window["packets"].append(packet)
            
            # Анализируем окно
            self._analyze_window_if_needed(window_type, window, packet_time)
    
    def _update_statistics(self, packet: Packet, packet_time: float):
        """Обновляет статистику на основе нового пакета."""
        if self.statistics["start_time"] is None:
            self.statistics["start_time"] = packet_time
        
        self.statistics["end_time"] = packet_time
        self.statistics["total"] += 1
        
        # Статистика по размеру пакетов
        try:
            self.statistics["total_bytes"] += int(packet.length)
        except (AttributeError, ValueError):
            pass
        
        # Статистика по протоколам
        self._update_protocol_stats(packet)
        
        # Статистика по IP
        src_ip = self._get_src_ip(packet)
        dst_ip = self._get_dst_ip(packet)
        
        if src_ip:
            self.statistics["src_ips"][src_ip] = self.statistics["src_ips"].get(src_ip, 0) + 1
        if dst_ip:
            self.statistics["dst_ips"][dst_ip] = self.statistics["dst_ips"].get(dst_ip, 0) + 1
        
        # Статистика по DNS
        self._update_dns_stats(packet)
        
        # Статистика по подозрительным IP
        self._update_suspicious_ip_stats(packet, src_ip, dst_ip)
    
    def _analyze_window_if_needed(self, window_type: str, window: Dict, current_time: float):
        """
        Анализирует окно если прошло достаточно времени с последнего анализа.
        """
        window_sec = window["window_sec"]
        
        # Для коротких окон анализируем каждый пакет
        if window_sec < 5.0:
            self._analyze_window(window_type, window["packets"])
            window["last_analysis"] = current_time
            return
        
        # Для длинных окон анализируем с периодичностью
        time_since_last_analysis = current_time - window["last_analysis"]
        if time_since_last_analysis >= 1.0:
            self._analyze_window(window_type, window["packets"])
            window["last_analysis"] = current_time
    
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
                alarm = self.analyzer.analyze_ddos_multi_ip(packets)
            elif "flood_SYN" in window_type:
                alarm = self.analyzer.analyze_syn_flood(packets)
            elif "C2" in window_type:
                alarm = self.analyzer.analyze_c2_beaconing(packets)
            else:
                return
                
            if len(alarm) == 0:return
            
            self.alarms.append(alarm[0])
            
            if alarm and len(alarm) != 0:
                Alarm(alarm[0][0], alarm[0][1], alarm[0][2], alarm[0][3]).log(
                    self.log_path,
                    self.rules["reaction"]["out"]
                )
                
                if self.debug_mode:
                    print(f"[ALERT] {alarm[0][1]} в окне {window_type}")
        except:
            if self.debug_mode:print(f"Error in analyze {window_type}")
                
    
    def analyze_file(self, pcap_path: str) -> Dict[str, Any]:
        """
        Анализирует PCAP-файл полностью в синхронном режиме.
        """
        print(f"[+] Начало анализа файла: {pcap_path}")
        
        # Загрузка всех пакетов
        capture = pyshark.FileCapture(pcap_path)
        
        # Обработка всех пакетов
        for packet in capture:
            self.process_packet(packet)
        
        capture.close()
        
        # Финальный анализ всех окон
        self._analyze_all_windows()
        
        # Генерация отчетов
        self._generate_reports(pcap_path)
        
        print("[+] Анализ файла завершен")
        return self._get_results()
    
    def _analyze_all_windows(self):
        """Принудительно анализирует все окна перед завершением."""
        for window_type, window in self.windows.items():
            if window["packets"]:
                self._analyze_window(window_type, window["packets"])
    
    def start_live_capture(self, interface: str, duration: int = 0):
        """
        Запускает live-захват в отдельном потоке.
        """
        print(f"[+] Запуск live-мониторинга на интерфейсе: {interface}")
        if self.debug_mode:
            print("[DEBUG] Режим отладки включен")
        
        # Сбрасываем флаг остановки
        self.stop_flag = False
        
        # Запускаем захват в отдельном потоке
        self.capture_thread = threading.Thread(
            target=self._live_capture_worker,
            args=(interface, duration),
            daemon=True
        )
        self.capture_thread.start()
        
        print("[+] Live-захват запущен (нажмите Ctrl+C для остановки)")
    
    def _live_capture_worker(self, interface: str, duration: int):
        """Рабочая функция для live-захвата в отдельном потоке."""
        # Создаем event loop для этого потока
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        start_time = time.time()
        
        try:
            # Используем event loop в pyshark
            capture = pyshark.LiveCapture(
                interface=interface,
                eventloop=loop
            )
            
            for packet in capture.sniff_continuously():
                if self.stop_flag:
                    break
                
                # Проверка времени работы
                if duration > 0 and (time.time() - start_time) >= duration:
                    print(f"[+] Достигнуто время захвата: {duration} сек")
                    break
                
                # Обработка пакета
                self.process_packet(packet)
                
                # Отладочный вывод
                if self.debug_mode:
                    src = self._get_src_ip(packet) or "N/A"
                    dst = self._get_dst_ip(packet) or "N/A"
                    if self.statistics["total"] % 100 == 0:
                        print(f"[DEBUG] Пакет #{self.statistics['total']}: {src} -> {dst}")
        
        except Exception as e:
            print(f"[ERROR] Ошибка захвата трафика: {e}")
        finally:
            # Закрываем event loop
            loop.close()
            # Закрываем захват
            if 'capture' in locals():
                try:
                    capture.close()
                except Exception as e:
                    if self.debug_mode:
                        print(f"[DEBUG] Ошибка закрытия захвата: {e}")
            print("[+] Live-захват остановлен")
    
    def stop_live_capture(self):
        """
        Останавливает live-захват.
        """
        print("\n[!] Остановка live-захвата...")
        self.stop_flag = True
        
        # Ждем завершения потока захвата
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
        
        # Финальный анализ всех окон
        self._analyze_all_windows()
        
        # Генерация отчетов
        self._generate_reports("live_capture")
        
        print("[+] Live-мониторинг завершен")
    
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
                self.rules)
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
            print(f"[ERROR] Ошибка генерации отчетов: {e}")
    
    def _get_results(self) -> Dict[str, Any]:
        """Возвращает результаты анализа."""
        return {
            "windows": {k: v["packets"] for k, v in self.windows.items()},
            "statistics": self.statistics,
        }
    
    # Вспомогательные методы
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
            self.statistics["suspicious_ips"]["src_ips"][src_ip] = self.statistics["suspicious_ips"]["src_ips"].get(src_ip, 0) + 1
        
        if dst_ip and dst_ip in self.suspicious_ips:
            is_suspicious = True
            self.statistics["suspicious_ips"]["dst_count"] += 1
            self.statistics["suspicious_ips"]["dst_ips"][dst_ip] = self.statistics["suspicious_ips"]["dst_ips"].get(dst_ip, 0) + 1
        
        if is_suspicious:
            self.statistics["suspicious_ips"]["total_packets"] += 1

# Функции-обертки для совместимости
def filescan(
    path_to_file: str,
    path_to_output_dir: str,
    output_filename: str,
    path_to_prot_ips: str,
    path_to_rules: str
):
    """Анализирует PCAP-файл."""
    monitor = NetworkTrafficMonitor(
        rules_path=path_to_rules,
        protected_ips_path=path_to_prot_ips,
        output_dir=path_to_output_dir,
        log_filename=output_filename
    )
    return monitor.analyze_file(path_to_file)

def livescan(
    interface: str,
    output_dir: str,
    log_file: str,
    protected_ips: str,
    rules_file: str,
    debug_mode: bool = False,
    duration: int = 0
):
    """Запускает live-мониторинг."""
    monitor = NetworkTrafficMonitor(
        rules_path=rules_file,
        protected_ips_path=protected_ips,
        output_dir=output_dir,
        log_filename=log_file,
        debug_mode=debug_mode
    )
    
    try:
        monitor.start_live_capture(interface, duration)
        
        # Ожидаем остановки пользователем
        while monitor.capture_thread and monitor.capture_thread.is_alive():
            time.sleep(0.5)
    
    except KeyboardInterrupt:
        print("\n[!] Остановка по запросу пользователя")
        time.sleep(3)
    finally:
        monitor.stop_live_capture()