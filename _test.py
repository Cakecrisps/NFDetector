#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import tempfile
import os
from unittest.mock import Mock
from general.trafficanalyzer import TrafficAnalyzer


class TestTrafficAnalyzer:
    """Набор тестов для класса TrafficAnalyzer."""
    
    def setup_method(self):
        """
        Подготовка тестовой среды.
        
        Создает временные файлы с правилами и защищаемыми IP,
        инициализирует тестируемый объект.
        """
        self.rules_data = {
            "ddos": {
                "enabled": True,
                "1ip": {"request_limit": 3}
            },
            "flood": {
                "enabled": True,
                "HTTP": {"request_rate_limit": 2}
            },
            "suspicious_ips": {
                "enabled": True,
                "files_of_susp_ip_list": []
            },
            "brute_force": {"enabled": False},
            "C2_analysys": {"enabled": False}
        }
        
        self.temp_rules_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(self.rules_data, self.temp_rules_file)
        self.temp_rules_file.close()
        
        self.temp_protectips_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        self.temp_protectips_file.write("192.168.1.1\n192.168.1.2\n")
        self.temp_protectips_file.close()
        
        self.analyzer = TrafficAnalyzer(
            rules_file=self.temp_rules_file.name,
            protectips=self.temp_protectips_file.name
        )
    
    def teardown_method(self):
        """Очистка тестовой среды - удаление временных файлов."""
        if os.path.exists(self.temp_rules_file.name):
            os.unlink(self.temp_rules_file.name)
        if os.path.exists(self.temp_protectips_file.name):
            os.unlink(self.temp_protectips_file.name)
    
    def _create_packet(self, src_ip, dst_ip, is_http=False, timestamp=1000):
        """
        Создает mock-объект сетевого пакета.
        
        Args:
            src_ip (str): IP-адрес источника
            dst_ip (str): IP-адрес назначения
            is_http (bool): Флаг HTTP-пакета
            timestamp (int): Временная метка
            
        Returns:
            Mock: Сконфигурированный mock-объект пакета
        """
        packet = Mock()
        packet.ip = Mock()
        packet.ip.src = src_ip
        packet.ip.dst = dst_ip
        packet.sniff_time = Mock()
        packet.sniff_time.timestamp = Mock(return_value=timestamp)
        packet.tcp = Mock()
        packet.tcp.srcport = "5000"
        packet.tcp.dstport = "80"
        packet.tcp.flags = "ACK"
        if is_http:
            packet.http = Mock()
        else:
            if hasattr(packet, 'http'):
                delattr(packet, 'http')
        return packet
    
    def test_analyze_ddos_single_ip_positive(self):
        """
        Позитивный тест: обнаружение DDoS атаки от одного IP.
        
        Проверяет, что при превышении порога пакетов от одного IP
        система генерирует корректное предупреждение.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", timestamp=1000 + i) for i in range(4)]
        alarms = self.analyzer.analyze_ddos_single_ip(packets)
        
        assert len(alarms) == 1
        reason, target, attacker, is_protected = alarms[0]
        assert "DDoS_SINGLE_IP" in reason
        assert "10.0.0.1" in reason
        assert is_protected
        assert attacker == "10.0.0.1"
    
    def test_analyze_ddos_single_ip_negative(self):
        """
        Негативный тест: DDoS не обнаружен при малом количестве пакетов.
        
        Проверяет, что система не генерирует ложных срабатываний
        при количестве пакетов ниже порогового значения.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", timestamp=1000 + i) for i in range(2)]
        alarms = self.analyzer.analyze_ddos_single_ip(packets)
        assert len(alarms) == 0
    
    def test_analyze_ddos_single_ip_non_protected_dst(self):
        """
        Тест: пакеты к незащищаемым IP не учитываются.
        
        Проверяет, что система игнорирует трафик,
        направленный на IP, не входящие в список защищаемых.
        """
        packets = [self._create_packet("10.0.0.1", "8.8.8.8", timestamp=1000 + i) for i in range(5)]
        alarms = self.analyzer.analyze_ddos_single_ip(packets)
        assert len(alarms) == 0
    
    def test_analyze_http_flood_positive(self):
        """
        Позитивный тест: обнаружение HTTP flood атаки.
        
        Проверяет генерацию предупреждения при превышении
        порога HTTP-запросов от одного источника.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", is_http=True, timestamp=1000 + i) for i in range(3)]
        alarms = self.analyzer.analyze_http_flood(packets)
        
        assert len(alarms) == 1
        reason, target, attacker, is_protected = alarms[0]
        assert "HTTP_FLOOD" in reason
        assert "10.0.0.1" in reason
        assert is_protected
    
    def test_analyze_http_flood_negative(self):
        """
        Негативный тест: HTTP flood не обнаружен.
        
        Проверяет отсутствие срабатывания при количестве
        HTTP-запросов ниже порогового значения.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", is_http=True, timestamp=1000 + i) for i in range(1)]
        alarms = self.analyzer.analyze_http_flood(packets)
        assert len(alarms) == 0
    
    def test_analyze_http_flood_non_http_packets(self):
        """
        Тест: не-HTTP пакеты игнорируются при анализе HTTP flood.
        
        Проверяет, что система учитывает только HTTP-трафик
        и не реагирует на другие типы пакетов.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", is_http=False, timestamp=1000 + i) for i in range(5)]
        alarms = self.analyzer.analyze_http_flood(packets)
        assert len(alarms) == 0
    
    def test_analyze_suspicious_ips_positive_source(self):
        """
        Позитивный тест: обнаружение подозрительного IP.источника.
        
        Проверяет генерацию предупреждения при трафике
        от IP, находящегося в списке подозрительных.
        """
        temp_susp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_susp_file.write("10.0.0.99\n")
        temp_susp_file.close()
        
        self.analyzer.suspicious_ips.add("10.0.0.99")
        
        packets = [self._create_packet("10.0.0.99", "192.168.1.1")]
        alarms = self.analyzer.analyze_suspicious_ips(packets)
        
        assert len(alarms) == 1
        reason, target, attacker, is_protected = alarms[0]
        assert "SUSPICIOUS_SOURCE_IP" in reason
        assert "10.0.0.99" in reason
        assert attacker == "10.0.0.99"
        assert target == "192.168.1.1"
        assert is_protected
        
        os.unlink(temp_susp_file.name)
    
    def test_analyze_suspicious_ips_positive_destination(self):
        """
        Позитивный тест: обнаружение подозрительного IP.назначения.
        
        Проверяет генерацию предупреждения при трафике
        к IP, которое находится и в списке защищаемых,
        и в списке подозрительных.
        """
        self.analyzer.suspicious_ips.add("192.168.1.1")
        
        packets = [self._create_packet("10.0.0.1", "192.168.1.1")]
        alarms = self.analyzer.analyze_suspicious_ips(packets)
        
        assert len(alarms) == 1
        reason, target, attacker, is_protected = alarms[0]
        assert "SUSPICIOUS_DEST_IP" in reason
        assert target == "192.168.1.1"
        assert attacker == "10.0.0.1"
    
    def test_analyze_suspicious_ips_negative(self):
        """
        Негативный тест: подозрительные IP не обнаружены.
        
        Проверяет отсутствие срабатывания при трафике
        от и к IP, не входящим в списки подозрительных.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1")]
        alarms = self.analyzer.analyze_suspicious_ips(packets)
        assert len(alarms) == 0
    
    def test_analyze_suspicious_ips_disabled(self):
        """
        Тест: анализ подозрительных IP отключен в правилах.
        
        Проверяет, что при отключенной функции в конфигурации
        система не генерирует предупреждений.
        """
        self.rules_data["suspicious_ips"]["enabled"] = False
        
        temp_rules_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(self.rules_data, temp_rules_file)
        temp_rules_file.close()
        
        analyzer = TrafficAnalyzer(
            rules_file=temp_rules_file.name,
            protectips=self.temp_protectips_file.name
        )
        
        analyzer.suspicious_ips.add("10.0.0.99")
        
        packets = [self._create_packet("10.0.0.99", "192.168.1.1")]
        alarms = analyzer.analyze_suspicious_ips(packets)
        assert len(alarms) == 0
        
        os.unlink(temp_rules_file.name)
    
    def test_statistics_increment(self):
        """
        Тест корректного обновления статистики.
        
        Проверяет, что система корректно подсчитывает
        общее количество обработанных пакетов и количество срабатываний.
        """
        packets = [self._create_packet("10.0.0.1", "192.168.1.1", timestamp=1000 + i) for i in range(3)]
        self.analyzer.analyze_ddos_single_ip(packets)
        
        stats = self.analyzer.get_statistics()
        assert stats["total"] == 3
        assert stats["alarms"]["ddos"] == 1