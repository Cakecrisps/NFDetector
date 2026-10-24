"""Regression coverage for detection and monitor integration."""
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from general.trafficanalyzer import TrafficAnalyzer
from general.uTrafficMonitor import NetworkTrafficMonitor


ROOT = Path(__file__).resolve().parents[1]


def packet(src='10.0.0.1', dst='192.168.1.1', timestamp=1000,
           flags='0x0010', srcport='5000', dstport='80'):
    return SimpleNamespace(
        ip=SimpleNamespace(src=src, dst=dst),
        tcp=SimpleNamespace(srcport=srcport, dstport=dstport, flags=flags),
        sniff_time=datetime.fromtimestamp(timestamp),
        sniff_timestamp=str(timestamp), length='60', highest_layer='TCP',
    )


class DetectionRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.ips = self.directory / 'ips.txt'
        self.ips.write_text('# Protected hosts\n192.168.1.1 # server\n\n')
        self.susp = self.directory / 'susp.txt'
        self.susp.write_text('# Threat intel\n10.0.0.99 # scanner\n')
        self.rules = json.loads((ROOT / 'rules.json').read_text())
        self.rules['reaction']['out'] = []
        self.rules['suspicious_ips']['files_of_susp_ip_list'] = [str(self.susp)]
        self.rules['ddos']['1ip']['request_limit'] = 3
        self.rules['ddos']['nip']['request_limit'] = 4
        self.rules['flood']['SYN']['syn_only_limit'] = 2
        self.rules_path = self.directory / 'rules.json'

    def analyzer(self):
        self.rules_path.write_text(json.dumps(self.rules))
        return TrafficAnalyzer(str(self.rules_path), str(self.ips))

    def monitor(self):
        self.rules_path.write_text(json.dumps(self.rules))
        return NetworkTrafficMonitor(str(self.rules_path), str(self.ips),
                                     str(self.directory), 'alerts.log')

    def test_ip_comments_are_parsed_consistently(self):
        monitor = self.monitor()
        self.assertEqual(monitor.protected_ips, {'192.168.1.1'})
        self.assertEqual(set(monitor.analyzer.protectips), monitor.protected_ips)
        self.assertEqual(monitor.suspicious_ips, {'10.0.0.99'})
        self.assertEqual(monitor.analyzer.suspicious_ips, monitor.suspicious_ips)

    def test_numeric_tcp_flags(self):
        analyzer = self.analyzer()
        for flags, syn, syn_ack in [('0x0002', True, False),
                                     ('0x0012', False, True),
                                     ('0x0010', False, False)]:
            with self.subTest(flags=flags):
                info = analyzer._get_packet_info(packet(flags=flags))
                self.assertEqual(info['is_syn'], syn)
                self.assertEqual(info['is_syn_ack'], syn_ack)

    def test_syn_flood_with_capture_timestamps(self):
        analyzer = self.analyzer()
        alarms = analyzer.analyze_syn_flood([
            packet(flags='0x0002', srcport='5000'),
            packet(flags='0x0002', srcport='5001', timestamp=1000.1),
        ])
        self.assertEqual(len(alarms), 1)

    def test_syn_ack_clears_pending_connection(self):
        analyzer = self.analyzer()
        packets = [packet(flags='0x0002'),
                   packet(src='192.168.1.1', dst='10.0.0.1', flags='0x0012',
                          srcport='80', dstport='5000', timestamp=1000.1)]
        self.assertEqual(analyzer.analyze_syn_flood(packets), [])
        self.assertEqual(analyzer.pending_syns, {})

    def test_syn_timeout_uses_configured_capture_window(self):
        self.rules['flood']['SYN']['syn_only_window'] = 10
        analyzer = self.analyzer()
        analyzer.analyze_syn_flood([packet(flags='0x0002')])
        analyzer.analyze_syn_flood([packet(timestamp=1006)])
        self.assertEqual(len(analyzer.pending_syns), 1)
        analyzer.analyze_syn_flood([packet(timestamp=1011)])
        self.assertEqual(analyzer.pending_syns, {})

    def test_multi_ip_requires_multiple_sources(self):
        self.assertEqual(self.analyzer().analyze_ddos_multi_ip([packet()] * 5), [])

    def test_default_multi_ip_threshold_does_not_flag_normal_pair(self):
        self.rules['ddos']['nip'] = json.loads((ROOT / 'rules.json').read_text())['ddos']['nip']
        self.assertEqual(self.analyzer().analyze_ddos_multi_ip([
            packet(), packet(src='10.0.0.2')]), [])

    def test_multi_ip_attack_retains_all_attackers(self):
        monitor = self.monitor()
        monitor._analyze_window('ddos_nip', [packet()] * 2 + [packet(src='10.0.0.2')] * 2)
        self.assertEqual({alarm[2] for alarm in monitor.alarms}, {'10.0.0.1', '10.0.0.2'})

    def test_every_alarm_is_logged(self):
        monitor = self.monitor()
        alarms = [('first', 'target', 'a', True), ('second', 'target', 'b', True)]
        with patch.object(monitor.analyzer, 'analyze_ddos_single_ip', return_value=alarms), \
                patch('general.uTrafficMonitor.Alarm.log') as log:
            monitor._analyze_window('ddos_1ip', [packet()])
        self.assertEqual(monitor.alarms, alarms)
        self.assertEqual(log.call_count, 2)

    def test_fast_replay_detects_burst_before_window_expires(self):
        monitor = self.monitor()
        with patch('general.uTrafficMonitor.time.time', return_value=100000):
            for timestamp in [1000, 1000.1, 1000.2, 1002]:
                monitor.process_packet(packet(timestamp=timestamp))
        self.assertTrue(any('DDoS_SINGLE_IP' in alarm[0] for alarm in monitor.alarms))

    def test_replay_speed_does_not_change_alarms(self):
        results = []
        for speed in [0.001, 2]:
            monitor = self.monitor()
            with patch('general.uTrafficMonitor.time.time', side_effect=[100000 + i * speed for i in range(100)]):
                for timestamp in [1000, 1000.1, 1000.2, 1002]:
                    monitor.process_packet(packet(timestamp=timestamp))
            results.append(monitor.alarms)
        self.assertEqual(results[0], results[1])

    def test_suspicious_ip_is_checked_once_per_packet(self):
        monitor = self.monitor()
        monitor.process_packet(packet(src='10.0.0.99'))
        monitor._analyze_all_windows()
        self.assertEqual(sum('SUSPICIOUS_SOURCE_IP' in alarm[0] for alarm in monitor.alarms), 1)

    def test_disabled_suspicious_ip_does_not_emit_alarm(self):
        self.rules['suspicious_ips']['enabled'] = False
        monitor = self.monitor()
        monitor.process_packet(packet(src='10.0.0.99'))
        self.assertEqual(monitor.alarms, [])


if __name__ == '__main__':
    unittest.main()
