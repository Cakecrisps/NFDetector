"""State, expiry and integration checks for incremental detection."""
import json
from unittest.mock import patch

import pytest

from general.streaming import BeaconWindow, StreamingDetector
from general.uTrafficMonitor import NetworkTrafficMonitor
from test_regressions import packet


@pytest.fixture
def analyzer(tmp_path):
    rules = {
        'ddos': {'enabled': True, '1ip': {'request_limit': 3, 'request_limit_window': 1},
                 'nip': {'request_limit': 4, 'request_limit_window': 1, 'display_ips': 10}},
        'flood': {'enabled': True, 'HTTP': {'request_rate_limit': 2, 'request_rate_window': 1},
                  'SYN': {'syn_only_limit': 2, 'syn_only_window': 5}},
        'brute_force': {'enabled': True, 'auth_proto': ['SSH'], 'tryes_limit': 2, 'tryes_limit_window': 20},
        'C2_analysys': {'enabled': True, 'beaconing_detection': {
            'enabled': True, 'interval_min_sec': 10, 'interval_max_sec': 300,
            'jitter_sec': 5, 'min_consistent_connections': 5}},
        'suspicious_ips': {'enabled': True, 'files_of_susp_ip_list': []},
        'reaction': {'out': []},
    }
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules))
    ips = tmp_path / 'ips.txt'
    ips.write_text('192.168.1.1\n192.168.1.2\n')
    from general.trafficanalyzer import TrafficAnalyzer
    return TrafficAnalyzer(str(path), str(ips))


def event(analyzer, timestamp=1000, **kwargs):
    info = analyzer._get_packet_info(packet(timestamp=timestamp, **kwargs))
    info.pop('packet')
    return info


def labels(alarms, prefix):
    return [alarm for alarm in alarms if alarm[0].startswith(prefix)]


def test_threshold_crossing_and_rearm(analyzer):
    detector = StreamingDetector(analyzer)
    alarms = []
    for timestamp in [1000, 1000.1, 1000.2, 1000.3, 1002, 1002.1, 1002.2]:
        alarms += detector.process(event(analyzer, timestamp))
    assert len(labels(alarms, 'DDoS_SINGLE_IP')) == 2
    assert detector.stats['total'] == 7


def test_rate_boundary_is_inclusive(analyzer):
    detector = StreamingDetector(analyzer)
    assert not labels(detector.process(event(analyzer, 1000)), 'DDoS_SINGLE_IP')
    detector.process(event(analyzer, 1000.5))
    assert labels(detector.process(event(analyzer, 1001)), 'DDoS_SINGLE_IP')
    assert len(detector.rates['ddos'].events) == 3


def test_separate_targets_do_not_combine_rates(analyzer):
    detector = StreamingDetector(analyzer)
    alarms = []
    for target in ['192.168.1.1', '192.168.1.2']:
        for _ in range(2):
            alarms += detector.process(event(analyzer, dst=target))
    assert not labels(alarms, 'DDoS_SINGLE_IP')
    assert not labels(alarms, 'DDoS_MULTI_IP')


def test_distributed_attack_rearms_after_sources_expire(analyzer):
    detector = StreamingDetector(analyzer)
    alarms = []
    for start in [1000, 1002]:
        for source in ['10.0.0.1', '10.0.0.2']:
            for _ in range(2):
                alarms += detector.process(event(analyzer, start, src=source))
    assert len(labels(alarms, 'DDoS_MULTI_IP')) == 4


def test_http_and_auth_filtering(analyzer):
    detector = StreamingDetector(analyzer)
    ordinary = event(analyzer)
    assert detector.process(ordinary) == []
    http = dict(ordinary, is_http=True)
    assert not labels(detector.process(http, 'FTP'), 'HTTP_FLOOD')
    alarms = detector.process(http, 'SSH')
    assert labels(alarms, 'HTTP_FLOOD')
    assert not labels(alarms, 'BRUTEFORCE')
    assert labels(detector.process(ordinary, 'SSH'), 'BRUTEFORCE_SSH')


def test_syn_ack_retransmit_and_expiry(analyzer):
    detector = StreamingDetector(analyzer)
    syn = event(analyzer, flags='0x0002')
    detector.process(syn)
    detector.process(syn)
    assert sum(detector.syn_counts.values()) == 1
    alarms = detector.process(event(analyzer, srcport='5001', flags='0x0002'))
    assert len(labels(alarms, 'SYN_FLOOD')) == 1
    detector.process(event(analyzer, 1001, src='192.168.1.1', dst='10.0.0.1',
                           flags='0x0012', srcport='80', dstport='5000'))
    assert sum(detector.syn_counts.values()) == 1
    detector.process(event(analyzer, 1006))
    assert not detector.pending_syns
    assert not detector.syn_counts


def test_beaconing_incremental_result_matches_batch(analyzer):
    detector = StreamingDetector(analyzer)
    packets = [packet(timestamp=1000 + i * 15) for i in range(5)]
    alarms = []
    for pkt in packets:
        alarms += detector.process(analyzer._get_packet_info(pkt))
    assert len(labels(alarms, 'C2_BEACONING')) == len(analyzer.analyze_c2_beaconing(packets)) == 1
    # Continuing the incident does not emit the same alarm on every packet.
    assert not labels(detector.process(event(analyzer, 1075)), 'C2_BEACONING')


def test_beacon_extrema_survive_expiration():
    state = BeaconWindow()
    for timestamp in [0, 10, 30, 60, 100]:
        state.add(timestamp)
    state.expire(30)
    assert list(state.times) == [30, 60, 100]
    assert state.interval_sum == 70
    assert state.minimum[0][1] == 30
    assert state.maximum[0][1] == 40
    state.expire(101)
    assert not state.times and not state.intervals
    assert not state.minimum and not state.maximum
    assert state.interval_sum == 0


def test_idle_stream_releases_all_state(analyzer):
    detector = StreamingDetector(analyzer)
    for i in range(50):
        detector.process(event(analyzer, 1000 + i / 100, src=f'10.0.0.{i}', flags='0x0002'), 'SSH')
    # Unprotected traffic still advances all expiry clocks.
    detector.process(event(analyzer, 2000, dst='8.8.8.8'))
    assert all(not window.events and not window.counts for window in detector.rates.values())
    assert not detector.multi_events and not detector.multi_sources and not detector.multi_totals
    assert not detector.multi_active
    assert not detector.syn_events and not detector.pending_syns and not detector.syn_counts
    assert not detector.beacon_events and not detector.beacons and not detector.beacon_active


def test_late_packet_does_not_mutate_state(analyzer):
    detector = StreamingDetector(analyzer)
    detector.process(event(analyzer, 1000))
    with pytest.raises(ValueError, match='nondecreasing'):
        detector.process(event(analyzer, 999))
    assert detector.stats['total'] == 1
    assert len(detector.rates['ddos'].events) == 1


def test_monitor_decodes_each_packet_once_and_does_not_retain_it(tmp_path, analyzer):
    monitor = NetworkTrafficMonitor(str(tmp_path / 'rules.json'), str(tmp_path / 'ips.txt'), str(tmp_path), 'alerts.log')
    with patch.object(monitor.analyzer, '_get_packet_info', wraps=monitor.analyzer._get_packet_info) as decode:
        for i in range(20):
            monitor.process_packet(packet(timestamp=1000 + i / 100))
    assert decode.call_count == 20
    assert not monitor.windows
    assert monitor.analyzer.stats['total'] == 20
    assert not monitor.analyzer.stats['connections']
    assert not monitor.analyzer.stats['auth_attempts']


def test_file_is_decoded_once_without_packet_retention(tmp_path, analyzer):
    monitor = NetworkTrafficMonitor(str(tmp_path / 'rules.json'), str(tmp_path / 'ips.txt'), str(tmp_path), 'alerts.log')
    from unittest.mock import MagicMock
    capture = MagicMock()
    capture.__iter__.return_value = iter([packet(), packet(timestamp=1000.1)])
    with patch('general.uTrafficMonitor.pyshark.FileCapture', return_value=capture) as factory, \
            patch.object(monitor, '_generate_reports'):
        monitor.analyze_file('capture.pcap')
    factory.assert_called_once_with('capture.pcap', debug=False, keep_packets=False)
    capture.close.assert_called_once()
    assert monitor.statistics['total'] == 2


def test_state_survives_file_boundary(tmp_path, analyzer):
    from unittest.mock import MagicMock
    monitor = NetworkTrafficMonitor(str(tmp_path / 'rules.json'), str(tmp_path / 'ips.txt'), str(tmp_path), 'alerts.log')
    captures = [MagicMock(), MagicMock()]
    captures[0].__iter__.return_value = iter([packet(), packet(timestamp=1000.1)])
    captures[1].__iter__.return_value = iter([packet(timestamp=1000.2)])
    with patch('general.uTrafficMonitor.pyshark.FileCapture', side_effect=captures), \
            patch.object(monitor, '_generate_reports'):
        monitor.analyze_file('first.pcap')
        assert not labels(monitor.alarms, 'DDoS_SINGLE_IP')
        monitor.analyze_file('second.pcap')
    assert len(labels(monitor.alarms, 'DDoS_SINGLE_IP')) == 1
    assert monitor.statistics['total'] == 3


def test_beacon_running_statistics_match_reference():
    import random
    rng = random.Random(42)
    state = BeaconWindow()
    reference = []
    timestamp = 1000
    for _ in range(300):
        timestamp += rng.choice([0, 1, 5, 10, 40])
        cutoff = timestamp - 60
        reference = [value for value in reference if value >= cutoff]
        state.expire(cutoff)
        state.add(timestamp)
        reference.append(timestamp)
        intervals = [b - a for a, b in zip(reference, reference[1:])]
        assert list(state.times) == reference
        assert state.interval_sum == pytest.approx(sum(intervals))
        if intervals:
            assert state.minimum[0][1] == min(intervals)
            assert state.maximum[0][1] == max(intervals)
