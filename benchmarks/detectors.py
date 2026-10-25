"""Compare full-window rescans with incremental detection on decoded packets.

Run: python -m benchmarks.detectors --counts 500 1000 2000 --repeat 3
This measures Python detection only; it does not measure TShark or capture I/O.
"""
import argparse
import json
import statistics
import tempfile
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from general.streaming import StreamingDetector
from general.trafficanalyzer import TrafficAnalyzer
from general.uTrafficMonitor import TrafficWindow


def run(count, repeat):
    rules = {'ddos': {'enabled': True, '1ip': {'request_limit': count + 1, 'request_limit_window': 1}}}
    packets = [SimpleNamespace(
        ip=SimpleNamespace(src=f'10.0.{i // 256}.{i % 256}', dst='192.168.1.1'),
        tcp=SimpleNamespace(srcport='5000', dstport='80', flags='0x0010'),
        sniff_time=datetime.fromtimestamp(1000 + i / count),
        sniff_timestamp=str(1000 + i / count),
    ) for i in range(count)]
    results = {'rescan_seconds': [], 'incremental_seconds': []}
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / 'rules.json'
        ips = Path(directory) / 'ips.txt'
        config.write_text(json.dumps(rules))
        ips.write_text('192.168.1.1\n')
        for _ in range(repeat):
            analyzer = TrafficAnalyzer(str(config), str(ips))
            window = TrafficWindow(1)
            started = time.perf_counter()
            for pkt in packets:
                timestamp = float(pkt.sniff_timestamp)
                window.add_packet(pkt, timestamp)
                window.cleanup_old(timestamp)
                analyzer.analyze_ddos_single_ip(window.get_packets())
            results['rescan_seconds'].append(time.perf_counter() - started)
            analyzer = TrafficAnalyzer(str(config), str(ips))
            detector = StreamingDetector(analyzer)
            started = time.perf_counter()
            for pkt in packets:
                detector.process(analyzer._get_packet_info(pkt))
            results['incremental_seconds'].append(time.perf_counter() - started)
    medians = {key: statistics.median(values) for key, values in results.items()}
    return dict(packets=count, **medians,
                speedup=medians['rescan_seconds'] / medians['incremental_seconds'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counts', nargs='+', type=int, default=[500, 1000, 2000])
    parser.add_argument('--repeat', type=int, default=3)
    args = parser.parse_args()
    if args.repeat < 1 or any(count < 1 for count in args.counts):
        parser.error('counts and repeat must be positive')
    for count in args.counts:
        print(json.dumps(run(count, args.repeat)), flush=True)


if __name__ == '__main__':
    main()
