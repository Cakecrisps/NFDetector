"""HTTPS smoke test for an already running isolated Compose deployment.

The deployment must protect 192.168.1.1, set DDoS limit=3, HTTP limit=2 and
HTTP Basic brute-force limit=2. See docs/development/testing.md for setup.
No real traffic is captured. A large noise file makes parallel worker assignment visible.
"""
import argparse
import json
import socket
import tempfile
import time
from pathlib import Path

import dpkt

from distributed.agent import Uploader


def detected_kinds(events):
    """An incident may combine multiple rules under one representative reason."""
    return {kind for event in events
            for kind in (event.get('kinds') or [event['reason'].split(':', 1)[0]])}


def frame(payload=b'', seq=100, flags=16, target='192.168.1.1', port=80):
    tcp = dpkt.tcp.TCP(sport=5000, dport=port, seq=seq, flags=flags, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton('10.0.0.1'), dst=socket.inet_aton(target), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x00' * 6, dst=b'\x01' * 6, type=0x0800, data=ip))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--key-file', required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--noise-frames', type=int, default=150000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first, second = root / 'first.pcap', root / 'second.pcapng'
        prefix = b'GET / HTTP/1.1\r\nHost: example.test\r\nAuthor'
        suffix = b'ization: Basic dXNlcjpwYXNz\r\n\r\n'
        with first.open('wb') as handle:
            writer = dpkt.pcap.Writer(handle)
            writer.writepkt(frame(flags=2), ts=1000)
            writer.writepkt(frame(prefix, seq=101), ts=1000.1)
            noise = frame(target='8.8.8.8', port=443)
            for _ in range(args.noise_frames):
                writer.writepkt(noise, ts=1000.15)
        with second.open('wb') as handle:
            writer = dpkt.pcapng.Writer(handle)
            writer.writepkt(frame(suffix, seq=101 + len(prefix)), ts=1000.2)
            writer.writepkt(frame(prefix + suffix, seq=101 + len(prefix + suffix)), ts=1000.3)
        uploader = Uploader(args.server, args.key_file, root / 'state.json', 'synthetic', ca=args.ca)
        uploader.upload_files([first, second])
        stream = uploader.state['stream_id']
        deadline = time.monotonic() + 120
        expected = ('DDoS_SINGLE_IP', 'HTTP_FLOOD', 'BRUTEFORCE_HTTP Basic')
        while time.monotonic() < deadline:
            status = uploader.request('GET', f'/v1/streams/{stream}/status')
            if status['detector']['error'] or any(chunk['error'] for chunk in status['chunks']):
                raise RuntimeError(json.dumps(status))
            events = uploader.request('GET', '/v1/events')['events']
            own = [event for event in events if event['stream_id'] == stream]
            if set(expected) <= detected_kinds(own):
                owners = {chunk['parsed_by'] for chunk in status['chunks']}
                if len(owners) != 2:
                    raise AssertionError('The files were not handled by distinct workers; increase --noise-frames')
                finished = {chunk['sequence']: chunk['parser_finished_at'] for chunk in status['chunks']}
                if not finished[1] < finished[0]:
                    raise AssertionError('Expected the later, smaller file to finish parsing first')
                print(json.dumps(dict(stream_id=stream, parser_workers=sorted(owners),
                                      later_file_finished_first=True,
                                      detected=sorted(detected_kinds(own)),
                                      incidents=len(own)), indent=2))
                return
            time.sleep(0.5)
        raise TimeoutError('No combined attack detected within 120 seconds')


if __name__ == '__main__':
    main()
