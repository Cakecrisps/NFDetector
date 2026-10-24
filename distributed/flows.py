"""TCP/application and IPv4 fragment state, shared across parsed PCAP files.

This is a bounded detector-oriented decoder, not a replacement for every Wireshark
protocol dissector. TLS and encrypted SSH authentication remain opaque.
"""
import heapq
import re
from dataclasses import dataclass, field

import dpkt

from .capture import add_transport


@dataclass
class Direction:
    next_seq: int = None
    initial_seq: int = None
    segments: dict = field(default_factory=dict)
    segment_heap: list = field(default_factory=list)
    buffer: bytes = b''
    protocol: str = ''
    body_left: int = 0
    chunked: bool = False
    chunk_left: int = 0
    chunk_trailers: bool = False
    last_seen: float = 0

    def size(self):
        return len(self.buffer) + sum(len(part) + 128 for part in self.segments.values())


class FlowDecoder:
    def __init__(self, timeout=300, max_flows=10000, max_bytes=64 * 1024 * 1024):
        self.timeout, self.max_flows, self.max_bytes = timeout, max_flows, max_bytes
        self.flows, self.expiry, self.fragments = {}, [], {}
        self.bytes = 0

    def expire(self, now):
        while self.expiry and self.expiry[0][0] < now:
            _, key = heapq.heappop(self.expiry)
            flow = self.flows.get(key)
            if flow is None:
                continue
            if flow.last_seen + self.timeout < now:
                self.bytes -= flow.size()
                del self.flows[key]
            else:
                heapq.heappush(self.expiry, (flow.last_seen + self.timeout, key))
        for key in list(self.fragments):
            if self.fragments[key]['last'] + 30 < now:
                del self.fragments[key]
                self.warnings.append('Incomplete IPv4 fragment set expired')

    def feed(self, event, stream_id):
        self.warnings = []
        try:
            self._feed(event, stream_id)
        except (ValueError, dpkt.UnpackError) as error:
            # Malformed application data must not stop L3/L4 attack detection.
            self.warnings.append(str(error))
            key = (str(stream_id), event['src_ip'], event['dst_ip'], event['src_port'], event['dst_port'])
            self.flows.pop(key, None)
            fragment = event.get('fragment')
            if fragment:
                self.fragments.pop((str(stream_id), event['src_ip'], event['dst_ip'], fragment['id'], fragment['protocol']), None)
            self.bytes = sum(flow.size() for flow in self.flows.values())
            event['http_requests'], event['auth_protocols'], event['is_http'] = 0, [], False
        event['decode_warnings'] = list(self.warnings)

    def _feed(self, event, stream_id):
        self.expire(event['timestamp'])
        if 'fragment' in event:
            self._fragment(event, stream_id)
        event['http_requests'] = 0
        event['auth_protocols'] = []
        if event['protocol'] != 'TCP':
            return
        key = (str(stream_id), event['src_ip'], event['dst_ip'], event['src_port'], event['dst_port'])
        reverse = (key[0], key[2], key[1], key[4], key[3])
        flags = event['tcp_flags']
        if flags & 4:  # RST ends both directions.
            for item in (key, reverse):
                old = self.flows.pop(item, None)
                if old:
                    self.bytes -= old.size()
            return
        payload = bytes.fromhex(event['payload'])
        if not payload and not flags & 2:
            return
        flow = self.flows.get(key)
        sequence = event['tcp_seq']
        # A new SYN with a different ISN starts a new incarnation of the tuple.
        if flow is not None and flags & 2 and flow.initial_seq != sequence:
            self.bytes -= flow.size()
            del self.flows[key]
            flow = None
        if flow is None:
            if len(self.flows) >= self.max_flows:
                raise ValueError('TCP flow capacity exceeded')
            flow = self.flows[key] = Direction(last_seen=event['timestamp'])
            heapq.heappush(self.expiry, (event['timestamp'] + self.timeout, key))
        flow.last_seen = event['timestamp']
        before = flow.size()
        if not hasattr(flow, 'segment_heap'):  # Recover checkpoints from early development builds.
            flow.segment_heap = list(flow.segments)
            heapq.heapify(flow.segment_heap)
        if flags & 2:
            if flow.initial_seq is None:
                flow.initial_seq = sequence
                flow.next_seq = sequence + 1
            sequence += 1
        if flow.next_seq is None:
            flow.next_seq = sequence  # Midstream capture: earlier unseen bytes cannot be recovered.
        if payload:
            # Unwrap TCP sequence numbers relative to the contiguous cursor.
            delta = ((sequence - flow.next_seq + 2 ** 31) % (2 ** 32)) - 2 ** 31
            if delta < 0:
                payload = payload[-delta:]
                delta = 0
            if payload:
                start = flow.next_seq + delta
                previous = flow.segments.get(start, b'')
                if len(payload) > len(previous):
                    if start not in flow.segments:
                        heapq.heappush(flow.segment_heap, start)
                    flow.segments[start] = payload
            # Resolve overlapping/retransmitted segments deterministically.
            while flow.segment_heap:
                start = flow.segment_heap[0]
                if start > flow.next_seq:
                    break
                heapq.heappop(flow.segment_heap)
                data = flow.segments.pop(start)
                data = data[max(0, flow.next_seq - start):]
                flow.next_seq += len(data)
                flow.buffer += data
                self._application(flow, event)
        self.bytes += flow.size() - before
        if flow.size() > 1024 * 1024 or self.bytes > self.max_bytes:
            raise ValueError('TCP reassembly buffer limit exceeded')
        event['is_http'] = event['http_requests'] > 0

    def _application(self, flow, event):
        if not flow.protocol:
            port = event['dst_port']
            if port in ('80', '8000', '8080') or re.match(rb'^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE) ', flow.buffer):
                flow.protocol = 'HTTP'
            elif port == '21':
                flow.protocol = 'FTP'
            elif port == '23' or event['src_port'] == '23':
                flow.protocol = 'TELNET'
            elif port in ('445', '139'):
                flow.protocol = 'SMB'
            else:
                flow.buffer = b''
                return
        if flow.protocol == 'HTTP':
            self._http(flow, event)
        elif flow.protocol == 'FTP':
            while b'\n' in flow.buffer:
                line, flow.buffer = flow.buffer.split(b'\n', 1)
                if line.split(b' ', 1)[0].upper() in (b'USER', b'PASS'):
                    event['auth_protocols'].append('FTP')
        elif flow.protocol == 'TELNET':
            while True:
                match = re.search(rb'(login|username|user|password):', flow.buffer, re.I)
                if not match:
                    break
                event['auth_protocols'].append('TELNET')
                flow.buffer = flow.buffer[match.end():]
            flow.buffer = flow.buffer[-64:]
        elif flow.protocol == 'SMB':
            while len(flow.buffer) >= 4:
                length = int.from_bytes(flow.buffer[1:4], 'big')
                if length > 1024 * 1024:
                    raise ValueError('SMB message exceeds reassembly limit')
                if len(flow.buffer) < length + 4:
                    break
                message, flow.buffer = flow.buffer[4:4 + length], flow.buffer[4 + length:]
                if len(message) >= 20 and message[:4] == b'\xfeSMB':
                    if int.from_bytes(message[12:14], 'little') == 1 and not int.from_bytes(message[16:20], 'little') & 1:
                        event['auth_protocols'].append('SMB2')
                elif len(message) >= 10 and message[:4] == b'\xffSMB' and message[4] == 0x73 and not message[9] & 0x80:
                    event['auth_protocols'].append('SMB')

    @staticmethod
    def _http(flow, event):
        while flow.buffer:
            if flow.body_left:
                used = min(flow.body_left, len(flow.buffer))
                flow.buffer = flow.buffer[used:]
                flow.body_left -= used
                continue
            if flow.chunked:
                if flow.chunk_trailers:
                    if flow.buffer.startswith(b'\r\n'):
                        flow.buffer = flow.buffer[2:]
                    elif b'\r\n\r\n' in flow.buffer:
                        flow.buffer = flow.buffer.split(b'\r\n\r\n', 1)[1]
                    else:
                        return
                    flow.chunked = flow.chunk_trailers = False
                    continue
                if flow.chunk_left:
                    used = min(flow.chunk_left, len(flow.buffer))
                    flow.buffer = flow.buffer[used:]
                    flow.chunk_left -= used
                    continue
                if b'\r\n' not in flow.buffer:
                    return
                line, flow.buffer = flow.buffer.split(b'\r\n', 1)
                try:
                    length = int(line.split(b';', 1)[0], 16)
                except ValueError:
                    raise ValueError('Malformed HTTP chunk size')
                if length < 0:
                    raise ValueError('Negative HTTP chunk size')
                if length:
                    flow.chunk_left = length + 2  # Data and its trailing CRLF.
                else:
                    flow.chunk_trailers = True
                continue
            boundary = flow.buffer.find(b'\r\n\r\n')
            if boundary < 0:
                if len(flow.buffer) > 65536:
                    raise ValueError('HTTP headers exceed limit')
                return
            head, flow.buffer = flow.buffer[:boundary], flow.buffer[boundary + 4:]
            lines = head.split(b'\r\n')
            if not re.fullmatch(rb'[A-Z]+ [^\r\n]+ HTTP/1\.[01]', lines[0]):
                raise ValueError('Unsupported or malformed HTTP request')
            headers = {}
            for line in lines[1:]:
                name, separator, value = line.partition(b':')
                if not separator:
                    raise ValueError('Malformed HTTP header')
                name = name.strip().lower()
                if name in (b'content-length', b'transfer-encoding') and name in headers:
                    raise ValueError('Ambiguous HTTP message framing')
                headers[name] = value.strip().lower()
            if b'content-length' in headers and b'transfer-encoding' in headers:
                raise ValueError('Ambiguous HTTP message framing')
            if b'transfer-encoding' in headers and headers[b'transfer-encoding'] != b'chunked':
                raise ValueError('Unsupported HTTP transfer encoding')
            flow.chunked = headers.get(b'transfer-encoding') == b'chunked'
            flow.body_left = int(headers.get(b'content-length', b'0'))
            if flow.body_left < 0:
                raise ValueError('Negative HTTP content length')
            event['http_requests'] += 1
            if headers.get(b'authorization', b'').startswith(b'basic '):
                event['auth_protocols'].append('HTTP Basic')

    def _fragment(self, event, stream_id):
        fragment = event['fragment']
        key = (str(stream_id), event['src_ip'], event['dst_ip'], fragment['id'], fragment['protocol'])
        state = self.fragments.setdefault(key, {'parts': {}, 'total': None, 'last': event['timestamp']})
        state['last'] = event['timestamp']
        offset, data = fragment['offset'], bytes.fromhex(fragment['payload'])
        if len(self.fragments) > 1000 or offset + len(data) > 65535:
            raise ValueError('IPv4 fragment capacity exceeded')
        for start, previous in state['parts'].items():
            if max(start, offset) < min(start + len(previous), offset + len(data)):
                if start == offset and previous == data:
                    return
                raise ValueError('Ambiguous overlapping IPv4 fragments')
        state['parts'][offset] = data
        if not fragment['more']:
            state['total'] = offset + len(data)
        cursor, parts = 0, []
        for start in sorted(state['parts']):
            if start != cursor:
                return
            parts.append(state['parts'][start])
            cursor += len(parts[-1])
        if state['total'] is None or cursor != state['total']:
            return
        payload = b''.join(parts)
        del self.fragments[key]
        if fragment['protocol'] == 6:
            add_transport(event, dpkt.tcp.TCP(payload))
        elif fragment['protocol'] == 17:
            add_transport(event, dpkt.udp.UDP(payload))
