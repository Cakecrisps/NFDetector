"""Bounded, stateless L2/L3/L4 PCAP parsing. Application state lives downstream."""
import hashlib
import ipaddress
import json
import math
import os
import struct
from pathlib import Path

import dpkt


MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
          b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')
MAX_FRAMES = 500_000
MAX_ARTIFACT = 256 * 1024 * 1024


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_layout(handle):
    """Reject capture layouts dpkt would partially ignore, and truncated frames."""
    magic = handle.read(4)
    handle.seek(0)
    if magic == MAGICS[-1]:
        sections, interfaces = 0, 0
        order = None
        while True:
            header = handle.read(12)
            if not header:
                break
            if len(header) != 12:
                raise ValueError('Truncated PCAPNG block')
            if header[:4] == MAGICS[-1]:
                sections += 1
                if sections > 1:
                    raise ValueError('Multiple PCAPNG sections are not supported')
                order = '<' if header[8:12] == b'\x4d\x3c\x2b\x1a' else '>' if header[8:12] == b'\x1a\x2b\x3c\x4d' else None
            if order is None:
                raise ValueError('Invalid PCAPNG byte-order marker')
            kind, size = struct.unpack(order + 'II', header[:8])
            if size < 16 or size % 4 or size > 32 * 1024 * 1024:
                raise ValueError('Invalid PCAPNG block length')
            body = header[8:] + handle.read(size - 12)
            if len(body) != size - 8 or struct.unpack(order + 'I', body[-4:])[0] != size:
                raise ValueError('Truncated or inconsistent PCAPNG block')
            if kind == 1:
                interfaces += 1
                if interfaces > 1:
                    raise ValueError('Use one interface per PCAPNG chunk')
            elif kind == 6:
                if len(body) < 24 or struct.unpack(order + 'I', body[:4])[0] != 0:
                    raise ValueError('Invalid PCAPNG packet interface')
                caplen, length = struct.unpack(order + 'II', body[12:20])
                if caplen != length:
                    raise ValueError('Truncated capture frames are not supported')
            elif kind in (2, 3):
                raise ValueError('Use PCAPNG Enhanced Packet Blocks')
    elif magic in MAGICS[:-1]:
        order = '<' if magic in (MAGICS[0], MAGICS[2]) else '>'
        if len(handle.read(24)) != 24:
            raise ValueError('Truncated PCAP header')
        while True:
            header = handle.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError('Truncated PCAP record header')
            caplen, length = struct.unpack(order + 'II', header[8:])
            if caplen != length or caplen > 32 * 1024 * 1024:
                raise ValueError('Truncated or oversized capture frame')
            if len(handle.read(caplen)) != caplen:
                raise ValueError('Truncated PCAP record')
    else:
        raise ValueError('Expected PCAP or PCAPNG')
    handle.seek(0)


def reader(handle):
    magic = handle.read(4)
    handle.seek(0)
    if magic not in MAGICS:
        raise ValueError('Expected PCAP or PCAPNG')
    return dpkt.pcapng.Reader(handle) if magic == MAGICS[-1] else dpkt.pcap.Reader(handle)


def ip_packet(frame, linktype):
    if linktype == dpkt.pcap.DLT_EN10MB:
        return dpkt.ethernet.Ethernet(frame).data
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(frame).data
    if linktype in (dpkt.pcap.DLT_RAW, 101, 228, 229):
        return dpkt.ip6.IP6(frame) if frame and frame[0] >> 4 == 6 else dpkt.ip.IP(frame)
    if linktype == 276:  # Linux cooked capture v2.
        if len(frame) < 20:
            raise ValueError('Truncated Linux SLL2 frame')
        protocol = int.from_bytes(frame[:2], 'big')
        return dpkt.ip.IP(frame[20:]) if protocol == 0x0800 else dpkt.ip6.IP6(frame[20:]) if protocol == 0x86dd else None
    raise ValueError(f'Unsupported capture link type: {linktype}')


def parse_capture(source, destination):
    """Publish a sorted JSONL artifact only after the entire capture validates."""
    events = []
    with open(source, 'rb') as handle:
        validate_layout(handle)
        capture = reader(handle)
        for index, (timestamp, frame) in enumerate(capture):
            if index >= MAX_FRAMES:
                raise ValueError('Capture exceeds parser frame limit')
            timestamp = float(timestamp)
            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError('Invalid capture timestamp')
            info = dict(timestamp=timestamp, packet_index=index, length=len(frame), src_ip=None, dst_ip=None,
                        src_port=None, dst_port=None, is_syn=False, is_syn_ack=False, is_http=False,
                        protocol='OTHER', payload='', tcp_seq=None, tcp_flags=0)
            ip = ip_packet(frame, capture.datalink())
            if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                info['src_ip'], info['dst_ip'] = str(ipaddress.ip_address(ip.src)), str(ipaddress.ip_address(ip.dst))
                if isinstance(ip, dpkt.ip.IP) and (ip.mf or ip.offset):
                    # Preserve fragments for stateful reassembly across files/workers.
                    info['fragment'] = dict(id=ip.id, offset=ip.offset * 8, more=bool(ip.mf),
                                            protocol=ip.p, payload=bytes(ip.data).hex())
                elif isinstance(ip, dpkt.ip6.IP6) and 44 in ip.extension_hdrs:
                    raise ValueError('IPv6 fragmentation is not supported by this parser version')
                else:
                    add_transport(info, ip.data)
            events.append(info)
    events.sort(key=lambda info: (info['timestamp'], info['packet_index']))
    path = Path(destination)
    temporary = path.with_suffix('.tmp')
    size = 0
    try:
        with temporary.open('wb') as handle:
            for info in events:
                line = json.dumps(info, separators=(',', ':')).encode() + b'\n'
                size += len(line)
                if size > MAX_ARTIFACT:
                    raise ValueError('Parsed artifact exceeds size limit')
                handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return dict(path=str(path), frames=len(events), first_ts=events[0]['timestamp'] if events else None,
                last_ts=events[-1]['timestamp'] if events else None)


def add_transport(info, transport):
    if isinstance(transport, dpkt.tcp.TCP):
        flags = transport.flags
        info.update(protocol='TCP', src_port=str(transport.sport), dst_port=str(transport.dport),
                    is_syn=bool(flags & 2) and not bool(flags & 16), is_syn_ack=bool(flags & 2) and bool(flags & 16),
                    tcp_flags=flags, tcp_seq=transport.seq, payload=bytes(transport.data).hex())
    elif isinstance(transport, dpkt.udp.UDP):
        info.update(protocol='UDP', src_port=str(transport.sport), dst_port=str(transport.dport))


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()
