
import dpkt
import pytest

from distributed.capture import parse_capture
from distributed.flows import FlowDecoder


def event(payload=b'', seq=101, timestamp=1000, flags=16, port='80'):
    return dict(timestamp=timestamp, packet_index=0, src_ip='10.0.0.1', dst_ip='192.168.1.1',
                src_port='5000', dst_port=port, protocol='TCP', tcp_flags=flags,
                tcp_seq=seq, payload=payload.hex(), is_syn=bool(flags & 2), is_syn_ack=False, is_http=False)


def feed(decoder, payload=b'', **kwargs):
    value = event(payload, **kwargs)
    decoder.feed(value, 'stream')
    return value


def test_retransmission_does_not_duplicate_http_request():
    decoder = FlowDecoder()
    payload = b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'
    assert feed(decoder, payload)['http_requests'] == 1
    assert feed(decoder, payload)['http_requests'] == 0


def test_out_of_order_tcp_segments_are_assembled_after_syn():
    decoder = FlowDecoder()
    feed(decoder, seq=100, flags=2)
    prefix, suffix = b'GET / HTTP/1.1\r\n', b'Host: x\r\n\r\n'
    assert feed(decoder, suffix, seq=101 + len(prefix))['http_requests'] == 0
    assert feed(decoder, prefix)['http_requests'] == 1
    assert not feed(decoder, prefix)['decode_warnings']


def test_tcp_sequence_wrap():
    decoder = FlowDecoder()
    initial = 2 ** 32 - 10
    feed(decoder, seq=initial, flags=2)
    prefix, suffix = b'GET / HTTP/1.1\r\n', b'Host: x\r\n\r\n'
    assert feed(decoder, prefix, seq=initial + 1)['http_requests'] == 0
    assert feed(decoder, suffix, seq=(initial + 1 + len(prefix)) % (2 ** 32))['http_requests'] == 1


def test_multiple_http_requests_in_one_segment():
    decoder = FlowDecoder()
    payload = b'GET / HTTP/1.1\r\nAuthorization: Basic abc\r\n\r\n'
    value = feed(decoder, payload * 3)
    assert value['http_requests'] == 3
    assert value['auth_protocols'] == ['HTTP Basic'] * 3


def test_http_content_length_body_is_not_parsed_as_a_request():
    decoder = FlowDecoder()
    fake = b'GET /fake HTTP/1.1\r\n\r\n'
    head = f'POST / HTTP/1.1\r\nContent-Length: {len(fake)}\r\n\r\n'.encode()
    real = b'GET /real HTTP/1.1\r\n\r\n'
    assert feed(decoder, head + fake + real)['http_requests'] == 2


def test_http_chunked_body_and_trailers():
    decoder = FlowDecoder()
    payload = (b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'
               b'3\r\nabc\r\n0\r\nX-Trailer: value\r\n\r\nGET / HTTP/1.1\r\n\r\n')
    assert feed(decoder, payload)['http_requests'] == 2


def test_malformed_http_is_reported_without_stopping_packet_detection():
    decoder = FlowDecoder()
    value = feed(decoder, b'bad HTTP message\r\n\r\n')
    assert value['decode_warnings']
    assert value['src_ip'] == '10.0.0.1'
    assert not decoder.flows and decoder.bytes == 0


def test_ftp_commands_split_across_segments():
    decoder = FlowDecoder()
    prefix = b'USER test\r\nPA'
    assert feed(decoder, prefix, port='21')['auth_protocols'] == ['FTP']
    assert feed(decoder, b'SS secret\r\n', seq=101 + len(prefix), port='21')['auth_protocols'] == ['FTP']


def test_ssh_identification_split_reordered_and_restored():
    import pickle
    decoder = FlowDecoder()
    banner = b'SSH-2.0-OpenSSH_9.2\r\n'
    feed(decoder, seq=100, flags=2, port='22')
    assert feed(decoder, banner[5:], seq=106, port='22')['ssh_greetings'] == 0
    decoder = pickle.loads(pickle.dumps(decoder))
    value = feed(decoder, banner[:5], port='22')
    assert value['ssh_greetings'] == 1
    assert value['auth_protocols'] == []
    assert feed(decoder, banner, port='22')['ssh_greetings'] == 0
    assert feed(decoder, banner, seq=101 + len(banner), port='22')['ssh_greetings'] == 0


def test_ssh_new_connection_on_reused_tuple_counts_again():
    decoder = FlowDecoder()
    for sequence in (100, 500):
        feed(decoder, seq=sequence, flags=2, port='22')
        assert feed(decoder, b'SSH-2.0-client\r\n', seq=sequence + 1, port='22')['ssh_greetings'] == 1


@pytest.mark.parametrize('payload', [b'GET / HTTP/1.1\r\n\r\n', b'\x00\xffencrypted\n',
                                     b'SSH-2.0-\r\n', b'SSH-9.9-client\r\n'])
def test_non_ssh_payload_on_ssh_port_is_not_a_greeting(payload):
    assert feed(FlowDecoder(), payload, port='22')['ssh_greetings'] == 0


def test_ssh_identification_length_is_bounded():
    value = feed(FlowDecoder(), b'SSH-2.0-' + b'x' * 250, port='22')
    assert value['ssh_greetings'] == 0
    assert value['decode_warnings']


def test_ssh_ports_are_configurable_and_server_banner_is_not_counted():
    banner = b'SSH-2.0-client\r\n'
    assert feed(FlowDecoder(), banner, port='2222')['ssh_greetings'] == 0
    assert feed(FlowDecoder(ssh_ports=[2222]), banner, port='2222')['ssh_greetings'] == 1
    value = event(banner, port='50000')
    value['src_port'] = '22'
    FlowDecoder().feed(value, 'stream')
    assert value['ssh_greetings'] == 0


def test_smb2_session_setup_split_across_segments():
    decoder = FlowDecoder()
    message = bytearray(64)
    message[:4], message[12:14] = b'\xfeSMB', (1).to_bytes(2, 'little')
    payload = b'\x00' + len(message).to_bytes(3, 'big') + message
    assert feed(decoder, payload[:20], port='445')['auth_protocols'] == []
    assert feed(decoder, payload[20:], seq=121, port='445')['auth_protocols'] == ['SMB2']


def test_flow_memory_is_released_on_expiry():
    decoder = FlowDecoder(timeout=1)
    feed(decoder, b'GET /')
    assert decoder.bytes
    feed(decoder, seq=200, timestamp=1002, flags=16, port='443')
    assert not decoder.flows and decoder.bytes == 0


def test_flow_limit_produces_warning():
    decoder = FlowDecoder(max_flows=0)
    value = feed(decoder, b'GET /')
    assert value['decode_warnings'] == ['TCP flow capacity exceeded']


def test_capture_rejects_invalid_or_unsupported_format(tmp_path):
    source = tmp_path / 'invalid.pcap'
    source.write_bytes(b'not a PCAP')
    with pytest.raises(ValueError, match='PCAP'):
        parse_capture(source, tmp_path / 'parsed.jsonl')
    assert not (tmp_path / 'parsed.jsonl').exists()
