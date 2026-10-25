"""Real PostgreSQL/API integration; run against an isolated disposable database.

NF_TEST_DATABASE_URL=postgresql://nfdetect@localhost:55439/nfdetect python -m pytest tests/test_distributed.py
Each test owns a separate temporary schema and removes only that schema.
"""
import hashlib
import io
import json
import os
import socket
import uuid
from pathlib import Path

import dpkt
import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo

from distributed.api import create_app
from distributed.capture import parse_capture
from distributed.settings import Settings
from distributed.store import LeaseLost, Store
from distributed.workers import decode_state, detector_once, parser_once


@pytest.fixture
def system(tmp_path):
    url = os.environ.get('NF_TEST_DATABASE_URL')
    if not url:
        pytest.skip('Set NF_TEST_DATABASE_URL to a disposable PostgreSQL instance')
    schema = 'nf_test_' + uuid.uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA {schema}')
    dsn = make_conninfo(url, options=f'-c search_path={schema}')
    rules = json.loads((Path(__file__).resolve().parents[1] / 'rules.json').read_text())
    rules['reaction']['out'] = []
    rules['suspicious_ips']['enabled'] = False
    rules['C2_analysys']['enabled'] = False
    rules['ddos']['1ip']['request_limit'] = 3
    rules['ddos']['nip']['request_limit'] = 4
    rules['flood']['HTTP']['request_rate_limit'] = 2
    rules['brute_force'].update(auth_proto=['FTP', 'HTTP Basic', 'SMB2'], tryes_limit=2)
    rules_path = tmp_path / 'rules.json'
    rules_path.write_text(json.dumps(rules))
    ips = tmp_path / 'ips.txt'
    ips.write_text('192.168.1.1\n')
    settings = Settings(dsn, tmp_path / 'data', rules_path, ips)
    settings.prepare()
    store = Store(settings)
    try:
        with TestClient(create_app(settings)) as client:
            _, token = store.issue_key('test-agent', 'lab')
            yield client, store, {'Authorization': f'Bearer {token}'}
    finally:
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f'DROP SCHEMA {schema} CASCADE')


def tcp_frame(src='10.0.0.1', dst='192.168.1.1', sport=5000, dport=80, seq=100, flags=dpkt.tcp.TH_ACK, payload=b''):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, flags=flags, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x00' * 6, dst=b'\x01' * 6, type=0x0800, data=ip))


def capture(records, pcapng=False):
    output = io.BytesIO()
    writer = dpkt.pcapng.Writer(output) if pcapng else dpkt.pcap.Writer(output)
    for timestamp, frame in records:
        writer.writepkt(frame, ts=timestamp)
    return output.getvalue()


def register(client, headers, started_at=1000):
    response = client.post('/v1/streams', headers=headers, json={'interface': 'eth0', 'started_at': started_at})
    assert response.status_code == 200, response.text
    return response.json()['stream_id']


def upload(client, headers, stream_id, sequence, content):
    return client.put(f'/v1/streams/{stream_id}/chunks/{sequence}', content=content,
                      headers=dict(headers, **{'Content-Type': 'application/octet-stream',
                                                'X-Content-SHA256': hashlib.sha256(content).hexdigest()}))


def seal(client, headers, stream_id, last):
    response = client.post(f'/v1/streams/{stream_id}/seal', headers=headers, json={'last_sequence': last})
    assert response.status_code == 200, response.text


def alarms(store, prefix):
    with store.connect() as conn:
        return conn.execute('SELECT * FROM nf_events WHERE reason LIKE %s ORDER BY timestamp', (prefix + '%',)).fetchall()


def drain(store):
    # Each call reloads the committed checkpoint; no in-process cache hides restart bugs.
    for _ in range(100):
        if not detector_once(store, 'reducer-' + uuid.uuid4().hex):
            break
    with store.connect() as conn:
        error = conn.execute("SELECT error FROM nf_domains WHERE id='lab'").fetchone()['error']
    assert error is None, error


def test_attack_spanning_files_parsed_by_different_workers_out_of_order(system):
    client, store, headers = system
    stream = register(client, headers)
    one = capture([(1000, tcp_frame()), (1000.1, tcp_frame())])
    two = capture([(1000.2, tcp_frame()), (1000.3, tcp_frame())])
    assert upload(client, headers, stream, 0, one).status_code == 201
    assert upload(client, headers, stream, 1, two).status_code == 201
    seal(client, headers, stream, 1)
    job_one = store.claim_chunk('parser-A')
    job_two = store.claim_chunk('parser-B')
    assert job_one['id'] != job_two['id']
    parser_once(store, 'parser-B', job_two)
    drain(store)
    assert not alarms(store, 'DDoS_SINGLE_IP')
    parser_once(store, 'parser-A', job_one)
    drain(store)
    found = alarms(store, 'DDoS_SINGLE_IP')
    assert len(found) == 1 and found[0]['sequence'] == 1
    # An arbitrary number of extra polls does not duplicate already-committed alarms.
    drain(store)
    assert len(alarms(store, 'DDoS_SINGLE_IP')) == 1


def test_distributed_attack_merges_two_agents(system):
    client, store, first = system
    _, token = store.issue_key('another-sensor', 'lab')
    second = {'Authorization': f'Bearer {token}'}
    streams = [register(client, first), register(client, second)]
    for headers, stream, source in zip([first, second], streams, ['10.0.0.1', '10.0.0.2']):
        body = capture([(1000, tcp_frame(src=source)), (1000.1, tcp_frame(src=source))])
        assert upload(client, headers, stream, 0, body).status_code == 201
        seal(client, headers, stream, 0)
        parser_once(store, 'parser-' + source)
    drain(store)
    assert {row['source'] for row in alarms(store, 'DDoS_MULTI_IP')} == {'10.0.0.1', '10.0.0.2'}
    assert not alarms(store, 'DDoS_SINGLE_IP')


def test_tcp_http_and_authentication_survive_file_boundary(system):
    client, store, headers = system
    stream = register(client, headers)
    prefix = b'GET / HTTP/1.1\r\nHost: example.test\r\nAuthor'
    suffix = b'ization: Basic dXNlcjpwYXNz\r\n\r\n'
    full = prefix + suffix
    one = capture([(1000, tcp_frame(seq=100, flags=dpkt.tcp.TH_SYN)),
                   (1000.1, tcp_frame(seq=101, payload=prefix))])
    two = capture([(1000.2, tcp_frame(seq=101 + len(prefix), payload=suffix)),
                   (1000.3, tcp_frame(seq=101 + len(full), payload=full))], pcapng=True)
    for index, body in enumerate([one, two]):
        assert upload(client, headers, stream, index, body).status_code == 201
    seal(client, headers, stream, 1)
    a, b = store.claim_chunk('A'), store.claim_chunk('B')
    parser_once(store, 'B', b)
    parser_once(store, 'A', a)
    drain(store)
    assert len(alarms(store, 'HTTP_FLOOD')) == 1
    assert len(alarms(store, 'BRUTEFORCE_HTTP Basic')) == 1
    # The external smoke-test must inspect combined kinds: DDOS keeps only
    # one representative reason even when HTTP_FLOOD also contributed.
    from benchmarks.compose_smoke import detected_kinds
    incidents = client.get('/v1/events', headers=headers).json()['events']
    assert len(incidents) == 2
    assert {'DDoS_SINGLE_IP', 'HTTP_FLOOD', 'BRUTEFORCE_HTTP Basic'} <= detected_kinds(incidents)


def test_checkpoint_restores_after_every_single_packet(system):
    client, store, headers = system
    store.settings.batch_size = 1
    stream = register(client, headers)
    body = capture([(1000 + i / 10, tcp_frame()) for i in range(5)])
    assert upload(client, headers, stream, 0, body).status_code == 201
    seal(client, headers, stream, 0)
    parser_once(store, 'parser')
    drain(store)
    assert len(alarms(store, 'DDoS_SINGLE_IP')) == 1
    with store.connect() as conn:
        state = decode_state(conn.execute("SELECT checkpoint FROM nf_domains WHERE id='lab'").fetchone()['checkpoint'], store.settings)
    assert state['detector'].stats['total'] == 5
    assert state['cursors'][stream]['sequence'] == 1


def test_ssh_greetings_across_files_workers_and_checkpoint(system):
    client, store, headers = system
    rules = json.loads(store.settings.rules_path.read_text())
    rules['brute_force']['auth_proto'].append('SSH')
    store.settings.rules_path.write_text(json.dumps(rules))
    store.settings.batch_size = 1
    stream = register(client, headers)
    banner = b'SSH-2.0-OpenSSH_9.2\r\n'
    one = capture([(1000, tcp_frame(dport=22, flags=dpkt.tcp.TH_SYN)),
                   (1000.1, tcp_frame(dport=22, seq=101, payload=banner)),
                   (1000.2, tcp_frame(dport=22, sport=5001, flags=dpkt.tcp.TH_SYN)),
                   (1000.3, tcp_frame(dport=22, sport=5001, seq=101, payload=banner[:5]))])
    two = capture([(1000.4, tcp_frame(dport=22, sport=5001, seq=106, payload=banner[5:])),
                   (1000.5, tcp_frame(dport=22, sport=5001, seq=101, payload=banner))])
    for index, body in enumerate([one, two]):
        assert upload(client, headers, stream, index, body).status_code == 201
    seal(client, headers, stream, 1)
    a, b = store.claim_chunk('A'), store.claim_chunk('B')
    parser_once(store, 'B', b)
    drain(store)
    assert not alarms(store, 'BRUTEFORCE_SSH_HANDSHAKES')
    parser_once(store, 'A', a)
    drain(store)
    found = alarms(store, 'BRUTEFORCE_SSH_HANDSHAKES')
    assert len(found) == 1 and found[0]['sequence'] == 1
    drain(store)
    assert len(alarms(store, 'BRUTEFORCE_SSH_HANDSHAKES')) == 1


def test_duplicate_delivery_is_idempotent_and_conflict_is_rejected(system):
    client, store, headers = system
    stream = register(client, headers)
    body = capture([(1000, tcp_frame())])
    assert upload(client, headers, stream, 0, body).status_code == 201
    assert upload(client, headers, stream, 0, body).status_code == 200
    different = capture([(1000.1, tcp_frame())])
    assert upload(client, headers, stream, 0, different).status_code == 409
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) AS n FROM nf_chunks').fetchone()['n'] == 1
    assert len(list((store.settings.data_dir / 'captures').iterdir())) == 1
    assert not list((store.settings.data_dir / 'incoming').iterdir())


def test_revocation_and_stream_ownership(system):
    client, store, headers = system
    stream = register(client, headers)
    agent_id, token = store.issue_key('different-agent', 'other-domain')
    other = {'Authorization': 'Bearer ' + token}
    assert client.get(f'/v1/streams/{stream}/status', headers=other).status_code == 404
    assert client.post('/v1/streams', json={'interface': 'eth0', 'started_at': 1000}).status_code == 401
    with store.connect() as conn:
        conn.execute('UPDATE nf_agents SET revoked=true WHERE id=%s', (agent_id,))
    assert client.get('/v1/events', headers=other).status_code == 401


def test_wrong_hash_and_oversized_upload_are_not_accepted(system):
    client, store, headers = system
    stream = register(client, headers)
    body = capture([(1000, tcp_frame())])
    invalid = dict(headers, **{'Content-Type': 'application/octet-stream', 'X-Content-SHA256': '0' * 64})
    assert client.put(f'/v1/streams/{stream}/chunks/0', content=body, headers=invalid).status_code == 400
    store.settings.max_upload = len(body) - 1
    assert upload(client, headers, stream, 0, body).status_code == 413
    assert not list((store.settings.data_dir / 'incoming').iterdir())


def test_seal_requires_continuous_sequence(system):
    client, store, headers = system
    stream = register(client, headers)
    assert upload(client, headers, stream, 1, capture([(1000, tcp_frame())])).status_code == 201
    assert client.post(f'/v1/streams/{stream}/seal', headers=headers, json={'last_sequence': 1}).status_code == 409


def test_parser_lease_fences_an_old_worker(system):
    client, store, headers = system
    stream = register(client, headers)
    assert upload(client, headers, stream, 0, capture([(1000, tcp_frame())])).status_code == 201
    old = store.claim_chunk('old-worker')
    with store.connect() as conn:
        conn.execute("UPDATE nf_chunks SET lease_until=clock_timestamp()-interval '1 second' WHERE id=%s", (old['id'],))
    new = store.claim_chunk('new-worker')
    assert new['generation'] > old['generation']
    result = parse_capture(old['path'], store.settings.data_dir / 'parsed' / 'test.jsonl')
    with pytest.raises(LeaseLost):
        store.finish_chunk(old, result)
    parser_once(store, 'new-worker', new)
    assert store.chunk(stream, 0)['status'] == 'ready'


def test_detector_lease_fences_an_old_worker(system):
    client, store, headers = system
    stream = register(client, headers)
    assert upload(client, headers, stream, 0, capture([(1000, tcp_frame())])).status_code == 201
    parser_once(store, 'parser')
    old = store.claim_domain('old-reducer')
    with store.connect() as conn:
        conn.execute("UPDATE nf_domains SET lease_until=clock_timestamp()-interval '1 second' WHERE id='lab'")
    new = store.claim_domain('new-reducer')
    with pytest.raises(LeaseLost):
        store.commit_domain(old, b'bad', 'bad', [], 1000)
    assert new['generation'] > old['generation']


def test_backward_chunk_range_fails_visibly(system):
    client, store, headers = system
    stream = register(client, headers)
    for index, timestamp in enumerate([1001, 1000]):
        assert upload(client, headers, stream, index, capture([(timestamp, tcp_frame())])).status_code == 201
        parser_once(store, f'parser-{index}')
    seal(client, headers, stream, 1)
    detector_once(store, 'first')
    detector_once(store, 'second')
    status = client.get(f'/v1/streams/{stream}/status', headers=headers).json()
    assert 'backwards' in status['detector']['error']


def test_bad_capture_is_visible_and_not_skipped(system):
    client, store, headers = system
    stream = register(client, headers)
    # A valid magic passes inexpensive ingress validation; full parsing must fail.
    assert upload(client, headers, stream, 0, b'\xd4\xc3\xb2\xa1' + b'broken').status_code == 201
    parser_once(store, 'parser')
    status = client.get(f'/v1/streams/{stream}/status', headers=headers).json()
    assert status['chunks'][0]['status'] == 'error'
    assert status['chunks'][0]['error']


def test_agent_retains_file_until_ack_and_retries_lost_response(system, tmp_path):
    import requests
    from distributed.agent import Uploader
    client, store, headers = system
    key = tmp_path / 'agent.key'
    key.write_text(headers['Authorization'].removeprefix('Bearer '))
    key.chmod(0o600)
    path = tmp_path / 'owned.pcap'
    path.write_bytes(capture([(1000, tcp_frame())]))
    state = tmp_path / 'spool.json'

    class Bridge:
        lost = False
        def request(self, method, url, **kwargs):
            kwargs.pop('verify', None)
            kwargs.pop('timeout', None)
            kwargs['follow_redirects'] = kwargs.pop('allow_redirects', False)
            data = kwargs.pop('data', None)
            kwargs['headers'] = dict(headers, **kwargs.get('headers', {}))
            if data is not None:
                kwargs['content'] = data.read()
            response = client.request(method, url.removeprefix('https://test'), **kwargs)
            if method == 'PUT' and not self.lost:
                self.lost = True
                raise requests.ConnectionError('Response lost after server commit')
            return response

    uploader = Uploader('https://test', key, state, 'eth0')
    uploader.session = Bridge()
    uploader.add(path, owned=True)
    with pytest.raises(requests.ConnectionError):
        uploader.send_pending()
    assert path.exists()
    restarted = Uploader('https://test', key, state, 'eth0')
    restarted.session = uploader.session
    restarted.send_pending()
    assert not path.exists()
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) AS n FROM nf_chunks').fetchone()['n'] == 1
