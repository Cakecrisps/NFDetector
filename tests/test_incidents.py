"""Incident lifecycle using the actual PCAP queue, checkpoints and PostgreSQL."""
import json
import uuid
from datetime import datetime, timezone

from distributed.workers import detector_once, parser_once
from distributed.web_metrics import events, overview
from test_distributed import system, capture, tcp_frame, register, upload, seal, drain


def incidents(store):
    with store.connect() as conn:
        return conn.execute('SELECT * FROM nf_incidents ORDER BY first_seen,id').fetchall()


def test_repeated_crossings_across_files_are_one_incident(system):
    client, store, headers = system
    store.settings.batch_size = 1
    stream = register(client, headers)
    for sequence, start in enumerate((1000, 1002, 1004)):
        body = capture([(start + i / 10, tcp_frame()) for i in range(3)])
        assert upload(client, headers, stream, sequence, body).status_code == 201
    seal(client, headers, stream, 2)
    jobs = [store.claim_chunk(str(i)) for i in range(3)]
    for i in (2, 1, 0):
        parser_once(store, str(i), jobs[i])
        drain(store)
    found = incidents(store)
    assert len(found) == 1
    row = found[0]
    assert row['first_seen'] == 1000.2 and row['last_seen'] == 1004.2
    assert row['signal_count'] == 3 and row['kind'] == 'DDOS'
    assert row['close_reason'] == 'capture_ended'
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) AS n FROM nf_events').fetchone()['n'] == 3
        assert conn.execute('SELECT count(*) AS n FROM nf_incident_outbox').fetchone()['n'] == 1
        assert conn.execute('SELECT count(*) AS n FROM nf_events WHERE incident_id IS NULL').fetchone()['n'] == 0
    drain(store)
    assert incidents(store)[0]['signal_count'] == 3
    result = events(store, kind='DDoS_SINGLE_IP', query='10.0.0.1')
    assert result['total'] == 1 and result['events'][0]['duration_seconds'] == 4
    assert overview(store, as_of=datetime.fromtimestamp(1010, timezone.utc))['alerts']['total'] == 1


def test_continuous_hour_extends_duration_without_new_threshold_alarms(system):
    client, store, headers = system
    store.settings.batch_size = 1000
    stream = register(client, headers)
    records = [(1000 + i / 4, tcp_frame()) for i in range(14403)]
    records.append((5001, tcp_frame(dst='8.8.8.8')))
    assert upload(client, headers, stream, 0, capture(records)).status_code == 201
    seal(client, headers, stream, 0)
    parser_once(store, 'parser')
    drain(store)
    row, = incidents(store)
    assert row['first_seen'] == 1000.5 and row['last_seen'] == 4600.5
    assert row['last_seen'] - row['first_seen'] == 3600
    assert row['signal_count'] == 1  # Duration comes from ongoing activity.
    assert row['close_reason'] == 'quiet' and row['closed_at'] == row['last_seen']


def test_pause_longer_than_gap_creates_new_incident(system):
    client, store, headers = system
    store.settings.incident_gap_seconds = 5
    stream = register(client, headers)
    body = capture([(t, tcp_frame()) for t in (1000, 1000, 1000, 1010, 1010, 1010)])
    assert upload(client, headers, stream, 0, body).status_code == 201
    seal(client, headers, stream, 0); parser_once(store, 'parser'); drain(store)
    found = incidents(store)
    assert len(found) == 2
    assert [r['signal_count'] for r in found] == [1, 1]
    assert found[0]['closed_at'] == 1000


def test_sources_and_flood_rules_merge_per_target_across_sensors(system):
    client, store, first = system
    _, key = store.issue_key('other-sensor', 'lab')
    second = {'Authorization': 'Bearer ' + key}
    for headers, source in ((first, '10.0.0.1'), (second, '10.0.0.2')):
        stream = register(client, headers)
        body = capture([(1000 + i / 10, tcp_frame(src=source)) for i in range(3)])
        assert upload(client, headers, stream, 0, body).status_code == 201
        seal(client, headers, stream, 0); parser_once(store, 'parser')
    drain(store)
    row, = incidents(store)
    assert set(row['sources']) == {'10.0.0.1', '10.0.0.2'}
    assert set(row['kinds']) == {'DDoS_SINGLE_IP', 'DDoS_MULTI_IP'}
    for headers in (first, second):
        result = client.get('/v1/events', headers=headers).json()['events']
        assert len(result) == 1 and result[0]['id'] == row['id']
    _, key = store.issue_key('nonparticipant', 'lab')
    assert client.get('/v1/events', headers={'Authorization': 'Bearer ' + key}).json()['events'] == []
    assert events(store, query='other-sensor')['total'] == 1


def test_different_targets_are_separate_incidents(system):
    client, store, headers = system
    store.settings.protected_path.write_text('192.168.1.1\n192.168.1.2\n')
    stream = register(client, headers)
    records = [(1000 + i / 100, tcp_frame(dst=target))
               for target in ('192.168.1.1', '192.168.1.2') for i in range(3)]
    assert upload(client, headers, stream, 0, capture(sorted(records))).status_code == 201
    seal(client, headers, stream, 0); parser_once(store, 'parser'); drain(store)
    assert {r['target'] for r in incidents(store)} == {'192.168.1.1', '192.168.1.2'}


def test_ssh_sources_ports_and_flood_are_not_combined(system):
    client, store, headers = system
    rules = json.loads(store.settings.rules_path.read_text())
    rules['brute_force']['auth_proto'].append('SSH')
    rules['brute_force']['ssh_handshakes']['ports'] = [22, 2222]
    store.settings.rules_path.write_text(json.dumps(rules))
    stream = register(client, headers)
    banner = b'SSH-2.0-client\r\n'
    records = []
    for index, (source, port) in enumerate((('10.0.0.1', 22), ('10.0.0.2', 22), ('10.0.0.1', 2222))):
        for attempt in range(2):
            records.append((1000 + index + attempt / 10, tcp_frame(src=source, dport=port, sport=5000+attempt, payload=banner)))
    assert upload(client, headers, stream, 0, capture(records)).status_code == 201
    seal(client, headers, stream, 0); parser_once(store, 'parser'); drain(store)
    found = [r for r in incidents(store) if r['kind'] == 'BRUTEFORCE_SSH_HANDSHAKES']
    assert {(r['source'], r['service']) for r in found} == {('10.0.0.1', '22'), ('10.0.0.2', '22'), ('10.0.0.1', '2222')}


def test_backfill_is_idempotent_and_preserves_raw_evidence(system):
    client, store, headers = system
    stream = register(client, headers)
    with store.connect() as conn:
        for index, timestamp in enumerate((1000, 1100, 1200)):
            conn.execute('''INSERT INTO nf_events(id,domain,stream_id,sequence,packet_index,timestamp,reason,target,source)
                VALUES (%s,'lab',%s,0,%s,%s,'DDoS_SINGLE_IP: historical','192.168.1.1','10.0.0.1')''',
                ('old-' + str(index), stream, index, timestamp))
    assert store.backfill_incidents('lab') == 3
    assert store.backfill_incidents('lab') == 0
    row, = incidents(store)
    assert row['first_seen'] == 1000 and row['last_seen'] == 1200 and row['signal_count'] == 3
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) AS n FROM nf_events').fetchone()['n'] == 3
        assert conn.execute('SELECT count(*) AS n FROM nf_incident_outbox').fetchone()['n'] == 1


def test_older_evidence_extends_start_without_reopening_finished_incident(system):
    client, store, headers = system
    stream = register(client, headers, started_at=900)
    assert upload(client, headers, stream, 0, capture([(1000 + i / 10, tcp_frame()) for i in range(3)])).status_code == 201
    seal(client, headers, stream, 0); parser_once(store, 'parser'); drain(store)
    original, = incidents(store)
    assert original['closed_at'] is not None
    with store.connect() as conn:
        conn.execute('''INSERT INTO nf_events(id,domain,stream_id,sequence,packet_index,timestamp,reason,target,source)
            VALUES ('older','lab',%s,0,0,950,'DDoS_SINGLE_IP: earlier evidence','192.168.1.1','10.0.0.1')''', (stream,))
    assert store.backfill_incidents('lab') == 1
    row, = incidents(store)
    assert row['id'] == original['id'] and row['first_seen'] == 950
    assert row['closed_at'] == original['closed_at'] and row['signal_count'] == 2
