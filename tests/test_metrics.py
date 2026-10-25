"""Period boundaries and snapshot consistency for the dashboard statistics."""
import hashlib
import json
import socket
from datetime import datetime, timedelta, timezone

import dpkt
import pytest

from distributed import web_metrics
from distributed.workers import parser_once
from test_distributed import system, register, upload, capture, tcp_frame
from test_web import web, full_login

REFERENCE = datetime(2026, 10, 25, 12, 30, tzinfo=timezone.utc)


def udp_frame():
    udp = dpkt.udp.UDP(sport=5000, dport=53, data=b'test'); udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton('10.0.0.1'), dst=socket.inet_aton('192.168.1.1'), p=17, data=udp); ip.len=len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\0'*6, dst=b'\1'*6, type=0x0800, data=ip))


@pytest.fixture
def metric_data(system):
    client, store, headers = system
    stream = register(client, headers)
    # Exact left/right boundaries, older files and future arrivals.
    rows = [(timedelta(minutes=-20), 2, tcp_frame()), (timedelta(hours=-3), 3, udp_frame()),
            (timedelta(days=-2), 5, tcp_frame()), (timedelta(days=-8), 7, udp_frame()),
            (timedelta(minutes=10), 11, udp_frame()), (timedelta(hours=-1), 13, udp_frame()),
            (timedelta(), 17, tcp_frame())]
    for sequence, (offset, count, frame) in enumerate(rows):
        body = capture([(1000 + sequence + i / 1000, frame) for i in range(count)])
        assert upload(client, headers, stream, sequence, body).status_code == 201
        parser_once(store, 'parser')
        with store.connect() as conn:
            conn.execute('UPDATE nf_chunks SET created_at=%s WHERE stream_id=%s AND sequence=%s', (REFERENCE + offset, stream, sequence))
    with store.connect() as conn:
        for identity, first, last, kind in [
            ('continuous', REFERENCE-timedelta(days=3), REFERENCE-timedelta(minutes=10), 'DDOS'),
            ('older', REFERENCE-timedelta(days=2), REFERENCE-timedelta(hours=25), 'BRUTEFORCE_SSH_HANDSHAKES'),
            ('warning', REFERENCE-timedelta(minutes=30), REFERENCE-timedelta(minutes=30), 'DECODE_WARNING'),
            ('future', REFERENCE+timedelta(minutes=1), REFERENCE+timedelta(minutes=2), 'DDOS')]:
            conn.execute('''INSERT INTO nf_incidents(id,incident_key,kind,domain,stream_id,sequence,packet_index,
                first_seen,last_seen,reason,target,source) VALUES (%s,%s,%s,'lab',%s,0,0,%s,%s,%s,'192.168.1.1','10.0.0.1')''',
                (identity, identity, kind, stream, first.timestamp(), last.timestamp(), kind+': stats test'))
    return store, stream


@pytest.mark.parametrize('hours,files,packets,tcp,udp,security,points', [
    (1,2,15,2,13,1,60), (24,3,18,2,16,1,96), (168,4,23,7,16,2,168)])
def test_graph_protocols_and_cards_use_identical_period(metric_data,hours,files,packets,tcp,udp,security,points):
    store, _ = metric_data
    result = web_metrics.traffic(store, hours, as_of=REFERENCE)
    summary=result['summary']; timeline=result['timeline']
    assert len(timeline)==points
    assert summary['traffic']['files']==files and summary['traffic']['packets']==packets
    assert summary['alerts']['security']==security and summary['alerts']['decode_warnings']==1
    assert dict((p['protocol'],p['packets']) for p in result['protocols'])=={'TCP':tcp,'UDP':udp}
    for column,field in [('bytes','received_bytes'),('captured_bytes','captured_bytes'),('files','files'),('packets','packets')]:
        assert sum(p[column] for p in timeline)==summary['traffic'][field]
    assert sum(p['packets'] for p in result['protocols'])==packets
    assert timeline[0]['hour']==REFERENCE-timedelta(hours=hours)
    assert timeline[-1]['hour']+timedelta(seconds=result['period']['bucket_seconds'])==REFERENCE
    assert result['period']==summary['period']
    assert sum(p['count'] for p in result['event_types'])==security+1


def test_empty_period_has_correct_zero_buckets_and_cards(metric_data):
    store, _=metric_data
    result=web_metrics.traffic(store,1,as_of=REFERENCE-timedelta(days=30))
    assert len(result['timeline'])==60
    assert all(p['bytes']==p['packets']==p['files']==0 for p in result['timeline'])
    assert result['summary']['traffic']['files']==0 and result['protocols']==[]
    assert result['summary']['alerts']['total']==0


def test_rolling_day_is_24_elapsed_hours_across_dst(metric_data):
    from zoneinfo import ZoneInfo
    store,_=metric_data
    reference=datetime(2026,11,1,12,tzinfo=ZoneInfo('America/New_York'))
    result=web_metrics.traffic(store,24,as_of=reference)
    period=result['period']
    assert (period['end']-period['start']).total_seconds()==86400
    assert result['timeline'][-1]['hour']+timedelta(seconds=period['bucket_seconds'])==period['end']


def test_unclassified_packets_are_not_omitted_from_protocol_total(metric_data):
    store, stream=metric_data
    with store.connect() as conn:
        conn.execute("UPDATE nf_chunks SET traffic_stats='{}'::jsonb WHERE stream_id=%s AND sequence=0",(stream,))
    result=web_metrics.traffic(store,1,as_of=REFERENCE)
    assert {p['protocol']:p['packets'] for p in result['protocols']}=={'UDP':13,'UNCLASSIFIED':2}


def test_snapshot_keeps_cards_and_graph_consistent_during_new_upload(metric_data,monkeypatch):
    store, stream=metric_data
    original=web_metrics._overview
    def upload_during_snapshot(conn,period):
        result=original(conn,period)
        with store.connect() as writer:
            writer.execute('''INSERT INTO nf_chunks(stream_id,sequence,sha256,size,path,created_at)
                VALUES (%s,99,%s,1234,'test-incoming',%s)''',(stream,'a'*64,REFERENCE-timedelta(minutes=1)))
        return result
    monkeypatch.setattr(web_metrics,'_overview',upload_during_snapshot)
    result=web_metrics.traffic(store,1,as_of=REFERENCE)
    assert result['summary']['traffic']['files']==2
    assert sum(p['files'] for p in result['timeline'])==2
    monkeypatch.setattr(web_metrics,'_overview',original)
    assert web_metrics.traffic(store,1,as_of=REFERENCE)['summary']['traffic']['files']==3


def test_period_parameter_is_validated_for_both_statistics_routes(web):
    client,_,_=web;full_login(web)
    for route in ('/admin/api/overview','/admin/api/traffic'):
        for hours in (0,-1,2,9999):assert client.get(route,params={'hours':hours}).status_code==400
        for hours in (1,24,168):
            response=client.get(route,params={'hours':hours});assert response.status_code==200
            assert response.json()['period']['hours']==hours
