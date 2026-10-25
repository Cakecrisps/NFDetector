"""Batch ongoing detector activity into event-time incidents, retaining raw evidence."""
import hashlib
import json
import re

FLOOD_KINDS = {'DDoS_SINGLE_IP', 'DDoS_MULTI_IP', 'SYN_FLOOD_HALF_OPEN', 'HTTP_FLOOD'}
MAX_SOURCES = 100


def identity(event, kind, service=''):
    family = 'DDOS' if kind in FLOOD_KINDS else kind
    source = '' if family == 'DDOS' else event['source']
    if kind == 'BRUTEFORCE_SSH_HANDSHAKES' and not service:
        match = re.search(r'-> .*?:(\d+)\s', event.get('reason', ''))
        service = match[1] if match else ''
    detail = event.get('reason', '') if kind == 'DECODE_WARNING' else ''
    key = json.dumps([event['domain'], family, event['target'], source, service, detail], separators=(',', ':'))
    return hashlib.sha256(key.encode()).hexdigest(), family, source, service


class IncidentBatch:
    """At most one current segment per key. No per-packet database operations."""
    def __init__(self, gap):
        self.gap, self.segments, self.latest = gap, [], {}

    def observe(self, event, kind=None, service='', evidence=False):
        kind = kind or event['reason'].split(':', 1)[0]
        key, family, source, service = identity(event, kind, service)
        now = event['timestamp']
        segment = self.latest.get(key)
        if segment is None or now - segment['last_seen'] > self.gap:
            segment = dict(key=key, kind=family, source=source, service=service,
                           first_seen=now, last_seen=now, representative=event,
                           sources=set(), truncated=False, kinds=set(), streams=set(), event_ids=[])
            self.latest[key] = segment
            self.segments.append(segment)
        segment['last_seen'] = max(segment['last_seen'], now)
        segment['kinds'].add(kind)
        segment['streams'].add(str(event['stream_id']))
        if event['source']:
            if len(segment['sources']) < MAX_SOURCES:
                segment['sources'].add(event['source'])
            elif event['source'] not in segment['sources']:
                segment['truncated'] = True
        if evidence:
            if not segment['event_ids']:
                segment['representative'] = event
            segment['event_ids'].append(event['id'])


def persist(conn, batch, gap):
    for segment in batch.segments:
        event = segment['representative']
        # Domain fencing serializes reducers; this row lock also protects admin backfill.
        row = conn.execute('''SELECT * FROM nf_incidents WHERE incident_key=%s
            AND first_seen<=%s AND last_seen>=%s ORDER BY first_seen LIMIT 1 FOR UPDATE''',
                           (segment['key'], segment['last_seen'] + gap, segment['first_seen'] - gap)).fetchone()
        if row is None:
            seed = [segment['key'], event['stream_id'], event['sequence'], event['packet_index'], segment['first_seen']]
            incident_id = hashlib.sha256(json.dumps(seed, default=str).encode()).hexdigest()
            row = conn.execute('''INSERT INTO nf_incidents(id,incident_key,kind,domain,stream_id,sequence,packet_index,
                first_seen,last_seen,reason,target,source,service)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (incident_id, segment['key'], segment['kind'], event['domain'], event['stream_id'],
                 event['sequence'], event['packet_index'], segment['first_seen'], segment['last_seen'],
                 event.get('reason') or segment['kind'] + ': ongoing detector activity',
                 event['target'], segment['source'], segment['service'])).fetchone()
            conn.execute('INSERT INTO nf_incident_outbox(incident_id) VALUES (%s)', (incident_id,))
        incident_id = row['id']
        if segment['first_seen'] < row['first_seen']:
            conn.execute('''UPDATE nf_incidents SET stream_id=%s,sequence=%s,packet_index=%s,reason=%s WHERE id=%s''',
                (event['stream_id'], event['sequence'], event['packet_index'],
                 event.get('reason') or segment['kind'] + ': ongoing detector activity', incident_id))
        attached = conn.execute('''UPDATE nf_events SET incident_id=%s
            WHERE id=ANY(%s::text[]) AND incident_id IS NULL RETURNING id''',
                               (incident_id, segment['event_ids'])).fetchall() if segment['event_ids'] else []
        sources = set(row['sources']) | segment['sources']
        kinds = sorted(set(row['kinds']) | segment['kinds'])
        conn.execute('''UPDATE nf_incidents SET first_seen=LEAST(first_seen,%s),last_seen=GREATEST(last_seen,%s),
            signal_count=signal_count+%s,sources=%s,sources_truncated=%s,kinds=%s,
            closed_at=CASE WHEN %s>last_seen THEN NULL ELSE closed_at END,
            close_reason=CASE WHEN %s>last_seen THEN NULL ELSE close_reason END,
            updated_at=clock_timestamp() WHERE id=%s''',
            (segment['first_seen'], segment['last_seen'], len(attached), sorted(sources)[:MAX_SOURCES],
             row['sources_truncated'] or segment['truncated'] or len(sources) > MAX_SOURCES, kinds,
             segment['last_seen'], segment['last_seen'], incident_id))
        for stream_id in segment['streams']:
            conn.execute('INSERT INTO nf_incident_streams(incident_id,stream_id) VALUES (%s,%s) ON CONFLICT DO NOTHING',
                         (incident_id, stream_id))


def close_quiet(conn, domain, watermark, gap, finished=False):
    if watermark is not None:
        conn.execute('''UPDATE nf_incidents SET closed_at=last_seen,close_reason='quiet',updated_at=clock_timestamp()
            WHERE domain=%s AND closed_at IS NULL AND last_seen+%s<%s''', (domain, gap, watermark))
    if finished:
        conn.execute('''UPDATE nf_incidents SET closed_at=last_seen,close_reason='capture_ended',updated_at=clock_timestamp()
            WHERE domain=%s AND closed_at IS NULL''', (domain,))
