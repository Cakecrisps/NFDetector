"""PostgreSQL coordination. All publication is fenced by owner and generation."""
import hashlib
import hmac
import secrets
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .incidents import IncidentBatch, persist, close_quiet


class Conflict(Exception):
    pass


class LeaseLost(Exception):
    pass


class Store:
    def __init__(self, settings):
        self.settings = settings

    def connect(self):
        return psycopg.connect(self.settings.database_url, row_factory=dict_row, connect_timeout=5)

    def initialize(self):
        with self.connect() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(638101337)')
            conn.execute(Path(__file__).with_name('schema.sql').read_text())

    def issue_key(self, name, domain):
        key_id, secret = secrets.token_hex(8), secrets.token_urlsafe(32)
        agent_id = uuid.uuid4()
        with self.connect() as conn:
            conn.execute('INSERT INTO nf_domains(id) VALUES (%s) ON CONFLICT DO NOTHING', (domain,))
            conn.execute('INSERT INTO nf_agents(id,name,domain,key_id,key_hash) VALUES (%s,%s,%s,%s,%s)',
                         (agent_id, name, domain, key_id, hashlib.sha256(secret.encode()).hexdigest()))
        return str(agent_id), f'{key_id}.{secret}'

    def authenticate(self, token):
        key_id, _, secret = token.partition('.')
        with self.connect() as conn:
            row = conn.execute('SELECT * FROM nf_agents WHERE key_id=%s AND NOT revoked', (key_id,)).fetchone()
        expected = row['key_hash'] if row else '0' * 64
        valid = hmac.compare_digest(expected, hashlib.sha256(secret.encode()).hexdigest())
        if row and valid and secret:
            with self.connect() as conn:
                conn.execute('''UPDATE nf_agents SET last_seen_at=clock_timestamp() WHERE id=%s
                    AND (last_seen_at IS NULL OR last_seen_at<clock_timestamp()-interval '5 seconds')''', (row['id'],))
            return row
        return None

    def claim_chunk(self, owner):
        with self.connect() as conn:
            row = conn.execute("""SELECT * FROM nf_chunks
                WHERE status='pending' OR (status='parsing' AND lease_until < clock_timestamp())
                ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1""").fetchone()
            if not row:
                return None
            return conn.execute("""UPDATE nf_chunks SET status='parsing',owner=%s,
                generation=generation+1,lease_until=clock_timestamp()+(%s * interval '1 second'),error=NULL
                WHERE id=%s RETURNING *""", (owner, self.settings.lease_seconds, row['id'])).fetchone()

    def claim_domain(self, owner):
        with self.connect() as conn:
            row = conn.execute("""SELECT d.* FROM nf_domains d WHERE d.error IS NULL AND d.work_version>d.completed_version
                AND (d.owner IS NULL OR d.lease_until < clock_timestamp())
                AND EXISTS (SELECT 1 FROM nf_streams s JOIN nf_agents a ON a.id=s.agent_id
                    JOIN nf_chunks c ON c.stream_id=s.id WHERE a.domain=d.id AND c.status='ready')
                ORDER BY d.updated_at FOR UPDATE OF d SKIP LOCKED LIMIT 1""").fetchone()
            if not row:
                return None
            return conn.execute("""UPDATE nf_domains SET owner=%s,generation=generation+1,
                lease_until=clock_timestamp()+(%s * interval '1 second') WHERE id=%s RETURNING *""",
                                (owner, self.settings.lease_seconds, row['id'])).fetchone()

    def renew(self, kind, job):
        table = {'parser': 'nf_chunks', 'detector': 'nf_domains'}[kind]
        with self.connect() as conn:
            row = conn.execute(f"""UPDATE {table} SET lease_until=clock_timestamp()+(%s * interval '1 second')
                WHERE id=%s AND owner=%s AND generation=%s AND lease_until>clock_timestamp() RETURNING id""",
                               (self.settings.lease_seconds, job['id'], job['owner'], job['generation'])).fetchone()
        if not row:
            raise LeaseLost(str(job['id']))

    @staticmethod
    def fence(conn, table, job):
        if table not in ('nf_chunks', 'nf_domains'):
            raise ValueError('Unknown lease table')
        row = conn.execute(f"""SELECT id FROM {table} WHERE id=%s AND owner=%s AND generation=%s
            AND lease_until>clock_timestamp() FOR UPDATE""", (job['id'], job['owner'], job['generation'])).fetchone()
        if not row:
            raise LeaseLost(str(job['id']))

    def finish_chunk(self, job, result):
        with self.connect() as conn:
            self.fence(conn, 'nf_chunks', job)
            conn.execute("""UPDATE nf_chunks SET status='ready',artifact=%s,frames=%s,first_ts=%s,
                last_ts=%s,captured_bytes=%s,traffic_stats=%s,parsed_by=owner,parser_finished_at=clock_timestamp(),owner=NULL,lease_until=NULL WHERE id=%s""",
                         (result['path'], result['frames'], result['first_ts'], result['last_ts'],
                          result.get('captured_bytes'), Jsonb(result.get('traffic_stats', {})), job['id']))
            conn.execute('''UPDATE nf_domains SET work_version=work_version+1 WHERE id=(
                SELECT a.domain FROM nf_chunks c JOIN nf_streams s ON s.id=c.stream_id
                JOIN nf_agents a ON a.id=s.agent_id WHERE c.id=%s)''', (job['id'],))

    def fail(self, kind, job, error):
        table = {'parser': 'nf_chunks', 'detector': 'nf_domains'}[kind]
        with self.connect() as conn:
            self.fence(conn, table, job)
            if kind == 'parser':
                conn.execute("UPDATE nf_chunks SET status='error',error=%s,owner=NULL,lease_until=NULL WHERE id=%s",
                             (str(error)[:2000], job['id']))
            else:
                conn.execute('UPDATE nf_domains SET error=%s,owner=NULL,lease_until=NULL WHERE id=%s',
                             (str(error)[:2000], job['id']))

    def streams(self, domain):
        with self.connect() as conn:
            return conn.execute('SELECT s.* FROM nf_streams s JOIN nf_agents a ON a.id=s.agent_id WHERE a.domain=%s ORDER BY s.id',
                                (domain,)).fetchall()

    def chunk(self, stream_id, sequence):
        with self.connect() as conn:
            return conn.execute('SELECT * FROM nf_chunks WHERE stream_id=%s AND sequence=%s', (stream_id, sequence)).fetchone()

    def commit_domain(self, job, checkpoint, config_hash, events, last_timestamp, idle=False, cursors=None, observations=None):
        with self.connect() as conn:
            self.fence(conn, 'nf_domains', job)
            for event in events:
                conn.execute('''INSERT INTO nf_events(id,domain,stream_id,sequence,packet_index,timestamp,reason,target,source)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                             tuple(event[name] for name in ('id', 'domain', 'stream_id', 'sequence', 'packet_index',
                                                           'timestamp', 'reason', 'target', 'source')))
            if observations is None:
                observations = IncidentBatch(self.settings.incident_gap_seconds)
                for event in events:
                    observations.observe(event, evidence=True)
            persist(conn, observations, self.settings.incident_gap_seconds)
            for stream_id, cursor in (cursors or {}).items():
                conn.execute('UPDATE nf_streams SET processed_sequence=GREATEST(processed_sequence,%s) WHERE id=%s',
                             (cursor['sequence'] - 1, stream_id))
            finished = idle and conn.execute('''SELECT bool_and(s.last_sequence IS NOT NULL AND
                s.processed_sequence>=s.last_sequence) AS done FROM nf_streams s JOIN nf_agents a ON a.id=s.agent_id
                WHERE a.domain=%s''', (job['id'],)).fetchone()['done']
            close_quiet(conn, job['id'], last_timestamp, self.settings.incident_gap_seconds, finished)
            conn.execute('''UPDATE nf_domains SET checkpoint=%s,config_hash=%s,last_timestamp=%s,owner=NULL,lease_until=NULL,
                updated_at=clock_timestamp(),completed_version=CASE WHEN %s THEN %s ELSE completed_version END WHERE id=%s''', (checkpoint, config_hash, last_timestamp, idle, job['work_version'], job['id']))

    def backfill_incidents(self, domain):
        """Attach existing raw signals without deleting evidence or changing checkpoints."""
        with self.connect() as conn:
            job = conn.execute('''SELECT *,owner IS NOT NULL AND lease_until>clock_timestamp() AS busy
                FROM nf_domains WHERE id=%s FOR UPDATE''', (domain,)).fetchone()
            if not job or job['busy']:
                raise Conflict('Domain is missing or a detector lease is active; stop the detector and wait for its lease')
            total = 0
            with conn.cursor(name='incident_backfill') as cursor:
                cursor.execute('SELECT * FROM nf_events WHERE domain=%s AND incident_id IS NULL ORDER BY timestamp,id', (domain,))
                while rows := cursor.fetchmany(1000):
                    batch = IncidentBatch(self.settings.incident_gap_seconds)
                    for event in rows:
                        batch.observe(event, evidence=True)
                    persist(conn, batch, self.settings.incident_gap_seconds)
                    total += len(rows)
            close_quiet(conn, domain, job['last_timestamp'], self.settings.incident_gap_seconds)
            return total

    def worker_ping(self, identity, kind):
        with self.connect() as conn:
            conn.execute("DELETE FROM nf_workers WHERE last_seen_at<clock_timestamp()-interval '1 day'")
            conn.execute('''INSERT INTO nf_workers(id,kind) VALUES (%s,%s)
                ON CONFLICT(id) DO UPDATE SET last_seen_at=clock_timestamp()''', (identity, kind))
