"""Parallel file jobs and fenced, restartable domain event-time reducers."""
import hashlib
import heapq
import json
import logging
import pickle
import threading
import time
import uuid
import zlib
from contextlib import ExitStack

from general.trafficanalyzer import TrafficAnalyzer
from general.streaming import StreamingDetector
from .capture import parse_capture, digest_file
from .flows import FlowDecoder
from .store import LeaseLost, Store

log = logging.getLogger(__name__)
CHECKPOINT_VERSION = 1


class Heartbeat:
    def __init__(self, store, kind, job):
        self.store, self.kind, self.job = store, kind, job
        self.stop = threading.Event()
        self.failure = None

    def __enter__(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self):
        while not self.stop.wait(max(0.1, self.store.settings.lease_seconds / 3)):
            try:
                self.store.renew(self.kind, self.job)
            except Exception as error:
                self.failure = error
                return

    def check(self):
        if self.failure:
            raise LeaseLost(str(self.failure))

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=5)


def parser_once(store, owner, job=None):
    job = job or store.claim_chunk(owner)
    if not job:
        return False
    try:
        with Heartbeat(store, 'parser', job) as heartbeat:
            destination = store.settings.data_dir / 'parsed' / f"{job['id']}.{job['generation']}.jsonl"
            if digest_file(job['path']) != job['sha256']:
                raise ValueError('Stored capture checksum mismatch')
            result = parse_capture(job['path'], destination)
            heartbeat.check()
            store.finish_chunk(job, result)
        log.info('Parsed chunk %s sequence=%s owner=%s', job['id'], job['sequence'], owner)
    except LeaseLost:
        log.warning('Parser lease lost for chunk %s', job['id'])
    except Exception as error:
        log.exception('Parser failed for chunk %s', job['id'])
        try:
            store.fail('parser', job, error)
        except LeaseLost:
            pass
    return True


def fresh_state(settings):
    analyzer = TrafficAnalyzer(str(settings.rules_path), str(settings.protected_path))
    return dict(version=CHECKPOINT_VERSION, detector=StreamingDetector(analyzer),
                flows=FlowDecoder(), cursors={}, last_timestamp=None)


def config_hash(settings):
    analyzer = TrafficAnalyzer(str(settings.rules_path), str(settings.protected_path))
    value = dict(version=CHECKPOINT_VERSION, rules=analyzer.rules, protected=sorted(analyzer.protectips),
                 suspicious=sorted(analyzer.suspicious_ips))
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def encode_state(state, limit):
    data = pickle.dumps(state, protocol=5)
    if len(data) > limit:
        raise ValueError('Detector checkpoint limit exceeded')
    return zlib.compress(data, level=1)


def decode_state(data, settings):
    if not data:
        return fresh_state(settings)
    # Only service-owned PostgreSQL checkpoints are deserialized, never uploaded data.
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(data), settings.max_checkpoint + 1)
    if len(raw) > settings.max_checkpoint or decoder.unconsumed_tail or not decoder.eof:
        raise ValueError('Invalid or oversized detector checkpoint')
    state = pickle.loads(raw)
    if state['version'] != CHECKPOINT_VERSION:
        raise ValueError('Unsupported detector checkpoint version')
    return state


def reduce_batch(store, domain, state):
    """Merge ready file prefixes only up to every registered source's watermark.

    Each source must have non-overlapping timestamp ranges between consecutive
    chunks. Missing files hold the watermark, including a missing sequence zero.
    The same domain must contain disjoint observation sources with aligned clocks.
    """
    emitted, processed, changed = [], 0, False
    heap, bounds = [], []
    with ExitStack() as stack:
        for stream in store.streams(domain):
            stream_id = str(stream['id'])
            cursor = state['cursors'].setdefault(stream_id, {'sequence': 0, 'offset': 0, 'watermark': stream['started_at']})
            while True:
                sequence = cursor['sequence']
                chunk = store.chunk(stream['id'], sequence)
                if chunk and chunk['status'] == 'ready' and chunk['frames'] == 0:
                    cursor.update(sequence=sequence + 1, offset=0)
                    changed = True
                    continue
                break
            if stream['last_sequence'] is not None and cursor['sequence'] > stream['last_sequence']:
                bounds.append(float('inf'))
                continue
            if not chunk or chunk['status'] != 'ready':
                bounds.append(cursor['watermark'])
                continue
            if chunk['first_ts'] < cursor['watermark']:
                raise ValueError(f'Chunk timestamp range goes backwards: {stream_id}/{sequence}')
            bounds.append(chunk['last_ts'])
            handle = stack.enter_context(open(chunk['artifact'], 'rb'))
            handle.seek(cursor['offset'])
            line = handle.readline()
            if not line:
                raise ValueError('Parsed artifact is incomplete')
            event = json.loads(line)
            heapq.heappush(heap, (event['timestamp'], stream_id, event['packet_index'], event, handle, cursor, chunk))
        watermark = min(bounds, default=float('-inf'))
        while heap and heap[0][0] <= watermark and processed < store.settings.batch_size:
            timestamp, stream_id, index, event, handle, cursor, chunk = heapq.heappop(heap)
            if state['last_timestamp'] is not None and timestamp < state['last_timestamp']:
                raise ValueError('Late event is below domain watermark; replay in a new domain is required')
            state['flows'].feed(event, stream_id)
            alarms = state['detector'].process(event) if event['src_ip'] else []
            for warning in event.get('decode_warnings', []):
                alarms.append(('DECODE_WARNING: ' + warning, event['dst_ip'] or '', event['src_ip'] or '', False))
            for sub_index, (reason, target, source, _) in enumerate(alarms):
                identity = json.dumps([domain, stream_id, chunk['sequence'], index, sub_index, reason], separators=(',', ':'))
                emitted.append(dict(id=hashlib.sha256(identity.encode()).hexdigest(), domain=domain,
                                    stream_id=stream_id, sequence=chunk['sequence'], packet_index=index,
                                    timestamp=timestamp, reason=reason, target=target, source=source))
            state['last_timestamp'] = timestamp
            cursor['offset'] = handle.tell()
            processed += 1
            changed = True
            following = handle.readline()
            if following:
                next_event = json.loads(following)
                heapq.heappush(heap, (next_event['timestamp'], stream_id, next_event['packet_index'],
                                      next_event, handle, cursor, chunk))
            else:
                cursor.update(sequence=chunk['sequence'] + 1, offset=0, watermark=chunk['last_ts'])
    return emitted, processed, changed


def detector_once(store, owner):
    job = store.claim_domain(owner)
    if not job:
        return False
    try:
        with Heartbeat(store, 'detector', job) as heartbeat:
            signature = config_hash(store.settings)
            if job['config_hash'] and job['config_hash'] != signature:
                raise ValueError('Rules changed: replay into a new domain or migrate checkpoint explicitly')
            state = decode_state(job['checkpoint'], store.settings)
            events, processed, changed = reduce_batch(store, job['id'], state)
            heartbeat.check()
            checkpoint = encode_state(state, store.settings.max_checkpoint) if changed or not job['checkpoint'] else job['checkpoint']
            store.commit_domain(job, checkpoint, signature, events, state['last_timestamp'], idle=not (processed or changed), cursors=state['cursors'])
        if processed:
            log.info('Reduced domain=%s packets=%s alarms=%s owner=%s', job['id'], processed, len(events), owner)
        return bool(processed or changed)
    except LeaseLost:
        log.warning('Detector lease lost for domain %s', job['id'])
    except Exception as error:
        log.exception('Detector failed for domain %s', job['id'])
        try:
            store.fail('detector', job, error)
        except LeaseLost:
            pass
    return False


def run_worker(settings, kind):
    store = Store(settings)
    settings.prepare()
    store.initialize()
    owner = f'{kind}-{uuid.uuid4()}'
    operation = parser_once if kind == 'parser' else detector_once
    while True:
        if not operation(store, owner):
            time.sleep(0.5)
