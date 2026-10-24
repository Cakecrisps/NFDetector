"""Crash-resumable capture uploader. Secrets are read from a private file."""
import json
import os
import random
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import requests

from .capture import digest_file, fsync_directory, reader


class PermanentUploadError(Exception):
    pass


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    fsync_directory(path.parent)


def capture_start(path):
    with open(path, 'rb') as handle:
        capture = reader(handle)
        earliest = min((float(timestamp) for timestamp, _ in capture), default=None)
    return earliest


class Uploader:
    def __init__(self, server, key_file, state_file, interface, ca=True, allow_http=False):
        parsed = urlparse(server)
        if parsed.scheme != 'https' and not (allow_http and parsed.scheme == 'http'):
            raise ValueError('HTTPS is required; --allow-http is for local testing only')
        if not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid ingestion URL')
        key_file = Path(key_file)
        if key_file.stat().st_mode & 0o077:
            raise ValueError('Agent key file must have permissions 0600')
        token = key_file.read_text().strip()
        if not token or '\n' in token:
            raise ValueError('Invalid key file')
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'Bearer {token}'
        self.server, self.ca = server.rstrip('/'), ca
        self.path, self.lock = Path(state_file), threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            if self.state['server'] != self.server or self.state['interface'] != interface:
                raise ValueError('Spool belongs to a different server/interface')
        else:
            self.state = dict(server=self.server, interface=interface, stream_id=str(uuid.uuid4()),
                              started_at=None, registered=False, entries=[], next_sequence=0, sealed=False, server_sealed=False)
            self.save()
        self.state.setdefault('next_sequence', len(self.state['entries']))
        for index, entry in enumerate(self.state['entries']):
            entry.setdefault('sequence', index)

    def save(self):
        atomic_json(self.path, self.state)

    def add(self, path, owned=False):
        path = str(Path(path).resolve())
        with self.lock:
            if any(entry['path'] == path for entry in self.state['entries']):
                return
        timestamp = capture_start(path)  # Also validate that the entire file is readable.
        checksum, size = digest_file(path), os.path.getsize(path)
        with self.lock:
            if self.state['sealed']:
                raise ValueError('Cannot append to a sealed capture')
            if self.state['started_at'] is None:
                self.state['started_at'] = timestamp if timestamp is not None else time.time()
            elif not self.state['registered'] and timestamp is not None:
                self.state['started_at'] = min(self.state['started_at'], timestamp)
            self.state['entries'].append(dict(path=path, sha256=checksum, size=size, owned=owned, ack=False,
                                              sequence=self.state['next_sequence']))
            self.state['next_sequence'] += 1
            self.save()

    def request(self, method, route, **kwargs):
        response = self.session.request(method, self.server + route, timeout=(10, 60), verify=self.ca, **kwargs)
        if response.status_code in (429, 503) or response.status_code >= 500:
            raise requests.ConnectionError(f'Temporary server response {response.status_code}')
        if response.status_code >= 400:
            raise PermanentUploadError(f'Server rejected {route}: {response.status_code}: {response.text[:300]}')
        return response.json()

    def send_pending(self):
        with self.lock:
            if self.state['started_at'] is None:
                return False
            stream_id = self.state['stream_id']
            registered = self.state['registered']
        if not registered:
            self.request('POST', '/v1/streams', json=dict(id=stream_id, interface=self.state['interface'], started_at=self.state['started_at']))
            with self.lock:
                self.state['registered'] = True
                self.save()
        progress = False
        for entry in list(self.state['entries']):
            index = entry['sequence']
            if entry['ack']:
                if entry['owned']:
                    Path(entry['path']).unlink(missing_ok=True)
                continue
            if digest_file(entry['path']) != entry['sha256'] or os.path.getsize(entry['path']) != entry['size']:
                raise PermanentUploadError('Queued capture content changed')
            with open(entry['path'], 'rb') as handle:
                result = self.request('PUT', f'/v1/streams/{stream_id}/chunks/{index}', data=handle,
                                      headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(entry['size']),
                                               'X-Content-SHA256': entry['sha256']})
            if (not result.get('stored') or result.get('sha256') != entry['sha256']
                    or result.get('stream_id') != stream_id or result.get('sequence') != index):
                raise PermanentUploadError('Invalid upload acknowledgement')
            with self.lock:
                entry['ack'] = True
                self.save()  # Persist acknowledgement before deleting a spool file.
            if entry['owned']:
                Path(entry['path']).unlink(missing_ok=True)
            progress = True
        with self.lock:
            # Keep live spools proportional to pending files, not capture lifetime.
            retained = [item for item in self.state['entries'] if not (item['owned'] and item['ack'])]
            if len(retained) != len(self.state['entries']):
                self.state['entries'] = retained
                self.save()
            seal = self.state['sealed'] and not self.state['server_sealed'] and all(item['ack'] for item in self.state['entries'])
        if seal:
            self.request('POST', f'/v1/streams/{stream_id}/seal', json={'last_sequence': self.state['next_sequence'] - 1})
            with self.lock:
                self.state['server_sealed'] = True
                self.save()
        return progress

    def new_epoch(self):
        with self.lock:
            if not self.state['server_sealed']:
                raise ValueError('Finish the previous capture before starting another epoch')
            archive = self.path.with_name(self.path.stem + '.' + self.state['stream_id'] + '.json')
            atomic_json(archive, self.state)
            self.state = dict(server=self.server, interface=self.state['interface'], stream_id=str(uuid.uuid4()),
                              started_at=None, registered=False, entries=[], next_sequence=0, sealed=False, server_sealed=False)
            self.save()

    def deliver(self, attempts=8, stop_event=None):
        for attempt in range(attempts):
            try:
                return self.send_pending()
            except requests.exceptions.SSLError as error:
                raise PermanentUploadError('TLS certificate verification failed') from error
            except requests.RequestException:
                if attempt + 1 == attempts:
                    raise
                delay = random.uniform(0.5, min(30, 2 ** attempt))
                if stop_event is None:
                    time.sleep(delay)
                elif stop_event.wait(delay):
                    raise InterruptedError('Agent stopped before capture registration')

    def upload_files(self, paths):
        for path in paths:
            self.add(path)
        with self.lock:
            self.state['sealed'] = True
            self.save()
        self.deliver()


def run_capture(uploader, interface, spool, capture_filter, quota, stop_event=None):
    """Rotate continuously. A quota breach stops capture visibly; it never overwrites pending files."""
    spool = Path(spool).resolve()
    spool.mkdir(parents=True, exist_ok=True)
    if not capture_filter:
        raise ValueError('An explicit --filter excluding upload traffic is required')
    if quota < 64 * 1024 * 1024:
        raise ValueError('Spool quota must be at least 64 MiB')
    if uploader.state['sealed']:
        uploader.send_pending()
        uploader.new_epoch()
    # Recover files closed before the previous process could record their manifest.
    for path in sorted(spool.glob('capture*.pcapng')):
        uploader.add(path, owned=True)
    if uploader.state['entries'] or uploader.state['registered']:
        # A process restart is a capture gap: finish the old epoch explicitly.
        uploader.state['sealed'] = True
        uploader.save()
        uploader.send_pending()
        uploader.new_epoch()
    # Join the domain before capture starts, so another source cannot advance
    # its watermark beyond this source's first packet. Initial connectivity is required.
    if uploader.state['started_at'] is None:
        uploader.state['started_at'] = time.time()
        uploader.save()
    uploader.deliver(stop_event=stop_event)
    process = subprocess.Popen(['dumpcap', '-q', '-i', interface, '-f', capture_filter,
                                '-b', 'duration:2', '-b', 'filesize:16384', '-b', 'printname:stdout',
                                '-w', str(spool / 'capture.pcapng')], stdout=subprocess.PIPE, text=True)
    failures = []

    def harvest():
        try:
            for line in process.stdout:
                path = Path(line.strip()).resolve()
                if path.parent != spool:
                    raise ValueError('Unexpected dumpcap output path')
                uploader.add(path, owned=True)
        except Exception as error:
            failures.append(error)
            process.send_signal(signal.SIGINT)

    thread = threading.Thread(target=harvest, daemon=True)
    thread.start()
    stopped = stop_event or threading.Event()
    reasons, retry_at, backoff = [], 0, 1
    watchdog_stop = threading.Event()

    def watchdog():
        while not watchdog_stop.wait(0.25) and process.poll() is None:
            size = 0
            for path in spool.glob('capture*.pcapng'):
                try:
                    size += path.stat().st_size
                except FileNotFoundError:
                    pass
            if stopped.is_set() or size >= quota - 32 * 1024 * 1024:
                if not stopped.is_set():
                    reasons.append('Spool quota reached; capture stopped with an explicit observation gap')
                try:
                    process.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
                return

    watcher = threading.Thread(target=watchdog, daemon=True)
    watcher.start()
    try:
        while process.poll() is None:
            if stopped.is_set():
                break
            if failures:
                raise failures[0]
            if time.monotonic() >= retry_at:
                try:
                    uploader.send_pending()
                    backoff = 1
                except requests.RequestException:
                    retry_at = time.monotonic() + random.uniform(backoff / 2, backoff)
                    backoff = min(60, backoff * 2)
            stopped.wait(0.25)
    finally:
        watchdog_stop.set()
        watcher.join(timeout=5)
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=15)
        thread.join(timeout=15)
        if thread.is_alive():
            raise RuntimeError('Capture harvester did not stop')
    if failures:
        raise failures[0]
    if process.returncode not in (0, -signal.SIGINT):
        raise RuntimeError(f'dumpcap exited with code {process.returncode}')
    # Include the final file even if dumpcap did not print its name on shutdown.
    for path in sorted(spool.glob('capture*.pcapng')):
        uploader.add(path, owned=True)
    with uploader.lock:
        uploader.state['sealed'] = True
        uploader.save()
    uploader.send_pending()
    if reasons:
        raise RuntimeError(reasons[0])
