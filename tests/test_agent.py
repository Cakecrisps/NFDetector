import io
import threading

import dpkt
import pytest

from distributed.agent import PermanentUploadError, Uploader, run_capture


@pytest.fixture
def uploader(tmp_path):
    key = tmp_path / 'agent.key'
    key.write_text('id.secret\n')
    key.chmod(0o600)
    result = Uploader('https://server', key, tmp_path / 'state.json', 'eth0')

    class Session:
        calls = []
        status = 200
        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if method == 'PUT':
                sequence = int(url.rsplit('/', 1)[-1])
                value = dict(stored=True, sequence=sequence, sha256=kwargs['headers']['X-Content-SHA256'],
                             stream_id=url.split('/')[-3])
            else:
                value = {}
            return type('Response', (), {'status_code': self.status, 'text': 'test', 'json': lambda response: value})()
    result.session = Session()
    return result


def pcap(path):
    with path.open('wb') as handle:
        dpkt.pcap.Writer(handle)  # Valid empty PCAP.


def test_private_key_and_https_are_required(tmp_path):
    key = tmp_path / 'key'
    key.write_text('secret')
    key.chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        Uploader('https://server', key, tmp_path / 'state', 'eth0')
    key.chmod(0o600)
    with pytest.raises(ValueError, match='HTTPS'):
        Uploader('http://server', key, tmp_path / 'state', 'eth0')


def test_live_queue_prunes_acknowledged_entries_and_preserves_sequence(uploader, tmp_path):
    for index in range(3):
        path = tmp_path / f'{index}.pcap'
        pcap(path)
        uploader.add(path, owned=True)
        uploader.send_pending()
        assert not path.exists()
        assert uploader.state['entries'] == []
    assert uploader.state['next_sequence'] == 3
    puts = [url for method, url, _ in uploader.session.calls if method == 'PUT']
    assert [int(url.rsplit('/', 1)[1]) for url in puts] == [0, 1, 2]
    uploader.state['sealed'] = True
    uploader.send_pending()
    assert uploader.session.calls[-1][2]['json']['last_sequence'] == 2
    old_id = uploader.state['stream_id']
    uploader.new_epoch()
    assert uploader.state['stream_id'] != old_id
    assert uploader.state['next_sequence'] == 0


def test_rejected_upload_retains_spooled_capture(uploader, tmp_path):
    path = tmp_path / 'capture.pcap'
    pcap(path)
    uploader.add(path, owned=True)
    uploader.state['registered'] = True
    uploader.session.status = 401
    with pytest.raises(PermanentUploadError):
        uploader.send_pending()
    assert path.exists() and not uploader.state['entries'][0]['ack']


def test_changed_queue_file_is_not_sent(uploader, tmp_path):
    path = tmp_path / 'capture.pcap'
    pcap(path)
    uploader.add(path)
    path.write_bytes(b'changed content')
    with pytest.raises(PermanentUploadError, match='changed'):
        uploader.send_pending()


def test_capture_closes_uploads_and_seals_on_stop(uploader, tmp_path, monkeypatch):
    spool = tmp_path / 'spool'
    spool.mkdir()
    stop = threading.Event()

    class FakeDumpcap:
        returncode = None
        def __init__(self, command, **kwargs):
            assert command[0] == 'dumpcap'
            assert 'not tcp port 8443' in command
            path = spool / 'capture_00001.pcapng'
            pcap(path)
            self.stdout = io.StringIO(str(path) + '\n')
        def poll(self):
            return self.returncode
        def send_signal(self, signum):
            self.returncode = 0
        def wait(self, timeout):
            self.returncode = 0
            return 0

    monkeypatch.setattr('distributed.agent.subprocess.Popen', FakeDumpcap)
    timer = threading.Timer(0.4, stop.set)
    timer.start()
    try:
        run_capture(uploader, 'eth0', spool, 'not tcp port 8443', 64 * 1024 * 1024, stop)
    finally:
        timer.cancel()
    assert uploader.state['server_sealed']
    assert uploader.state['entries'] == []
    assert not list(spool.glob('capture*.pcapng'))


def test_transient_errors_retry_without_changing_sequence(uploader, tmp_path, monkeypatch):
    import requests
    path = tmp_path / 'capture.pcap'
    pcap(path)
    uploader.add(path)
    original = uploader.send_pending
    attempts = []

    def transient():
        attempts.append(True)
        if len(attempts) == 1:
            raise requests.ConnectionError('temporary')
        return original()

    monkeypatch.setattr(uploader, 'send_pending', transient)
    monkeypatch.setattr('distributed.agent.time.sleep', lambda delay: None)
    uploader.deliver()
    assert len(attempts) == 2
    assert uploader.state['next_sequence'] == 1
