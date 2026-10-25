"""Enrollment lifecycle, pinned TLS and the managed installer boundaries."""
import base64
import hashlib
import http.server
import io
import json
import os
import shlex
import ssl
import subprocess
import tarfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from fastapi import HTTPException

from distributed import installer
from distributed.agent import Uploader
from distributed.installation import PACKAGE_FILES, agent_package, server_origin
from distributed.tls import FingerprintAdapter
from test_distributed import system
from test_web import web, full_login, mutate


@pytest.fixture(scope='module')
def certificate(tmp_path_factory):
    root = tmp_path_factory.mktemp('enrollment-tls')
    cert, key = root / 'server.crt', root / 'server.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    return cert, key


def config_from_command(command):
    argv = shlex.split(command)
    assert argv[:3] == ['sudo', 'python3', '-c'] and len(argv) == 4
    # Read only the embedded JSON. Never execute a root installation in unit tests.
    import ast
    tree = ast.parse(argv[3])
    for item in ast.walk(tree):
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == 'b64decode':
            return json.loads(base64.b64decode(ast.literal_eval(item.args[0])))
    raise AssertionError('No installation configuration')


@pytest.fixture
def enrollment(web, certificate):
    client, store, _ = web
    store.settings.tls_public_cert = certificate[0]
    full_login(web)
    result = mutate(web, '/agents', {'name': 'new-host', 'domain': 'installation-test'}).json()
    return web, result, config_from_command(result['installation']['command'])


def enroll(client, token):
    return client.post('/v1/enroll', headers={'Authorization': 'Enrollment ' + token})


def test_install_command_has_short_lived_code_and_no_permanent_key(enrollment):
    (client, store, _), result, config = enrollment
    assert result['key'] not in result['installation']['command']
    assert config['server'] == 'https://testserver'
    assert config['package_sha256'] == hashlib.sha256(client.get('/install/agent.tar').content).hexdigest()
    assert config['installer_sha256'] == hashlib.sha256(client.get('/install/agent.py').content).hexdigest()
    with store.connect() as conn:
        row = conn.execute('SELECT * FROM nf_agent_installations').fetchone()
        assert row['token_hash'] == hashlib.sha256(config['token'].encode()).hexdigest()
        assert config['token'] not in str(row) and result['key'] not in str(row)
    assert client.get('/v1/events', headers={'Authorization': 'Bearer ' + config['token']}).status_code == 401


def test_agent_installation_address_can_differ_from_panel_address(enrollment):
    web, _, _ = enrollment
    client, store, _ = web
    store.settings.agent_origin = 'https://192.168.122.1'
    result = mutate(web, '/agents', {'name': 'remote-host', 'domain': 'remote'}).json()
    config = config_from_command(result['installation']['command'])
    assert config['server'] == 'https://192.168.122.1'
    assert client.get('/admin/api/session').json()['agent_install_url'] == 'https://192.168.122.1'


def test_creation_uses_and_remembers_panel_address_from_agent(enrollment):
    web, _, _ = enrollment
    client, store, _ = web
    created = []
    for address in ('192.168.122.1', 'https://panel.other.test:8443'):
        result = mutate(web, '/agents', {'name': address, 'domain': 'remote', 'server_url': address}).json()
        expected = address if address.startswith('https://') else 'https://' + address
        assert config_from_command(result['installation']['command'])['server'] == expected
        created.append((result['agent_id'], expected))
    listing = {a['id']: a for a in client.get('/admin/api/agents').json()['agents']}
    for identity, expected in created:
        assert listing[identity]['server_url'] == expected
        rotated = mutate(web, '/agents/' + identity + '/rotate', {}).json()
        assert config_from_command(rotated['installation']['command'])['server'] == expected


def test_invalid_panel_address_does_not_create_an_agent(enrollment):
    web, _, _ = enrollment
    _, store, _ = web
    response = mutate(web, '/agents', {'name': 'invalid-url', 'domain': 'invalid', 'server_url': 'http://insecure'})
    assert response.status_code == 400
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM nf_agents WHERE name='invalid-url'").fetchone()['n'] == 0


def test_enrollment_once_rotates_manual_key_and_never_exposes_it_again(enrollment):
    (client, store, _), result, config = enrollment
    response = enroll(client, config['token'])
    assert response.status_code == 200
    key = response.json()['key']
    assert key != result['key'] and store.authenticate(key)
    assert not store.authenticate(result['key'])
    assert enroll(client, config['token']).status_code == 401
    assert client.get('/admin/api/overview', headers={'Cookie': '', 'Authorization': 'Bearer ' + key}).status_code == 401
    with store.connect() as conn:
        audit = conn.execute("SELECT * FROM nf_web_audit WHERE action='agent_installed'").fetchall()
    assert len(audit) == 1 and key not in str(audit) and config['token'] not in str(audit)
    assert 'no-store' in response.headers['cache-control']


def test_concurrent_enrollment_succeeds_only_once(enrollment):
    from concurrent.futures import ThreadPoolExecutor
    (client, _, _), _, config = enrollment
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: enroll(client, config['token']).status_code, range(2)))
    assert sorted(results) == [200, 401]


@pytest.mark.parametrize('action', ['expired', 'revoked', 'rotated', 'reissued'])
def test_expiry_revocation_rotation_and_reissue_invalidate_old_command(enrollment, action):
    (client, store, _), result, config = enrollment
    identity = result['agent_id']
    if action == 'expired':
        with store.connect() as conn:
            conn.execute("UPDATE nf_agent_installations SET expires_at=clock_timestamp()-interval '1 second'")
    elif action == 'revoked':
        assert mutate(enrollment[0], '/agents/' + identity + '/revoke', {}).status_code == 200
    elif action == 'rotated':
        assert mutate(enrollment[0], '/agents/' + identity + '/rotate', {}).status_code == 200
    else:
        response = mutate(enrollment[0], '/agents/' + identity + '/installation', {'server_url': 'https://sensor-server:443', 'interface': 'eth0'})
        assert response.status_code == 200
        replacement = config_from_command(response.json()['command'])
        assert replacement['interface'] == 'eth0' and replacement['server'] == 'https://sensor-server:443'
        assert store.authenticate(result['key'])  # Issuance alone does not disrupt capture.
    assert enroll(client, config['token']).status_code == 401


def test_installation_command_needs_csrf_and_recent_admin_auth(enrollment):
    web, result, _ = enrollment
    client, store, _ = web
    path = '/admin/api/agents/' + result['agent_id'] + '/installation'
    assert client.post(path, json={'server_url': 'https://host'}).status_code == 403
    with store.connect() as conn:
        conn.execute("UPDATE nf_web_sessions SET reauthenticated_at=clock_timestamp()-interval '6 minutes'")
    response = mutate(web, '/agents/' + result['agent_id'] + '/installation', {'server_url': 'https://host'})
    assert response.status_code == 409
    assert response.json()['detail']['code'] == 'reauth_required'


@pytest.mark.parametrize('url', ['http://host', 'https://u:p@host', 'https://@host', 'https://host/path',
    'https://host/?token=secret', 'https://host/#x', 'https://[', 'https://host:0', 'https://host:99999',
    'https://host;touch-file', 'https://host\n'])
def test_installation_url_rejects_invalid_origin(url):
    with pytest.raises(HTTPException):
        server_origin(url)


def test_package_contains_only_agent_runtime_and_no_secrets(tmp_path):
    content = agent_package()
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        assert set(archive.getnames()) == set(PACKAGE_FILES)
    installer.extract_package(content, tmp_path)
    assert (tmp_path / 'distributed/service.py').is_file()
    assert not (tmp_path / 'distributed/store.py').exists()


def test_installer_rejects_symlinks_in_archive(tmp_path):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w') as archive:
        for name in PACKAGE_FILES:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = '/etc/passwd'
            archive.addfile(info)
    with pytest.raises(RuntimeError, match='member'):
        installer.extract_package(content.getvalue(), tmp_path)


@pytest.fixture
def tls_server(certificate):
    cert, key = certificate
    received = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get('Authorization'))
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    try:
        yield 'https://127.0.0.1:' + str(server.server_port), pin, received
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_agent_validates_pinned_tls_before_sending_credentials(tls_server, tmp_path):
    url, pin, received = tls_server
    path = tmp_path / 'agent.key'; path.write_text('id.secret'); path.chmod(0o600)
    uploader = Uploader(url, path, tmp_path / 'state', 'eth0', cert_sha256=pin)
    assert uploader.request('GET', '/health') == {'ok': True}
    assert received == ['Bearer id.secret']
    uploader.session.close()
    uploader = Uploader(url, path, tmp_path / 'state', 'eth0', cert_sha256='0' * 64)
    with pytest.raises(requests.exceptions.SSLError):
        uploader.request('GET', '/health')
    assert received == ['Bearer id.secret']
    uploader.session.close()


def test_installer_transport_refuses_wrong_certificate_before_http(tls_server):
    url, pin, received = tls_server
    assert installer.fetch(dict(server=url, cert_sha256=pin), '/health') == b'{"ok":true}'
    assert received == [None]
    with pytest.raises(RuntimeError, match='certificate changed'):
        installer.fetch(dict(server=url, cert_sha256='0' * 64), '/v1/enroll', token='secret')
    assert received == [None]


def test_installer_preserves_existing_manual_installation(tmp_path, monkeypatch):
    root = tmp_path / 'manual'; root.mkdir(); important = root / 'agent-state.json'; important.write_text('preserve')
    monkeypatch.setattr(installer, 'ROOT', root)
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer, 'systemd_available', lambda: True)
    with pytest.raises(RuntimeError, match='not managed'):
        installer.main({})
    assert important.read_text() == 'preserve'


def test_installer_does_not_reassign_an_existing_host_to_another_agent(tmp_path, monkeypatch):
    root, config = tmp_path / 'managed', tmp_path / 'config'
    root.mkdir(); config.mkdir(); (root / '.managed-install').write_text('managed')
    saved = config / 'config.json'
    saved.write_text(json.dumps(dict(agent_id='old-agent', server='https://host', interface='eth0')))
    monkeypatch.setattr(installer, 'ROOT', root)
    monkeypatch.setattr(installer, 'CONFIG', config)
    monkeypatch.setattr(installer, 'UNIT_PATH', tmp_path / 'nfagent.service')
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer, 'systemd_available', lambda: True)
    with pytest.raises(RuntimeError, match='different agent'):
        installer.main(dict(agent_id='new-agent', server='https://host'))
    assert json.loads(saved.read_text())['agent_id'] == 'old-agent'


def test_installer_writes_unit_config_and_private_key_after_dependencies(tmp_path, monkeypatch):
    from distributed import service
    root, config, state, unit = (tmp_path / p for p in ('opt', 'etc', 'state', 'nfagent.service'))
    for name, path in [('ROOT', root), ('CONFIG', config), ('STATE', state), ('UNIT_PATH', unit)]:
        monkeypatch.setattr(installer, name, path)
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer, 'systemd_available', lambda: True)
    monkeypatch.setattr(installer, 'directory', lambda p: p.mkdir(parents=True, exist_ok=True))
    owner = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_shell='/usr/sbin/nologin')
    monkeypatch.setattr(installer.pwd, 'getpwnam', lambda name: owner)
    monkeypatch.setattr(service, 'capture_options', lambda *args: ('eth0', 'not upload traffic'))
    commands = []
    monkeypatch.setattr(installer, 'run', lambda *args, **kwargs: commands.append(args))
    key = 'a' * 16 + '.' + 'b' * 43
    def fetch(c, path, **kwargs):
        if path == '/install/agent.tar': return agent_package()
        assert commands and any('pip' in c for c in commands)
        return json.dumps({'key': key, 'agent_id': 'test-agent'}).encode()
    monkeypatch.setattr(installer, 'fetch', fetch)
    installer.main(dict(agent_id='test-agent', server='https://host', cert_sha256='a' * 64, token='one-use',
                        package_sha256=hashlib.sha256(agent_package()).hexdigest()))
    assert (config / 'agent.key').read_text() == key + '\n'
    assert (config / 'agent.key').stat().st_mode & 0o777 == 0o600
    assert (root / 'app').stat().st_mode & 0o777 == 0o755
    saved = json.loads((config / 'config.json').read_text())
    assert saved == dict(agent_id='test-agent', server='https://host', cert_sha256='a' * 64, interface='eth0')
    assert 'one-use' not in str(saved) and key not in unit.read_text()
    assert 'User=nfagent' in unit.read_text() and 'NoNewPrivileges=true' in unit.read_text()
    assert commands[-1] == ('systemctl', 'is-active', '--quiet', 'nfagent.service')
