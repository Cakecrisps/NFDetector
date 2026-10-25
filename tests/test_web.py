"""Browser auth and admin APIs, backed by the disposable PostgreSQL fixture."""
import hashlib

import pytest

from distributed.web_auth import COOKIE
from distributed.workers import parser_once
from test_distributed import system, capture, tcp_frame, register, upload

ORIGIN = {'Origin': 'https://testserver'}
PASSWORD = 'A private test passphrase 2026!'


@pytest.fixture
def web(system):
    client, store, agent_headers = system
    client.base_url = 'https://testserver'
    store.settings.public_origin = 'https://testserver'
    return client, store, agent_headers


def login(web, password='root', code=None):
    client, store, _ = web
    if code is None:
        code = client.app.state.web_auth.setup_path.read_text().strip() if client.app.state.web_auth.setup_path.exists() else ''
    return client.post('/admin/api/login', headers=ORIGIN,
                       json={'username': 'root', 'password': password, 'setup_code': code})


def mutate(web, path, body, csrf=None, origin=ORIGIN):
    client, _, _ = web
    if csrf is None:
        session = client.get('/admin/api/session').json()
        csrf = session.get('csrf_token', '')
    return client.post('/admin/api' + path, headers=dict(origin, **{'X-CSRF-Token': csrf}), json=body)


def full_login(web):
    response = login(web)
    assert response.status_code == 200, response.text
    response = mutate(web, '/password', {'current_password': 'root', 'new_password': PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def test_initial_root_requires_server_only_setup_code(web):
    client, store, _ = web
    assert client.get('/admin/api/session').json() == {'authenticated': False, 'setup_required': True}
    assert login(web, code='').status_code == 401
    response = login(web)
    assert response.status_code == 200
    assert response.json()['must_change_password'] is True
    cookie = response.headers['set-cookie'].lower()
    assert cookie.startswith('__host-nf_session=')
    assert 'secure' in cookie and 'httponly' in cookie and 'samesite=strict' in cookie and 'path=/' in cookie
    assert 'domain=' not in cookie
    assert store.settings.data_dir.joinpath('admin-setup-code').stat().st_mode & 0o077 == 0


def test_public_origin_must_be_configured_before_remote_login(web):
    _, store, _ = web
    store.settings.public_origin = ''
    response = login(web)
    assert response.status_code == 503
    assert response.json()['detail']['code'] == 'web_origin_required'
    store.settings.public_origin = 'https://testserver'
    assert login(web).status_code == 200


def test_forced_change_cannot_be_bypassed_by_calling_admin_apis(web):
    client, store, _ = web
    assert login(web).status_code == 200
    for route in ('/overview', '/traffic', '/agents', '/events', '/audit'):
        response = client.get('/admin/api' + route)
        assert response.status_code == 403
        assert response.json()['detail']['code'] == 'password_change_required'
    assert mutate(web, '/agents', {'name': 'bypass', 'domain': 'main', 'must_change_password': False}).status_code == 403
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM nf_agents WHERE name='bypass'").fetchone()['n'] == 0


def test_password_change_revokes_initial_cookie_and_never_reseeds_root(web):
    client, store, _ = web
    assert login(web).status_code == 200
    old = client.cookies.get(COOKIE)
    assert mutate(web, '/password', {'current_password': 'root', 'new_password': 'root'}).status_code == 400
    response = mutate(web, '/password', {'current_password': 'root', 'new_password': PASSWORD})
    assert response.status_code == 200 and not response.json()['must_change_password']
    assert client.cookies.get(COOKIE) != old
    assert not client.app.state.web_auth.setup_path.exists()
    assert client.get('/admin/api/overview', headers={'Cookie': COOKIE + '=' + old}).status_code == 401
    client.app.state.web_auth.bootstrap()
    assert not client.app.state.web_auth.setup_path.exists()
    assert login(web, password='root', code='').status_code == 401
    assert login(web, password=PASSWORD, code='').status_code == 200
    with store.connect() as conn:
        row = conn.execute("SELECT * FROM nf_web_users WHERE username='root'").fetchone()
        assert row['password_hash'].startswith('$argon2id$')
        assert row['bootstrap_hash'] is None and row['password_version'] == 2


def test_agent_keys_and_admin_cookies_are_not_interchangeable(web):
    client, _, agent_headers = web
    assert client.get('/admin/api/overview', headers=agent_headers).status_code == 401
    full_login(web)
    assert client.post('/v1/streams', json={'interface': 'eth0', 'started_at': 1000}).status_code == 401
    assert client.get('/docs').status_code == 404
    assert client.get('/openapi.json').status_code == 404


def test_csrf_and_exact_origin_are_required_for_mutations(web):
    client, _, _ = web
    full_login(web)
    body = {'name': 'forged', 'domain': 'main'}
    assert client.post('/admin/api/agents', json=body, headers=ORIGIN).status_code == 403
    assert mutate(web, '/agents', body, csrf='incorrect').status_code == 403
    for origin in ({}, {'Origin': 'null'}, {'Origin': 'https://testserver.attacker.test'}, {'Origin': 'http://testserver'}):
        assert mutate(web, '/agents', body, origin=origin).status_code == 403
    assert mutate(web, '/agents', body).status_code == 200


def test_request_validation_never_echoes_passwords(web):
    client, _, _ = web
    secret = 'not-to-be-reflected-' * 20
    response = client.post('/admin/api/login', headers=ORIGIN, json={'username': 'root', 'password': secret})
    assert response.status_code == 422 and secret not in response.text
    response = client.post('/admin/api/login', headers=ORIGIN, json={'password': 'x' * 9000})
    assert response.status_code == 413
    assert client.post('/admin/api/login', data={'username': 'root', 'password': 'root'}, headers=ORIGIN).status_code == 415


def test_failed_logins_are_rate_limited_and_secrets_are_not_audited(web):
    client, store, _ = web
    for _ in range(10):
        assert login(web, password='incorrect secret').status_code == 401
    response = login(web)
    assert response.status_code == 429 and response.headers['retry-after'] == '300'
    with store.connect() as conn:
        rows = conn.execute('SELECT * FROM nf_web_audit').fetchall()
        assert len(rows) == 10
        assert 'incorrect secret' not in str(rows)


def test_key_is_returned_only_on_creation_rotation_and_can_be_revoked(web):
    client, store, _ = web
    full_login(web)
    created = mutate(web, '/agents', {'name': 'gateway', 'domain': 'office'}).json()
    key, identity = created['key'], created['agent_id']
    assert store.authenticate(key)['id'] is not None
    listing = client.get('/admin/api/agents').text
    assert key not in listing and 'key_hash' not in listing and 'password_hash' not in listing
    with store.connect() as conn:
        saved = conn.execute('SELECT key_hash FROM nf_agents WHERE id=%s', (identity,)).fetchone()['key_hash']
    assert saved == hashlib.sha256(key.split('.', 1)[1].encode()).hexdigest()
    rotated = mutate(web, f'/agents/{identity}/rotate', {}).json()['key']
    assert rotated != key and store.authenticate(key) is None and store.authenticate(rotated)
    assert mutate(web, f'/agents/{identity}/revoke', {}).status_code == 200
    assert store.authenticate(rotated) is None
    audit = client.get('/admin/api/audit').text
    assert key not in audit and rotated not in audit and PASSWORD not in audit


def test_sensitive_key_actions_require_recent_password_confirmation(web):
    client, store, _ = web
    full_login(web)
    with store.connect() as conn:
        conn.execute("UPDATE nf_web_sessions SET reauthenticated_at=clock_timestamp()-interval '6 minutes'")
    response = mutate(web, '/agents', {'name': 'test', 'domain': 'main'})
    assert response.status_code == 409 and response.json()['detail']['code'] == 'reauth_required'
    assert mutate(web, '/reauth', {'password': 'wrong'}).status_code == 400
    assert mutate(web, '/reauth', {'password': PASSWORD}).status_code == 200
    assert mutate(web, '/agents', {'name': 'test', 'domain': 'main'}).status_code == 200


def test_expired_or_idle_session_cannot_read_statistics(web):
    client, store, _ = web
    full_login(web)
    with store.connect() as conn:
        conn.execute("UPDATE nf_web_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes'")
    assert client.get('/admin/api/overview').status_code == 401
    assert login(web, password=PASSWORD, code='').status_code == 200
    with store.connect() as conn:
        conn.execute("UPDATE nf_web_sessions SET expires_at=clock_timestamp()-interval '1 second'")
    assert client.get('/admin/api/overview').status_code == 401


def test_logout_revokes_server_session(web):
    client, _, _ = web
    full_login(web)
    token = client.cookies.get(COOKIE)
    assert mutate(web, '/logout', {}).status_code == 200
    assert client.get('/admin/api/overview', headers={'Cookie': COOKIE + '=' + token}).status_code == 401


def test_statistics_and_heartbeat_come_from_actual_agent_traffic(web):
    client, store, agent_headers = web
    full_login(web)
    stream = register(client, agent_headers)
    body = capture([(1000, tcp_frame()), (1000.1, tcp_frame())])
    assert upload(client, agent_headers, stream, 0, body).status_code == 201
    assert parser_once(store, 'test-parser')
    response = client.post('/v1/heartbeat', headers=agent_headers, json={'capture_state': 'capturing', 'backlog_bytes': 1024,
        'backlog_files': 1, 'software_version': 'test-1'})
    assert response.status_code == 200
    summary = client.get('/admin/api/overview').json()
    assert summary['agents']['online'] == 1
    assert summary['traffic']['packets'] == 2
    assert summary['traffic']['received_bytes'] == len(body)
    assert summary['traffic']['captured_bytes'] == 2 * len(tcp_frame())
    listing = client.get('/admin/api/agents').json()['agents'][0]
    assert listing['status'] == 'online' and listing['backlog_bytes'] == 1024 and listing['backlog_files'] == 1
    chart = client.get('/admin/api/traffic').json()
    assert len(chart['timeline']) == 24
    assert chart['protocols'] == [{'protocol': 'TCP', 'packets': 2}]
    assert sum(point['bytes'] for point in chart['timeline']) == len(body)


def test_admin_output_is_hardened_and_inputs_are_not_interpreted_as_sql(web):
    client, _, _ = web
    full_login(web)
    name = '<img src=x onerror=alert(1)>'
    assert mutate(web, '/agents', {'name': name, 'domain': 'main'}).status_code == 200
    listing = client.get('/admin/api/agents').json()
    assert any(agent['name'] == name for agent in listing['agents'])
    assert client.get('/admin/api/agents', params={'q': "'; DROP TABLE nf_agents; --"}).json()['total'] == 0
    for path in ('/', '/assets/app.js', '/admin/api/overview'):
        response = client.get(path)
        assert response.headers['cache-control'] == 'no-store'
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']
        assert "script-src 'self'" in response.headers['content-security-policy']
    assert client.get('/assets/../schema.sql').status_code == 404
