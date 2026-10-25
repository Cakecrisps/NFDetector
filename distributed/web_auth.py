"""Separate browser authentication with one-time setup, Argon2 and server-side sessions."""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException, Request, Response

from .capture import fsync_directory

COOKIE = '__Host-nf_session'
SESSION_HOURS = 8
IDLE_MINUTES = 30


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class WebAuth:
    def __init__(self, store):
        self.store, self.settings = store, store.settings
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
        self.hash_slots = threading.BoundedSemaphore(4)
        self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))
        self.setup_path = self.settings.data_dir / 'admin-setup-code'
        if self.settings.public_origin:
            parsed = urlsplit(self.settings.public_origin)
            if parsed.scheme != 'https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
                raise ValueError('NF_PUBLIC_URL must be an HTTPS origin without a path or credentials')

    def bootstrap(self):
        with self.store.connect() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(638101338)')
            existing = conn.execute("SELECT id FROM nf_web_users WHERE username='root'").fetchone()
            if existing:
                return
            code = secrets.token_urlsafe(32)
            temporary = self.setup_path.with_suffix('.tmp')
            descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write(code + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.setup_path)
            fsync_directory(self.setup_path.parent)
            conn.execute('''INSERT INTO nf_web_users(username,password_hash,must_change_password,bootstrap_hash)
                VALUES ('root',%s,true,%s)''', (self.hasher.hash('root'), digest(code)))

    def client_ip(self, request):
        raw = request.headers.get('x-real-ip', '') if self.settings.trust_proxy_headers else ''
        raw = raw or (request.client.host if request.client else 'unknown')
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return 'unknown'

    def origin(self, request):
        expected = self.settings.public_origin
        if not expected:
            # Unknown public Host headers must not choose the trusted admin origin.
            expected = 'https://' + request.headers.get('host', '')
            if urlsplit(expected).hostname not in ('localhost', '127.0.0.1', '::1'):
                raise HTTPException(503, detail={'code': 'web_origin_required',
                    'message': 'Задайте NF_PUBLIC_URL с публичным HTTPS-адресом панели'})
        origin = request.headers.get('origin', '')
        if not origin or origin == 'null' or origin != expected:
            raise HTTPException(403, detail={'code': 'origin_rejected', 'message': 'Запрос с другого сайта запрещён'})
        if request.headers.get('sec-fetch-site') in ('cross-site', 'same-site'):
            raise HTTPException(403, detail={'code': 'origin_rejected', 'message': 'Запрос с другого сайта запрещён'})

    def audit(self, request, action, subject='', actor='root', conn=None):
        args = (actor, action, self.client_ip(request), str(subject)[:256])
        sql = 'INSERT INTO nf_web_audit(actor,action,client_ip,subject) VALUES (%s,%s,%s,%s)'
        if conn is not None:
            conn.execute(sql, args)
        else:
            with self.store.connect() as connection:
                connection.execute(sql, args)

    def rate_limit(self, request, purpose='login'):
        blocked = False
        with self.store.connect() as conn:
            conn.execute('DELETE FROM nf_web_login_limits WHERE window_end<clock_timestamp()')
            for bucket, limit in ((purpose + ':global', 100), (purpose + ':ip:' + digest(self.client_ip(request)), 10)):
                row = conn.execute('''INSERT INTO nf_web_login_limits(bucket,window_end,attempts)
                    VALUES (%s,clock_timestamp()+interval '5 minutes',1)
                    ON CONFLICT(bucket) DO UPDATE SET attempts=nf_web_login_limits.attempts+1
                    RETURNING attempts''', (bucket,)).fetchone()
                if row['attempts'] > limit:
                    blocked = True
                    break
        if blocked:
            raise HTTPException(429, detail={'code': 'rate_limited', 'message': 'Слишком много попыток. Повторите через 5 минут'},
                                headers={'Retry-After': '300'})

    def verify(self, encoded, password):
        try:
            with self.hash_slots:
                return self.hasher.verify(encoded, password)
        except (VerificationError, InvalidHashError):
            return False

    def public_session(self, row):
        return dict(authenticated=True, username=row['username'], must_change_password=row['must_change_password'],
                    csrf_token=row['csrf_token'], expires_at=row['expires_at'],
                    agent_install_url=self.settings.agent_origin or self.settings.public_origin)

    def session(self, request, required=True):
        token = request.cookies.get(COOKIE, '')
        row = None
        if re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            with self.store.connect() as conn:
                row = conn.execute('''SELECT s.*,u.username,u.must_change_password,u.password_hash
                    FROM nf_web_sessions s JOIN nf_web_users u ON u.id=s.user_id
                    WHERE s.token_hash=%s AND s.password_version=u.password_version
                    AND s.expires_at>clock_timestamp()
                    AND s.last_seen_at>clock_timestamp()-(%s * interval '1 minute')''',
                                   (digest(token), IDLE_MINUTES)).fetchone()
        if row is None and required:
            raise HTTPException(401, detail={'code': 'login_required', 'message': 'Войдите в систему'})
        return row

    def full_session(self, request: Request):
        row = self.session(request)
        if row['must_change_password']:
            raise HTTPException(403, detail={'code': 'password_change_required', 'message': 'Сначала смените первоначальный пароль'})
        return row

    def authenticated_mutation(self, request: Request):
        row = self.session(request)
        self.origin(request)
        csrf = request.headers.get('x-csrf-token', '')
        if not csrf or not hmac.compare_digest(csrf, row['csrf_token']):
            raise HTTPException(403, detail={'code': 'csrf_rejected', 'message': 'Проверка запроса не пройдена'})
        with self.store.connect() as conn:
            conn.execute('UPDATE nf_web_sessions SET last_seen_at=clock_timestamp() WHERE token_hash=%s', (row['token_hash'],))
        return row

    def mutation(self, request: Request):
        row = self.authenticated_mutation(request)
        if row['must_change_password']:
            raise HTTPException(403, detail={'code': 'password_change_required', 'message': 'Сначала смените первоначальный пароль'})
        return row

    @staticmethod
    def require_fresh(row):
        age = (datetime.now(timezone.utc) - row['reauthenticated_at']).total_seconds()
        if age > 300:
            raise HTTPException(409, detail={'code': 'reauth_required', 'message': 'Подтвердите текущий пароль'})

    def new_session(self, conn, user, response):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        seconds = 900 if user['must_change_password'] else SESSION_HOURS * 3600
        # Bound persistent session state, and invalidate the oldest sessions beyond this limit.
        conn.execute('DELETE FROM nf_web_sessions WHERE expires_at<clock_timestamp()')
        conn.execute('''DELETE FROM nf_web_sessions WHERE token_hash IN
            (SELECT token_hash FROM nf_web_sessions WHERE user_id=%s ORDER BY created_at DESC OFFSET 9)''', (user['id'],))
        row = conn.execute('''INSERT INTO nf_web_sessions(token_hash,user_id,password_version,csrf_token,expires_at)
            VALUES (%s,%s,%s,%s,clock_timestamp()+(%s * interval '1 second')) RETURNING *''',
                           (digest(token), user['id'], user['password_version'], csrf, seconds)).fetchone()
        response.set_cookie(COOKIE, token, max_age=seconds, secure=True, httponly=True, samesite='strict', path='/')
        return self.public_session(dict(row, username=user['username'], must_change_password=user['must_change_password']))

    def login(self, request, response, username, password, setup_code):
        self.origin(request)
        self.rate_limit(request)
        with self.store.connect() as conn:
            user = conn.execute('SELECT * FROM nf_web_users WHERE username=%s', (username,)).fetchone()
        verified = self.verify(user['password_hash'] if user else self.dummy_hash, password)
        setup_valid = user is not None and (not user['must_change_password'] or
                      hmac.compare_digest(user['bootstrap_hash'] or '', digest(setup_code)))
        if not verified or not setup_valid:
            self.audit(request, 'login_failed', actor='anonymous')
            raise HTTPException(401, detail={'code': 'invalid_credentials', 'message': 'Неверные данные входа или код установки'})
        with self.store.connect() as conn:
            current = conn.execute('SELECT * FROM nf_web_users WHERE id=%s FOR UPDATE', (user['id'],)).fetchone()
            if current['password_version'] != user['password_version']:
                raise HTTPException(401, detail={'code': 'invalid_credentials', 'message': 'Повторите вход'})
            result = self.new_session(conn, current, response)
            self.audit(request, 'login_succeeded', conn=conn)
        return result

    def change_password(self, request, response, session, current_password, new_password):
        self.rate_limit(request, 'password')
        if len(new_password) < 15 or len(new_password) > 128 or new_password == current_password:
            raise HTTPException(400, detail={'code': 'weak_password', 'message': 'Новый пароль: от 15 до 128 символов, отличный от прежнего'})
        if new_password.casefold() in ('passwordpassword', '123456789012345', '1234567890123456', 'qwertyuiopasdfgh'):
            raise HTTPException(400, detail={'code': 'weak_password', 'message': 'Выберите менее распространённый пароль'})
        with self.store.connect() as conn:
            user = conn.execute('SELECT * FROM nf_web_users WHERE id=%s FOR UPDATE', (session['user_id'],)).fetchone()
            if user['password_version'] != session['password_version'] or not self.verify(user['password_hash'], current_password):
                raise HTTPException(400, detail={'code': 'invalid_password', 'message': 'Текущий пароль неверен'})
            with self.hash_slots:
                encoded = self.hasher.hash(new_password)
            user = conn.execute('''UPDATE nf_web_users SET password_hash=%s,must_change_password=false,
                bootstrap_hash=NULL,password_version=password_version+1 WHERE id=%s RETURNING *''', (encoded, user['id'])).fetchone()
            conn.execute('DELETE FROM nf_web_sessions WHERE user_id=%s', (user['id'],))
            self.audit(request, 'password_changed', conn=conn)
            result = self.new_session(conn, user, response)
        self.setup_path.unlink(missing_ok=True)
        return result
