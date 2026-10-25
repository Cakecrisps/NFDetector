"""Browser administration served by the existing API behind the existing TLS LB."""
import hashlib
import secrets
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import web_metrics
from .web_auth import COOKIE, WebAuth


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)
    setup_code: str = Field(default='', max_length=128)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class PasswordConfirm(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    domain: str = Field(min_length=1, max_length=128)


def install_web(app, store):
    auth = WebAuth(store)
    app.state.web_auth = auth
    router = APIRouter(prefix='/admin/api')
    assets = Path(__file__).with_name('web')
    app.mount('/assets', StaticFiles(directory=assets), name='assets')

    @app.get('/', include_in_schema=False)
    def index():
        return FileResponse(assets / 'index.html')

    @router.get('/session')
    def session(request: Request, response: Response):
        row = auth.session(request, required=False)
        if row:
            return auth.public_session(row)
        response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='strict')
        with store.connect() as conn:
            user = conn.execute("SELECT must_change_password FROM nf_web_users WHERE username='root'").fetchone()
        return dict(authenticated=False, setup_required=bool(user and user['must_change_password']))

    @router.post('/login')
    def login(body: Login, request: Request, response: Response):
        return auth.login(request, response, body.username.strip(), body.password, body.setup_code.strip())

    @router.post('/password')
    def password(body: PasswordChange, request: Request, response: Response, row=Depends(auth.authenticated_mutation)):
        return auth.change_password(request, response, row, body.current_password, body.new_password)

    @router.post('/logout')
    def logout(request: Request, response: Response, row=Depends(auth.authenticated_mutation)):
        with store.connect() as conn:
            conn.execute('DELETE FROM nf_web_sessions WHERE token_hash=%s', (row['token_hash'],))
            auth.audit(request, 'logged_out', conn=conn)
        response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='strict')
        return {'ok': True}

    @router.post('/session/touch')
    def touch(row=Depends(auth.authenticated_mutation)):
        return {'ok': True}

    @router.post('/reauth')
    def reauthenticate(body: PasswordConfirm, request: Request, row=Depends(auth.mutation)):
        auth.rate_limit(request, 'reauth')
        if not auth.verify(row['password_hash'], body.password):
            raise HTTPException(400, detail={'code': 'invalid_password', 'message': 'Текущий пароль неверен'})
        with store.connect() as conn:
            result = conn.execute('''UPDATE nf_web_sessions SET reauthenticated_at=clock_timestamp()
                WHERE token_hash=%s RETURNING token_hash''', (row['token_hash'],)).fetchone()
            if not result:
                raise HTTPException(401, detail={'code': 'login_required', 'message': 'Повторите вход'})
            auth.audit(request, 'reauthenticated', conn=conn)
        return {'ok': True}

    @router.get('/overview')
    def overview(row=Depends(auth.full_session)):
        return web_metrics.overview(store)

    @router.get('/traffic')
    def traffic(hours: int = 24, row=Depends(auth.full_session)):
        if hours not in (1, 24, 168):
            raise HTTPException(400, 'Выберите период 1, 24 или 168 часов')
        return web_metrics.traffic(store, hours)

    @router.get('/agents')
    def agents(q: str = '', offset: int = 0, limit: int = 100, row=Depends(auth.full_session)):
        if len(q) > 128 or offset < 0 or not 1 <= limit <= 200:
            raise HTTPException(400, 'Некорректные параметры списка')
        return web_metrics.agents(store, q, offset, limit)

    @router.get('/agents/{agent_id}/streams')
    def agent_streams(agent_id: uuid.UUID, row=Depends(auth.full_session)):
        return {'streams': web_metrics.streams(store, agent_id)}

    @router.post('/agents')
    def issue(body: AgentCreate, request: Request, row=Depends(auth.mutation)):
        auth.require_fresh(row)
        name, domain = body.name.strip(), body.domain.strip()
        if not name or not domain:
            raise HTTPException(400, 'Укажите имя и домен наблюдения')
        # Keep key issuance and audit in the same transaction; return the secret only once.
        secret, key_id = secrets.token_urlsafe(32), secrets.token_hex(8)
        identity = uuid.uuid4()
        with store.connect() as conn:
            conn.execute('INSERT INTO nf_domains(id) VALUES (%s) ON CONFLICT DO NOTHING', (domain,))
            conn.execute('INSERT INTO nf_agents(id,name,domain,key_id,key_hash) VALUES (%s,%s,%s,%s,%s)',
                         (identity, name, domain, key_id, hashlib.sha256(secret.encode()).hexdigest()))
            auth.audit(request, 'agent_key_created', identity, conn=conn)
        return dict(agent_id=str(identity), name=name, key=key_id + '.' + secret)

    @router.post('/agents/{agent_id}/rotate')
    def rotate(agent_id: uuid.UUID, request: Request, row=Depends(auth.mutation)):
        auth.require_fresh(row)
        secret, key_id = secrets.token_urlsafe(32), secrets.token_hex(8)
        with store.connect() as conn:
            agent = conn.execute('''UPDATE nf_agents SET key_id=%s,key_hash=%s,revoked=false
                WHERE id=%s RETURNING name''', (key_id, hashlib.sha256(secret.encode()).hexdigest(), agent_id)).fetchone()
            if not agent:
                raise HTTPException(404, 'Агент не найден')
            auth.audit(request, 'agent_key_rotated', agent_id, conn=conn)
        return dict(agent_id=str(agent_id), name=agent['name'], key=key_id + '.' + secret)

    @router.post('/agents/{agent_id}/revoke')
    def revoke(agent_id: uuid.UUID, request: Request, row=Depends(auth.mutation)):
        auth.require_fresh(row)
        with store.connect() as conn:
            result = conn.execute('UPDATE nf_agents SET revoked=true WHERE id=%s RETURNING id', (agent_id,)).fetchone()
            if not result:
                raise HTTPException(404, 'Агент не найден')
            auth.audit(request, 'agent_key_revoked', agent_id, conn=conn)
        return {'revoked': True}

    @router.get('/events')
    def events(kind: str = '', q: str = '', offset: int = 0, limit: int = 50, row=Depends(auth.full_session)):
        if len(kind) > 64 or len(q) > 128 or offset < 0 or not 1 <= limit <= 200:
            raise HTTPException(400, 'Некорректные параметры списка')
        return web_metrics.events(store, kind, q, offset, limit)

    @router.get('/audit')
    def audit(row=Depends(auth.full_session)):
        with store.connect() as conn:
            rows = conn.execute('SELECT actor,action,client_ip,subject,created_at FROM nf_web_audit ORDER BY id DESC LIMIT 100').fetchall()
        return {'entries': rows}

    app.include_router(router)
    return auth
