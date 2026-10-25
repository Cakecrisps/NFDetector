"""Authenticated binary upload API. No public endpoint issues administrative keys."""
import hashlib
import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .capture import MAGICS, fsync_directory
from .settings import Settings
from .store import Store
from .web import install_web
from .web_security import WebSecurityMiddleware


class StreamRequest(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    interface: str = Field(min_length=1, max_length=128)
    started_at: float = Field(ge=0, allow_inf_nan=False)


class HeartbeatRequest(BaseModel):
    capture_state: str = Field(default='idle', pattern=r'^(idle|capturing|uploading|stopped|error)$')
    backlog_bytes: int = Field(default=0, ge=0, le=2**63-1)
    backlog_files: int = Field(default=0, ge=0, le=2**31-1)
    software_version: str = Field(default='', max_length=64)
    last_error: str = Field(default='', max_length=512)


class SealRequest(BaseModel):
    last_sequence: int = Field(ge=-1)


def create_app(settings=None):
    settings = settings or Settings.from_env()
    store = Store(settings)

    @asynccontextmanager
    async def lifespan(app):
        settings.prepare()
        await run_in_threadpool(store.initialize)
        await run_in_threadpool(app.state.web_auth.bootstrap)
        yield

    app = FastAPI(title='NFDetect', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    install_web(app, store)
    app.add_middleware(WebSecurityMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        # Pydantic normally echoes the rejected input, including password fields.
        safe = [{key: item[key] for key in ('loc', 'msg', 'type')} for item in error.errors()]
        return JSONResponse({'detail': safe}, status_code=422)

    def authenticate(request: Request):
        scheme, _, token = request.headers.get('authorization', '').partition(' ')
        agent = store.authenticate(token) if scheme.lower() == 'bearer' and len(token) <= 512 else None
        if not agent:
            raise HTTPException(401, 'Invalid or revoked agent key', headers={'WWW-Authenticate': 'Bearer'})
        return agent

    def own_stream(conn, stream_id, agent, lock=False):
        row = conn.execute('SELECT * FROM nf_streams WHERE id=%s AND agent_id=%s' + (' FOR UPDATE' if lock else ''),
                           (stream_id, agent['id'])).fetchone()
        if not row:
            raise HTTPException(404, 'Stream not found')
        return row

    @app.get('/health')
    def health():
        with store.connect() as conn:
            conn.execute('SELECT 1')
        return {'status': 'ok'}

    @app.post('/v1/enroll')
    def enroll(request: Request):
        scheme, _, token = request.headers.get('authorization', '').partition(' ')
        if scheme != 'Enrollment' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise HTTPException(401, 'Invalid or expired installation code')
        with store.connect() as conn:
            digest = hashlib.sha256(token.encode()).hexdigest()
            identity = conn.execute('SELECT agent_id FROM nf_agent_installations WHERE token_hash=%s', (digest,)).fetchone()
            if not identity:
                raise HTTPException(401, 'Invalid or expired installation code')
            # All admin actions acquire agent -> grant locks in this order too.
            agent = conn.execute('SELECT * FROM nf_agents WHERE id=%s FOR UPDATE', (identity['agent_id'],)).fetchone()
            grant = conn.execute('''SELECT * FROM nf_agent_installations WHERE token_hash=%s
                AND used_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE''', (digest,)).fetchone()
            if not grant or not agent or agent['revoked'] or grant['key_id'] != agent['key_id']:
                raise HTTPException(401, 'Invalid or expired installation code')
            # Fresh operational key: the bootstrap command never contains it.
            key_id, secret = secrets.token_hex(8), secrets.token_urlsafe(32)
            conn.execute('UPDATE nf_agents SET key_id=%s,key_hash=%s WHERE id=%s',
                         (key_id, hashlib.sha256(secret.encode()).hexdigest(), grant['agent_id']))
            conn.execute('UPDATE nf_agent_installations SET used_at=clock_timestamp() WHERE token_hash=%s',
                         (grant['token_hash'],))
            app.state.web_auth.audit(request, 'agent_installed', grant['agent_id'], actor='installer', conn=conn)
        return dict(agent_id=str(grant['agent_id']), key=key_id + '.' + secret, server_url=grant['server_url'])

    @app.post('/v1/streams')
    def register(body: StreamRequest, agent=Depends(authenticate)):
        with store.connect() as conn:
            domain = conn.execute('SELECT *,lease_until>clock_timestamp() AS busy FROM nf_domains WHERE id=%s FOR UPDATE',
                                  (agent['domain'],)).fetchone()
            existing = conn.execute('SELECT * FROM nf_streams WHERE id=%s', (body.id,)).fetchone()
            if existing:
                if existing['agent_id'] != agent['id'] or existing['interface'] != body.interface or existing['started_at'] != body.started_at:
                    raise HTTPException(409, 'Stream identity conflict')
                return {'stream_id': str(body.id), 'max_upload_bytes': settings.max_upload}
            active = conn.execute('SELECT count(*) AS n FROM nf_streams WHERE agent_id=%s AND last_sequence IS NULL', (agent['id'],)).fetchone()['n']
            if active >= settings.max_streams:
                raise HTTPException(429, 'Too many open capture streams', headers={'Retry-After': '5'})
            if domain['owner'] is not None and domain['busy']:
                raise HTTPException(503, 'Retry registration after the current detector batch', headers={'Retry-After': '1'})
            if domain['last_timestamp'] is not None and body.started_at < domain['last_timestamp']:
                raise HTTPException(409, 'Capture starts before domain watermark; use a separate replay domain')
            conn.execute('INSERT INTO nf_streams(id,agent_id,interface,started_at) VALUES (%s,%s,%s,%s)',
                         (body.id, agent['id'], body.interface, body.started_at))
            conn.execute('UPDATE nf_domains SET work_version=work_version+1 WHERE id=%s', (agent['domain'],))
        return {'stream_id': str(body.id), 'max_upload_bytes': settings.max_upload}

    def publish(stream_id, sequence, agent, path, size, checksum):
        with store.connect() as conn:
            stream = own_stream(conn, stream_id, agent, lock=True)
            # Serialize per-agent quota accounting across its streams.
            conn.execute('SELECT id FROM nf_agents WHERE id=%s FOR UPDATE', (agent['id'],))
            existing = conn.execute('SELECT * FROM nf_chunks WHERE stream_id=%s AND sequence=%s', (stream_id, sequence)).fetchone()
            if existing:
                if existing['sha256'] != checksum or existing['size'] != size:
                    raise HTTPException(409, 'Sequence already contains different content')
                return False, existing
            if stream['last_sequence'] is not None:
                raise HTTPException(409, 'Stream has been sealed')
            backlog = conn.execute('''SELECT COALESCE(sum(c.size),0) AS bytes FROM nf_chunks c
                JOIN nf_streams s ON s.id=c.stream_id WHERE s.agent_id=%s''',
                                   (agent['id'],)).fetchone()['bytes']
            if backlog + size > settings.max_backlog:
                raise HTTPException(429, 'Agent retained capture quota exceeded', headers={'Retry-After': '5'})
            destination = settings.data_dir / 'captures' / f'{uuid.uuid4().hex}.pcap'
            os.replace(path, destination)
            fsync_directory(destination.parent)
            row = conn.execute('''INSERT INTO nf_chunks(stream_id,sequence,sha256,size,path) VALUES (%s,%s,%s,%s,%s) RETURNING *''',
                               (stream_id, sequence, checksum, size, str(destination))).fetchone()
            # A crash before commit can leave an unreferenced capture, never an acknowledged missing capture.
        return True, row

    @app.put('/v1/streams/{stream_id}/chunks/{sequence}')
    async def upload(stream_id: uuid.UUID, sequence: int, request: Request, response: Response, agent=Depends(authenticate)):
        if sequence < 0 or sequence > 2_147_483_647:
            raise HTTPException(400, 'Invalid sequence')
        checksum = request.headers.get('x-content-sha256', '')
        if not re.fullmatch('[0-9a-f]{64}', checksum):
            raise HTTPException(400, 'X-Content-SHA256 must be a lowercase SHA-256 digest')
        if request.headers.get('content-type', '').split(';')[0] != 'application/octet-stream':
            raise HTTPException(415, 'Use application/octet-stream')
        try:
            length = int(request.headers['content-length'])
        except (KeyError, ValueError):
            raise HTTPException(411, 'Content-Length is required')
        if length < 4 or length > settings.max_upload:
            raise HTTPException(413, 'Capture exceeds upload limit')
        with store.connect() as conn:
            own_stream(conn, stream_id, agent)
        path = settings.data_dir / 'incoming' / uuid.uuid4().hex
        digest, size, prefix = hashlib.sha256(), 0, b''
        try:
            with path.open('xb') as handle:
                async for block in request.stream():
                    size += len(block)
                    if size > length or size > settings.max_upload:
                        raise HTTPException(413, 'Capture exceeds declared length')
                    prefix = (prefix + block)[:4] if len(prefix) < 4 else prefix
                    digest.update(block)
                    await run_in_threadpool(handle.write, block)
                await run_in_threadpool(handle.flush)
                await run_in_threadpool(os.fsync, handle.fileno())
            if size != length or digest.hexdigest() != checksum:
                raise HTTPException(400, 'Capture size or SHA-256 mismatch')
            if prefix not in MAGICS:
                raise HTTPException(400, 'Expected PCAP or PCAPNG')
            created, row = await run_in_threadpool(publish, stream_id, sequence, agent, path, size, checksum)
            response.status_code = 201 if created else 200
            return dict(stream_id=str(stream_id), sequence=sequence, sha256=checksum, stored=True, analysis_status=row['status'])
        finally:
            path.unlink(missing_ok=True)

    @app.post('/v1/streams/{stream_id}/seal')
    def seal(stream_id: uuid.UUID, body: SealRequest, agent=Depends(authenticate)):
        with store.connect() as conn:
            conn.execute('UPDATE nf_domains SET work_version=work_version+1 WHERE id=%s', (agent['domain'],))
            row = own_stream(conn, stream_id, agent, lock=True)
            if row['last_sequence'] is not None and row['last_sequence'] != body.last_sequence:
                raise HTTPException(409, 'Stream was sealed with a different sequence')
            count = conn.execute('SELECT count(*) AS n FROM nf_chunks WHERE stream_id=%s AND sequence<=%s',
                                 (stream_id, body.last_sequence)).fetchone()['n']
            maximum = conn.execute('SELECT max(sequence) AS n FROM nf_chunks WHERE stream_id=%s', (stream_id,)).fetchone()['n']
            if count != body.last_sequence + 1 or (maximum is not None and maximum > body.last_sequence):
                raise HTTPException(409, 'Upload the complete continuous sequence before sealing')
            conn.execute('UPDATE nf_streams SET last_sequence=%s WHERE id=%s', (body.last_sequence, stream_id))
        return {'sealed': True, 'last_sequence': body.last_sequence}

    @app.get('/v1/streams/{stream_id}/status')
    def status(stream_id: uuid.UUID, agent=Depends(authenticate)):
        with store.connect() as conn:
            stream = own_stream(conn, stream_id, agent)
            chunks = conn.execute('SELECT sequence,status,error,owner,generation,frames,parsed_by,parser_finished_at FROM nf_chunks WHERE stream_id=%s ORDER BY sequence',
                                  (stream_id,)).fetchall()
            domain = conn.execute('SELECT id,last_timestamp,error FROM nf_domains WHERE id=%s', (agent['domain'],)).fetchone()
        return {'stream_id': str(stream_id), 'last_sequence': stream['last_sequence'], 'processed_sequence': stream['processed_sequence'], 'chunks': chunks, 'detector': domain}

    @app.post('/v1/heartbeat')
    def heartbeat(body: HeartbeatRequest, agent=Depends(authenticate)):
        with store.connect() as conn:
            conn.execute('''UPDATE nf_agents SET last_heartbeat_at=clock_timestamp(),capture_state=%s,
                backlog_bytes=%s,backlog_files=%s,software_version=%s,last_error=%s WHERE id=%s''',
                         (body.capture_state, body.backlog_bytes, body.backlog_files,
                          body.software_version, body.last_error, agent['id']))
        return {'ok': True}

    @app.get('/v1/events')
    def events(limit: int = 100, agent=Depends(authenticate)):
        if not 1 <= limit <= 1000:
            raise HTTPException(400, 'limit must be between 1 and 1000')
        with store.connect() as conn:
            rows = conn.execute('SELECT e.* FROM nf_events e JOIN nf_streams s ON s.id=e.stream_id WHERE e.domain=%s AND s.agent_id=%s ORDER BY e.created_at DESC,e.id LIMIT %s', (agent['domain'], agent['id'], limit)).fetchall()
        return {'events': rows}

    return app
