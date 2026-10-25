"""One-time agent enrollment and reproducible, secret-free installation artifacts."""
import base64
import hashlib
import io
import json
import re
import secrets
import shlex
import ssl
import tarfile
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException

PACKAGE_FILES = ('distributed/__init__.py', 'distributed/__main__.py', 'distributed/agent.py',
                 'distributed/capture.py', 'distributed/tls.py', 'distributed/service.py',
                 'requirements-agent.txt')


@lru_cache(maxsize=1)
def agent_package():
    root = Path(__file__).resolve().parent.parent
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name in PACKAGE_FILES:
            content = (root / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o644
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def installer_source():
    return Path(__file__).with_name('installer.py').read_bytes()


def server_origin(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise HTTPException(400, 'Некорректный порт сервера')
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', parsed.hostname)
            or any(ch.isspace() or ord(ch) < 32 for ch in value) or port == 0):
        raise HTTPException(400, 'Укажите HTTPS-адрес сервера без пути, параметров и учётных данных')
    return value.rstrip('/')


def certificate_pin(settings):
    try:
        certificate = settings.tls_public_cert.read_text()
        # PEM_cert_to_DER_cert accepts one certificate; only the leaf is pinned.
        end = certificate.index('-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')
        der = ssl.PEM_cert_to_DER_cert(certificate[:end])
    except (OSError, ValueError):
        raise HTTPException(503, 'Публичный сертификат LB недоступен. Обновите конфигурацию Compose и LB')
    return hashlib.sha256(der).hexdigest()


def install_grant(store, conn, agent_id, key_id, server, interface=''):
    server = server_origin(server)
    if interface and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface):
        raise HTTPException(400, 'Некорректное имя интерфейса')
    config = dict(agent_id=str(agent_id), server=server, cert_sha256=certificate_pin(store.settings), interface=interface,
                  installer_sha256=hashlib.sha256(installer_source()).hexdigest(),
                  package_sha256=hashlib.sha256(agent_package()).hexdigest())
    token = secrets.token_urlsafe(32)
    conn.execute('DELETE FROM nf_agent_installations WHERE agent_id=%s OR expires_at<clock_timestamp()', (agent_id,))
    row = conn.execute('''INSERT INTO nf_agent_installations(token_hash,agent_id,key_id,server_url)
        VALUES (%s,%s,%s,%s) RETURNING expires_at''',
                       (hashlib.sha256(token.encode()).hexdigest(), agent_id, key_id, server)).fetchone()
    config['token'] = token
    # The downloaded root installer is checked against the digest from this
    # authenticated admin response. Compare the TLS peer BEFORE any HTTP request.
    bootstrap = (
        'import base64,json,ssl,http.client,hashlib,hmac,sys;'
        'from urllib.parse import urlsplit;'
        f'c=json.loads(base64.b64decode({base64.b64encode(json.dumps(config).encode()).decode()!r}));'
        'u=urlsplit(c["server"]);'
        's=http.client.HTTPSConnection(u.hostname,u.port or 443,context=ssl._create_unverified_context(),timeout=30);'
        's.connect();'
        'h=hashlib.sha256(s.sock.getpeercert(binary_form=True)).hexdigest();'
        'hmac.compare_digest(h,c["cert_sha256"]) or sys.exit("Server certificate changed; get a new command from the panel");'
        's.request("GET","/install/agent.py");r=s.getresponse();b=r.read(262145);s.close();'
        '(r.status==200 and len(b)<=262144) or sys.exit("Cannot download installer");'
        'hmac.compare_digest(hashlib.sha256(b).hexdigest(),c["installer_sha256"]) or sys.exit("Installer version changed; get a new command");'
        'exec(compile(b,"<NFDetect installer>","exec"),{"__name__":"__main__","INSTALL_CONFIG":c})'
    )
    return dict(command='sudo python3 -c ' + shlex.quote(bootstrap), expires_at=row['expires_at'],
                server_url=server, interface=interface)
