"""Downloaded by a digest-checked bootstrap. This file uses Python stdlib only."""
import hashlib
import hmac
import http.client
import io
import json
import os
import pwd
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path('/opt/nfagent')
CONFIG = Path('/etc/nfagent')
STATE = Path('/var/lib/nfagent')
UNIT_PATH = Path('/etc/systemd/system/nfagent.service')
UNIT = '''[Unit]
Description=NFDetect capture agent
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=nfagent
Group=nfagent
WorkingDirectory=/opt/nfagent/app
ExecStart=/opt/nfagent/venv/bin/python -m distributed.service
Restart=on-failure
RestartSec=10
TimeoutStopSec=90
KillSignal=SIGINT
KillMode=mixed
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
ReadWritePaths=/var/lib/nfagent

[Install]
WantedBy=multi-user.target
'''


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def fetch(config, path, token=None, limit=4 * 1024 * 1024):
    url = urlsplit(config['server'])
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443,
        context=ssl._create_unverified_context(), timeout=60)
    try:
        connection.connect()
        actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(actual, config['cert_sha256']):
            raise RuntimeError('Server certificate changed. Generate a new installation command.')
        headers = {'Authorization': 'Enrollment ' + token} if token else {}
        connection.request('POST' if token else 'GET', path, body=b'' if token else None, headers=headers)
        response = connection.getresponse()
        content = response.read(limit + 1)
        if response.status != 200 or len(content) > limit:
            raise RuntimeError(f'Server rejected installation ({response.status}). Generate a new command in the panel.')
        return content
    finally:
        connection.close()


def directory(path, mode=0o755):
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise RuntimeError(f'Unsafe installation path: {path}')
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise RuntimeError(f'Installation directory must be owned by root and not writable by others: {path}')
    path.chmod(mode)


def private_file(path, value, owner):
    if path.is_symlink():
        raise RuntimeError(f'Unsafe credential path: {path}')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        os.fchown(handle.fileno(), owner.pw_uid, owner.pw_gid)
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def extract_package(content, destination):
    expected = {'distributed/__init__.py', 'distributed/__main__.py', 'distributed/agent.py',
                'distributed/capture.py', 'distributed/tls.py', 'distributed/service.py', 'requirements-agent.txt'}
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != expected:
            raise RuntimeError('Invalid agent package contents')
        for member in members:
            if not member.isfile() or member.size > 1024 * 1024:
                raise RuntimeError('Invalid agent package member')
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.parent.chmod(0o755)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(0o644)


def main(config):
    if os.geteuid() != 0:
        raise RuntimeError('Run the installation command with sudo or as root.')
    if not systemd_available():
        raise RuntimeError('A Linux host running systemd is required.')
    if ROOT.exists() and not (ROOT / '.managed-install').is_file():
        raise RuntimeError('/opt/nfagent already exists and is not managed by this installer. Existing files were preserved.')
    if UNIT_PATH.exists() and not (ROOT / '.managed-install').is_file():
        raise RuntimeError('nfagent.service already exists. Existing service was preserved.')
    existing = CONFIG / 'config.json'
    if existing.exists():
        previous = json.loads(existing.read_text())
        if previous.get('agent_id') != config.get('agent_id') or previous.get('server') != config['server']:
            raise RuntimeError('This host already belongs to a different agent or server. Existing spool was preserved.')
        if config.get('interface') and previous.get('interface') != config['interface']:
            raise RuntimeError('Changing the interface requires explicitly finishing the previous capture first.')
    for path in (ROOT, CONFIG):
        directory(path)
    # Permit a safe retry if dependency installation fails before enrollment.
    (ROOT / '.managed-install').write_text('NFDetect managed installation v1\n')
    content = fetch(config, '/install/agent.tar')
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), config['package_sha256']):
        raise RuntimeError('Agent package version changed. Generate a new installation command.')
    print('Installing NFDetect dependencies...', flush=True)
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    if shutil.which('apt-get'):
        run('apt-get', 'update', env=env)
        run('apt-get', 'install', '-y', '--no-install-recommends', 'python3', 'python3-venv',
            'wireshark-common', 'iproute2', 'ca-certificates', env=env)
    elif shutil.which('dnf'):
        run('dnf', 'install', '-y', 'python3', 'python3-pip', 'wireshark-cli', 'iproute', 'ca-certificates')
    else:
        raise RuntimeError('Supported package managers: apt-get (Debian/Ubuntu), dnf (Fedora/RHEL).')
    try:
        owner = pwd.getpwnam('nfagent')
        if owner.pw_uid == 0 or owner.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
            raise RuntimeError('The existing nfagent account is not a dedicated service account.')
    except KeyError:
        run('useradd', '--system', '--user-group', '--home-dir', str(STATE), '--shell',
            shutil.which('nologin') or '/usr/sbin/nologin', 'nfagent')
        owner = pwd.getpwnam('nfagent')
    import grp
    try:
        grp.getgrnam('wireshark')
        run('usermod', '-a', '-G', 'wireshark', 'nfagent')
    except KeyError:
        pass
    if STATE.is_symlink():
        raise RuntimeError('Unsafe state directory')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE, owner.pw_uid, owner.pw_gid)
    os.chmod(STATE, 0o700)
    with tempfile.TemporaryDirectory(prefix='.install-', dir=ROOT) as stage:
        stage = Path(stage)
        extract_package(content, stage)
        run('python3', '-m', 'venv', str(ROOT / 'venv'), umask=0o022)
        run(str(ROOT / 'venv/bin/python'), '-m', 'pip', 'install', '--disable-pip-version-check',
            '-r', str(stage / 'requirements-agent.txt'), umask=0o022)
        # Resolve interface and validate the transport before consuming the grant.
        sys.path.insert(0, str(stage))
        sys.path.insert(0, str(ROOT / 'venv/lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages'))
        from distributed.service import capture_options
        interface, _ = capture_options(config['server'], config.get('interface', ''))
        # An installation grant can be used once. The permanent key exists only
        # in this TLS response and in the private local credential file.
        credentials = json.loads(fetch(config, '/v1/enroll', token=config['token'], limit=8192))
        if credentials.get('agent_id') != config['agent_id']:
            raise RuntimeError('Enrollment returned a different agent identity')
        key = credentials['key']
        if not re.fullmatch(r'[a-f0-9]{16}\.[A-Za-z0-9_-]{40,64}', key):
            raise RuntimeError('Invalid enrollment response')
        if UNIT_PATH.exists():
            run('systemctl', 'stop', 'nfagent.service')
        private_file(CONFIG / 'agent.key', key + '\n', owner)
        private_file(CONFIG / 'config.json', json.dumps(dict(agent_id=config['agent_id'], server=config['server'],
            interface=interface, cert_sha256=config['cert_sha256'])) + '\n', owner)
        destination = ROOT / 'app'
        if destination.is_symlink():
            raise RuntimeError('Unsafe application directory')
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(stage, destination)
        destination.chmod(0o755)  # TemporaryDirectory starts with root-only 0700.
    (ROOT / '.managed-install').write_text('NFDetect managed installation v1\n')
    UNIT_PATH.write_text(UNIT)
    UNIT_PATH.chmod(0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'nfagent.service')
    run('systemctl', 'is-active', '--quiet', 'nfagent.service')
    print(f'NFDetect installed. Interface: {interface}. Service: nfagent.service. Logs: journalctl -u nfagent -f')


def systemd_available():
    return Path('/run/systemd/system').is_dir()


if __name__ == '__main__':
    try:
        main(INSTALL_CONFIG)
    except Exception as error:
        print(f'NFDetect installation failed: {error}', file=sys.stderr)
        sys.exit(1)
