"""Managed agent entry point; credentials stay in private files, never argv."""
import ipaddress
import json
import re
import signal
import socket
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

from .agent import Uploader, run_capture


def capture_options(server, interface=''):
    parsed = urlsplit(server)
    addresses = sorted({str(ipaddress.ip_address(item[4][0])) for item in
                        socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError('Cannot resolve the server address')
    if not interface:
        route = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', addresses[0]], text=True))
        interface = route[0]['dev']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface) or not (Path('/sys/class/net') / interface).exists():
        raise ValueError('Capture interface does not exist')
    hosts = ' or '.join('host ' + address for address in addresses)
    return interface, f'not (({hosts}) and tcp port {parsed.port or 443})'


def main():
    config = json.loads(Path('/etc/nfagent/config.json').read_text())
    interface, capture_filter = capture_options(config['server'], config.get('interface', ''))
    uploader = Uploader(config['server'], '/etc/nfagent/agent.key', '/var/lib/nfagent/state.json',
                        interface, cert_sha256=config['cert_sha256'])
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    run_capture(uploader, interface, '/var/lib/nfagent/spool', capture_filter, 2 * 1024**3, stop)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    main()
