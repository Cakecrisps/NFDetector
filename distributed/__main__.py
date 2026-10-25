import argparse
import logging
import os
import signal
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='NFDetect distributed capture and analysis')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init-db')
    commands.add_parser('setup-code')
    issue = commands.add_parser('issue-key')
    issue.add_argument('--name', required=True)
    issue.add_argument('--domain', required=True)
    issue.add_argument('--key-file', required=True)
    revoke = commands.add_parser('revoke-key')
    revoke.add_argument('--agent-id', required=True)
    api = commands.add_parser('api')
    api.add_argument('--host', default='0.0.0.0')
    api.add_argument('--port', type=int, default=8000)
    commands.add_parser('parser-worker')
    commands.add_parser('detector-worker')
    for name in ('upload', 'capture'):
        command = commands.add_parser(name)
        command.add_argument('--server', required=True)
        command.add_argument('--key-file', required=True)
        command.add_argument('--state', required=True)
        command.add_argument('--interface', required=True)
        tls = command.add_mutually_exclusive_group()
        tls.add_argument('--ca')
        tls.add_argument('--cert-sha256')
        command.add_argument('--allow-http', action='store_true')
        if name == 'upload':
            command.add_argument('files', nargs='+')
        else:
            command.add_argument('--spool', required=True)
            command.add_argument('--filter', required=True)
            command.add_argument('--quota-mib', type=int, default=2048)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    if args.command in ('upload', 'capture'):
        from .agent import Uploader, run_capture
        uploader = Uploader(args.server, args.key_file, args.state, args.interface, ca=args.ca or True,
                            allow_http=args.allow_http, cert_sha256=args.cert_sha256)
        if args.command == 'upload':
            uploader.upload_files(args.files)
            print('Uploaded and sealed stream:', uploader.state['stream_id'])
        else:
            stop = threading.Event()
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, lambda *_: stop.set())
            run_capture(uploader, args.interface, args.spool, args.filter, args.quota_mib * 1024 * 1024, stop)
        return
    from .settings import Settings
    from .store import Store
    settings = Settings.from_env()
    settings.prepare()
    store = Store(settings)
    if args.command == 'api':
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(settings), host=args.host, port=args.port)
    elif args.command in ('parser-worker', 'detector-worker'):
        from .workers import run_worker
        run_worker(settings, 'parser' if args.command == 'parser-worker' else 'detector')
    else:
        store.initialize()
        if args.command == 'setup-code':
            from .web_auth import WebAuth
            auth = WebAuth(store)
            auth.bootstrap()
            with store.connect() as conn:
                initial = conn.execute("SELECT must_change_password FROM nf_web_users WHERE username='root'").fetchone()
            if not initial or not initial['must_change_password']:
                parser.error('Initial setup is already complete; root:root is disabled')
            print(auth.setup_path.read_text().strip())
        elif args.command == 'issue-key':
            if not args.domain.strip() or len(args.domain) > 128:
                parser.error('domain must contain 1–128 characters')
            path = Path(args.key_file)
            # Reserve the private file before creating a credential in PostgreSQL.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                agent_id, token = store.issue_key(args.name, args.domain)
                with os.fdopen(descriptor, 'w') as handle:
                    handle.write(token + '\n')
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            print(f'Agent {agent_id}; key saved to {path}')
        elif args.command == 'revoke-key':
            with store.connect() as conn:
                row = conn.execute('UPDATE nf_agents SET revoked=true WHERE id=%s RETURNING id', (args.agent_id,)).fetchone()
                if not row:
                    parser.error('unknown agent')
            print('Agent key revoked')


if __name__ == '__main__':
    main()
