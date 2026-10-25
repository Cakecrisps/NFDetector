"""Environment configuration shared by service processes."""
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    database_url: str
    data_dir: Path
    rules_path: Path
    protected_path: Path
    max_upload: int = 32 * 1024 * 1024
    max_backlog: int = 2 * 1024 * 1024 * 1024
    batch_size: int = 2000
    lease_seconds: int = 60
    max_checkpoint: int = 64 * 1024 * 1024
    max_streams: int = 16
    public_origin: str = ''
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls):
        return cls(
            os.environ.get('DATABASE_URL', 'postgresql://nfdetect@localhost/nfdetect'),
            Path(os.environ.get('NF_DATA_DIR', '/data')),
            Path(os.environ.get('NF_RULES', 'rules.json')),
            Path(os.environ.get('NF_PROTECTED_IPS', 'ext/protectips.txt')),
            int(os.environ.get('NF_MAX_UPLOAD', 32 * 1024 * 1024)),
            int(os.environ.get('NF_MAX_BACKLOG', 2 * 1024 * 1024 * 1024)),
            int(os.environ.get('NF_BATCH_SIZE', 2000)),
            int(os.environ.get('NF_LEASE_SECONDS', 60)),
            max_streams=int(os.environ.get('NF_MAX_STREAMS', 16)),
            public_origin=os.environ.get('NF_PUBLIC_URL', '').rstrip('/'),
            trust_proxy_headers=os.environ.get('NF_TRUST_PROXY_HEADERS', '0') == '1',
        )

    def prepare(self):
        for name in ('incoming', 'captures', 'parsed'):
            (self.data_dir / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        if min(self.max_upload, self.max_backlog, self.batch_size, self.lease_seconds, self.max_streams) <= 0:
            raise ValueError('Service limits must be positive')
