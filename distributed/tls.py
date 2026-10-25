"""Explicit leaf certificate authentication for agents installed from the panel."""
import re

from requests.adapters import HTTPAdapter


class FingerprintAdapter(HTTPAdapter):
    def __init__(self, fingerprint, **kwargs):
        if not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
            raise ValueError('Certificate SHA-256 must contain 64 lowercase hex characters')
        self.fingerprint = fingerprint
        super().__init__(**kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # urllib3 authenticates the actual peer certificate with assert_fingerprint.
        # This is explicit pinning, including for private/self-signed certificates.
        super().cert_verify(conn, url, False, cert)
        conn.assert_fingerprint = self.fingerprint
