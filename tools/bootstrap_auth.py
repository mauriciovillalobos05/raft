#!/usr/bin/env python3
"""Create a LOCAL development CA and credentials in a new private directory.

Run with the project virtualenv: python -m tools.bootstrap_auth /private/path
Never use this development CA as a production CA.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
from security.auth import hash_password


def bootstrap(directory):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    (directory / "ca.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\n"
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=Raft development CA", "-config", "ca.cnf")
    identities = {}
    for identity, role in [("A", "node"), ("B", "node"), ("C", "node"),
                           ("kv-gateway", "client"), ("direct-client", "client"), ("https", None)]:
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{identity}.key",
                "-out", f"{identity}.csr", "-subj", f"/CN={identity}")
        (directory / "extensions.cnf").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", f"{identity}.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", f"{identity}.crt", "-days", "30", "-extfile", "extensions.cnf")
        if role:
            der = ssl.PEM_cert_to_DER_cert((directory / f"{identity}.crt").read_text())
            identities[identity] = {"role": role, "cert": f"{identity}.crt", "key": f"{identity}.key",
                                    "fingerprint": hashlib.sha256(der).hexdigest()}
    users, passwords = {}, {}
    for identity, role in [("kv-client", "client"), ("viewer", "ui"), ("operator", "operator")]:
        password = secrets.token_urlsafe(24)
        passwords[identity] = password
        users[identity] = {"role": role, "password_hash": hash_password(password)}
    config = {"ca_cert": "ca.crt", "identities": identities, "users": users,
              "gateway_identity": "kv-gateway", "allowed_origins": ["https://localhost:8765"],
              "session_ttl_seconds": 900, "https": {"cert": "https.crt", "key": "https.key"}}
    (directory / "auth.json").write_text(json.dumps(config, indent=2) + "\n")
    (directory / "passwords.json").write_text(json.dumps(passwords, indent=2) + "\n")
    for path in directory.iterdir():
        path.chmod(0o600)
    return directory / "auth.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="New private directory outside the repository")
    args = parser.parse_args()
    old_umask = os.umask(0o077)
    try:
        path = bootstrap(args.directory)
        print(f"Created development credentials. Set RAFT_AUTH_CONFIG={path}")
        print(f"HTTP passwords are in {path.parent / 'passwords.json'}; keep them private.")
    finally:
        os.umask(old_umask)
