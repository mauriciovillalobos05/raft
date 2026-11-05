"""Fail-closed configuration and authenticated TLS RPC connections.

RAFT_AUTH_CONFIG points to a private JSON file. Certificate SHA-256 fingerprints
are mapped to identities by administrators, never supplied by the caller.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from functools import lru_cache

from security.transport import (ensure_runtime, get_policy, configure_context, observe_socket,
                                enforce, agree, probe_capability, TransportError)
from rpyc.core.stream import SocketStream
from rpyc.utils.factory import connect_stream
from rpyc.utils.authenticators import AuthenticationError

RPC_CONFIG = {
    "allow_public_attrs": False, "allow_all_attrs": False,
    "allow_pickle": False, "allow_setattr": False, "allow_delattr": False,
    "include_local_traceback": False, "include_local_version": False,
    "sync_request_timeout": 5,
}


@dataclass(frozen=True)
class Principal:
    identity: str
    role: str


class AuthConfig:
    def __init__(self, path):
        ensure_runtime()
        self.capability = None
        path = Path(path).resolve()
        self.data = json.loads(path.read_text())
        self.directory = path.parent
        self.identities = self.data["identities"]
        self.fingerprints = {}
        for identity, entry in self.identities.items():
            if entry["role"] not in {"node", "client"}:
                raise ValueError("RPC identities must be node or client")
            fingerprint = entry["fingerprint"].lower().replace(":", "")
            if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
                raise ValueError("Invalid certificate fingerprint")
            if fingerprint in self.fingerprints:
                raise ValueError("Duplicate certificate fingerprint")
            self.fingerprints[fingerprint] = Principal(identity, entry["role"])
        self.users = self.data["users"]
        if not self.users:
            raise ValueError("HTTP users are required")
        for user in self.users.values():
            if user["role"] not in {"client", "ui", "operator"}:
                raise ValueError("Invalid HTTP role")
            validate_password_hash(user["password_hash"])
        self.origins = self.data["allowed_origins"]
        if not self.origins or any(not o.startswith("https://") for o in self.origins):
            raise ValueError("Explicit HTTPS origins are required")
        self.session_ttl = int(self.data.get("session_ttl_seconds", 900))
        if not 1 <= self.session_ttl <= 3600:
            raise ValueError("Session TTL must be between 1 and 3600 seconds")
        self.gateway_identity = self.data["gateway_identity"]
        if self.identities[self.gateway_identity]["role"] != "client":
            raise ValueError("Gateway must use a client identity")
        # Private keys are validated only by the process using that identity.
        # A direct client or separate node need not possess gateway/other-node keys.
        ssl.create_default_context(cafile=self.path(self.data["ca_cert"]))

    def path(self, name):
        return str((self.directory / name).resolve())

    def check_capability(self, identity):
        if self.capability is None:
            self.capability = probe_capability(self, identity)
        return self.capability

    def server_context(self, identity):
        self.check_capability(identity)
        entry = self.identities[identity]
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.path(self.data["ca_cert"]))
        context.load_cert_chain(self.path(entry["cert"]), self.path(entry["key"]))
        self._check_local_certificate(identity)
        return configure_context(context, "node-peer")

    def _check_local_certificate(self, identity):
        entry = self.identities[identity]
        der = ssl.PEM_cert_to_DER_cert(Path(self.path(entry["cert"])).read_text())
        if self.principal(der) != Principal(identity, entry["role"]):
            raise ValueError("Local certificate does not match configured identity")

    def principal(self, der):
        fingerprint = hashlib.sha256(der).hexdigest()
        principal = self.fingerprints.get(fingerprint)
        if principal is None:
            raise AuthenticationError("Unregistered peer certificate")
        return principal

    def authenticator(self, node_id, listener="rpc"):
        if listener not in get_policy().data["listeners"]:
            raise TransportError("Unclassified listener")
        if self.identities[str(node_id)]["role"] != "node":
            raise ValueError("RPC listener must use a node identity")
        context = self.server_context(str(node_id))

        def authenticate(sock):
            wrapped = None
            try:
                sock.settimeout(5)
                wrapped = context.wrap_socket(sock, server_side=True)
                principal = self.principal(wrapped.getpeercert(binary_form=True))
                transport_class = get_policy().classify(principal, self.gateway_identity)
                if transport_class not in get_policy().data["listeners"][listener]:
                    raise TransportError("Class not allowed on listener")
                record = observe_socket(wrapped, transport_class, "accepted", str(node_id), principal.identity)
                enforce(record)
                agree(wrapped, record, server=True)
                wrapped.settimeout(None)
                return wrapped, principal
            except (OSError, AuthenticationError) as exc:
                (wrapped or sock).close()
                raise AuthenticationError("RPC authentication failed") from exc
        return authenticate

    def connect(self, host, port, identity, expected_node, transport_class=None):
        principal = Principal(identity, self.identities[identity]["role"])
        classified = get_policy().classify(principal, self.gateway_identity)
        if transport_class is not None and transport_class != classified:
            raise TransportError("Requested class does not match authenticated identity")
        transport_class = classified
        self.check_capability(identity)
        entry = self.identities[identity]
        self._check_local_certificate(identity)
        context = ssl.create_default_context(cafile=self.path(self.data["ca_cert"]))
        configure_context(context, transport_class)
        context.load_cert_chain(self.path(entry["cert"]), self.path(entry["key"]))
        sock = socket.create_connection((host, port), timeout=5)
        wrapped = None
        try:
            handshake_started = time.perf_counter()
            wrapped = context.wrap_socket(sock, server_hostname=host)
            handshake_ms = (time.perf_counter() - handshake_started) * 1000
            principal = self.principal(wrapped.getpeercert(binary_form=True))
            if principal != Principal(str(expected_node), "node"):
                raise AuthenticationError("Unexpected RPC server identity")
            record = observe_socket(wrapped, transport_class, "dialed", identity, str(expected_node))
            record["tls_handshake_ms"] = handshake_ms
            enforce(record)
            agree(wrapped, record)
            return connect_stream(SocketStream(wrapped), config=RPC_CONFIG.copy())
        except BaseException:
            (wrapped or sock).close()
            raise

    def web_tls(self):
        entry = self.data["https"]
        cert, key = self.path(entry["cert"]), self.path(entry["key"])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        return {"ssl_certfile": cert, "ssl_keyfile": key}

    def web_config(self, app, **kwargs):
        import uvicorn
        from security.browser import EvidenceHTTPProtocol
        config = uvicorn.Config(app, http=EvidenceHTTPProtocol, ws="websockets-sansio", proxy_headers=False,
                                **self.web_tls(), **kwargs)
        config.load()
        configure_context(config.ssl, "browser-https")
        return config


@lru_cache(maxsize=1)
def get_auth():
    path = os.environ.get("RAFT_AUTH_CONFIG")
    if not path:
        raise RuntimeError("Set RAFT_AUTH_CONFIG to a private authentication config file")
    return AuthConfig(path)


def hash_password(password):
    if len(password) < 12:
        raise ValueError("Passwords must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def validate_password_hash(encoded):
    algorithm, salt, digest = encoded.split("$")
    if algorithm != "scrypt" or len(bytes.fromhex(salt)) != 16 or len(bytes.fromhex(digest)) != 64:
        raise ValueError("Invalid password hash")


def verify_password(password, encoded):
    _, salt, expected = encoded.split("$")
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return hmac.compare_digest(actual, bytes.fromhex(expected))
