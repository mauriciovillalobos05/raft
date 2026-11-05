"""Data-flow policy and measured TLS evidence. No application data is recorded."""
from collections import Counter, deque
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import logging
import os
from pathlib import Path
import ssl
import struct
import sys
import threading
import time
import tomllib

LOG = logging.getLogger("raft.transport")
HYBRID = "X25519MLKEM768"
CLASSICAL = "X25519"
GROUPS = {0x11EC: HYBRID, 0x001D: CLASSICAL}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
EXCLUSIONS = ["classical certificate authentication", "classical browser HTTPS/WSS", "stored data"]
CLASSES = {"node-peer", "gateway-node", "client-node", "log-access", "browser-https", "telemetry"}
VALUE_CLASSES = {"node-peer", "gateway-node", "client-node", "log-access"}


class TransportError(OSError):
    pass


class Policy:
    def __init__(self, path=None, profile=None):
        self.profile = profile or os.environ.get("RAFT_PQC_PROFILE", "policy")
        if self.profile not in {"policy", "hybrid-preferred", "classical"}:
            raise ValueError("Unknown transport profile")
        path = Path(path or os.environ.get("RAFT_PQC_POLICY", Path(__file__).with_name("transport-policy.toml")))
        self.data = tomllib.loads(path.read_text())
        classes = self.data.get("classes", {})
        if set(classes) != CLASSES:
            raise ValueError("Transport policy must classify every known class exactly once")
        if any(classes[c] != "hybrid-required" for c in VALUE_CLASSES):
            raise ValueError("Value-bearing classes must remain hybrid-required in policy")
        if classes["browser-https"] != "classical" or classes["telemetry"] not in {"hybrid-required", "hybrid-preferred"}:
            raise ValueError("Invalid browser or telemetry classification")
        if self.data.get("listeners") != {"rpc": ["node-peer", "gateway-node", "client-node"]}:
            raise ValueError("Unclassified or unsupported RPC listener")
        self.classes = classes

    def requirement(self, transport_class):
        if transport_class not in self.classes:
            raise TransportError("Unclassified transport")
        if transport_class == "browser-https":
            return "classical"
        return self.classes[transport_class] if self.profile == "policy" else self.profile

    def classify(self, principal, gateway):
        if principal.role == "node":
            return "node-peer"
        if principal.role == "client":
            return "gateway-node" if principal.identity == gateway else "client-node"
        raise TransportError("Identity has no RPC transport class")

    def validate(self, evidence):
        requirement = self.requirement(evidence["class"])
        if evidence["tls_version"] != "TLSv1.3" or evidence["key_exchange_group"] not in GROUPS.values():
            raise TransportError("Missing or unsupported TLS negotiation evidence")
        expected = "hybrid" if evidence["key_exchange_group"] == HYBRID else "classical"
        if evidence.get("protection") != expected:
            raise TransportError("Inconsistent protection evidence")
        if requirement == "hybrid-required" and evidence["protection"] != "hybrid":
            raise TransportError("Hybrid-required class negotiated classical key exchange")
        if requirement == "classical" and evidence["key_exchange_group"] != CLASSICAL:
            raise TransportError("Classical comparison profile negotiated a nonclassical group")
        return requirement


@lru_cache(maxsize=1)
def get_policy():
    return Policy()


def ensure_runtime():
    profile = get_policy().profile
    config = Path(__file__).parent / "openssl" / ("classical.cnf" if profile == "classical" else "hybrid.cnf")
    if os.environ.get("RAFT_PQC_LAUNCHED") != "1" or os.environ.get("OPENSSL_CONF") != str(config.resolve()):
        raise RuntimeError("Start through python -m security.launcher so OpenSSL policy loads before TLS")
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14) or ssl.OPENSSL_VERSION_INFO[:2] != (3, 6):
        raise RuntimeError("PQC transport requires the tested CPython 3.14 / OpenSSL 3.6 runtime")
    if not hasattr(ssl.SSLContext, "_msg_callback"):
        raise RuntimeError("TLS negotiation callback unavailable")


def parse_server_hello(data):
    """Validate a complete handshake message; return (group, random, is_HRR)."""
    if len(data) < 42 or data[0] != 2 or int.from_bytes(data[1:4], "big") != len(data) - 4:
        raise ValueError("Malformed ServerHello length/type")
    if data[4:6] != b"\x03\x03":
        raise ValueError("Unexpected ServerHello legacy version")
    random = data[6:38]
    session_len = data[38]
    if session_len > 32:
        raise ValueError("Invalid session ID")
    offset = 39 + session_len
    if offset + 5 > len(data) or data[offset + 2] != 0:
        raise ValueError("Malformed ServerHello fields")
    offset += 3
    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    if offset + length != len(data):
        raise ValueError("Malformed ServerHello extensions")
    group, tls13, seen = None, False, set()
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("Truncated extension header")
        kind, size = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        value = data[offset:offset + size]
        if len(value) != size or kind in seen:
            raise ValueError("Truncated or duplicate extension")
        seen.add(kind)
        offset += size
        if kind == 43:
            tls13 = value == b"\x03\x04"
        if kind == 51:
            if random == HRR_RANDOM:
                if size != 2:
                    raise ValueError("Invalid HelloRetryRequest key share")
            elif size < 5 or int.from_bytes(value[2:4], "big") != size - 4:
                raise ValueError("Invalid ServerHello key share")
            group = GROUPS.get(int.from_bytes(value[:2], "big"))
    if not tls13 or group is None:
        raise ValueError("Unrecognized TLS version or key exchange group")
    return group, random.hex(), random == HRR_RANDOM


class HandshakeTrace:
    """One trace per socket, attached by the context callback; no secret logging."""
    def __init__(self):
        self.group = None
        self.connection_id = None
        self.error = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.frozen = False
        self.hello_retries = 0

    def observe(self, direction, content_type, message_type, data):
        if self.frozen:
            return
        # CPython calls this with TLS record headers, then decoded messages.
        if int(content_type) == 256 and len(data) == 5:
            size = 5 + int.from_bytes(data[3:5], "big")
            if direction == "write":
                self.bytes_sent += size
            else:
                self.bytes_received += size
        if int(content_type) == 22 and int(message_type) == 2:
            try:
                group, random, retry = parse_server_hello(data)
                if retry:
                    self.hello_retries += 1
                else:
                    self.group = group
                    self.connection_id = hashlib.sha256(bytes.fromhex(random)).hexdigest()
            except ValueError as exc:
                self.error = str(exc)


def _callback(conn, direction, version, content_type, message_type, data):
    trace = getattr(conn, "_raft_trace", None)
    if trace is None:
        trace = conn._raft_trace = HandshakeTrace()
    trace.observe(direction, content_type, message_type, data)


def configure_context(context, transport_class):
    get_policy().requirement(transport_class)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_TICKET
    if context.protocol == ssl.PROTOCOL_TLS_SERVER:
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        context.num_tickets = 0
    if transport_class == "browser-https":
        context.set_ecdh_curve(CLASSICAL)
    # CPython cannot set a hybrid groups list per context. The launcher sets the
    # offered list; required classes ALSO enforce the final result on both ends.
    context._msg_callback = _callback
    return context


def observe_socket(sock, transport_class, direction, local, peer):
    trace = getattr(sock, "_raft_trace", None)
    if trace is None or trace.error or not trace.group or not trace.connection_id:
        EVIDENCE.add({"class": transport_class, "direction": direction, "local_identity": local,
                      "peer_identity": peer, "key_exchange_group": None, "protection": "unknown"},
                     "required-class-rejection" if get_policy().requirement(transport_class) == "hybrid-required" else "negotiation-rejection")
        raise TransportError("Missing or malformed final ServerHello evidence")
    trace.frozen = True
    return {"connection_id": trace.connection_id, "class": transport_class, "direction": direction,
            "local_identity": local, "peer_identity": peer, "tls_version": sock.version(),
            "cipher": sock.cipher()[0], "key_exchange_group": trace.group,
            "protection": "hybrid" if trace.group == HYBRID else "classical",
            "requirement": get_policy().requirement(transport_class), "profile": get_policy().profile,
            "tls_bytes_sent": trace.bytes_sent, "tls_bytes_received": trace.bytes_received,
            "hello_retries": trace.hello_retries, "timestamp": time.time()}


class EvidenceStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.records = deque(maxlen=20000)
        self.counts = Counter()
        self.started = time.time()

    def add(self, record, outcome):
        record = dict(record, outcome=outcome, timestamp=record.get("timestamp", time.time()))
        with self.lock:
            self.records.append(record)
            self.counts[(record["class"], outcome)] += 1
            path = os.environ.get("RAFT_PQC_EVIDENCE")
            if path:
                # A process-specific path avoids interleaved multi-process writes.
                path = path.replace("{pid}", str(os.getpid()))
                with open(path, "a", encoding="utf-8") as output:
                    output.write(json.dumps(record) + "\n")
        return record

    def snapshot(self):
        with self.lock:
            return {"window_start": self.started, "window_end": time.time(),
                    "dropped_records": sum(self.counts.values()) - len(self.records),
                    "counts": [{"class": c, "outcome": o, "count": n}
                               for (c, o), n in sorted(self.counts.items())]}

    def reset(self):
        with self.lock:
            self.records.clear()
            self.counts.clear()
            self.started = time.time()


EVIDENCE = EvidenceStore()


def enforce(record):
    try:
        requirement = get_policy().validate(record)
    except TransportError:
        outcome = "required-class-rejection" if get_policy().requirement(record["class"]) == "hybrid-required" else "negotiation-rejection"
        EVIDENCE.add(record, outcome)
        LOG.warning("Rejected %s peer=%s group=%s", record["class"], record["peer_identity"], record.get("key_exchange_group"))
        raise
    return requirement


def _send(sock, payload):
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    if len(encoded) > 4096:
        raise TransportError("Transport evidence frame too large")
    sock.sendall(struct.pack("!I", len(encoded)) + encoded)


def _receive(sock):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise TransportError("Peer closed before transport evidence agreement")
            data.extend(chunk)
        return bytes(data)
    size = struct.unpack("!I", exact(4))[0]
    if not 1 <= size <= 4096:
        raise TransportError("Invalid transport evidence frame size")
    try:
        value = json.loads(exact(size))
    except (ValueError, UnicodeError) as exc:
        raise TransportError("Malformed transport evidence") from exc
    if type(value) is not dict:
        raise TransportError("Invalid transport evidence shape")
    return value


def agree(sock, record, server=False):
    """Compare authenticated observations before dispatching any RPyC traffic."""
    keys = ("connection_id", "class", "tls_version", "cipher", "key_exchange_group")
    local = {key: record[key] for key in keys}
    local.update(version=1, local_identity=record["local_identity"], peer_identity=record["peer_identity"])
    try:
        if not server:
            _send(sock, local)
        peer = _receive(sock)
        expected = dict(local, local_identity=local["peer_identity"], peer_identity=local["local_identity"])
        if peer != expected:
            EVIDENCE.add(record, "anomaly")
            raise TransportError("Authenticated transport observations disagree")
        if server:
            _send(sock, local)
            if _receive(sock) != {"ack": record["connection_id"]}:
                EVIDENCE.add(record, "anomaly")
                raise TransportError("Transport evidence acknowledgment mismatch")
        else:
            _send(sock, {"ack": record["connection_id"]})
        outcome = "fallback" if record["requirement"] == "hybrid-preferred" and record["protection"] == "classical" else "accepted"
        if outcome == "fallback":
            LOG.warning("Classical fallback class=%s peer=%s", record["class"], record["peer_identity"])
        EVIDENCE.add(dict(record, peer_agreed=True), outcome)
    except (OSError, ValueError) as exc:
        EVIDENCE.add(record, "agreement-rejection")
        raise TransportError("Transport evidence agreement failed") from exc


def probe_capability(auth, identity):
    """Fresh in-memory handshake verifies actual local support, not CLI version."""
    server = configure_context(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), "telemetry")
    entry = auth.identities[identity]
    server.load_cert_chain(auth.path(entry["cert"]), auth.path(entry["key"]))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # Only a local algorithm probe, never network authentication.
    configure_context(client, "telemetry")
    si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
    s = server.wrap_bio(si, so, server_side=True)
    c = client.wrap_bio(ci, co, server_hostname="localhost")
    done = set()
    for _ in range(30):
        for name, connection in (("client", c), ("server", s)):
            if name not in done:
                try:
                    connection.do_handshake()
                    done.add(name)
                except ssl.SSLWantReadError:
                    pass
        if co.pending:
            si.write(co.read())
        if so.pending:
            ci.write(so.read())
        if len(done) == 2:
            break
    expected = CLASSICAL if get_policy().profile == "classical" else HYBRID
    if len(done) != 2 or any(not hasattr(x, "_raft_trace") or x._raft_trace.error or x._raft_trace.group != expected for x in (s, c)):
        raise RuntimeError("Local TLS capability probe failed; required group was not negotiated")
    return {"local_hybrid_support": True if expected == HYBRID else None, "observed_group": c._raft_trace.group,
            "tls_version": c.version(), "python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}
