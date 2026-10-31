"""Real TLS/HTTP/WebSocket tests. Uses temporary CAs, ports and Raft state."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import rpyc
import uvicorn
from websockets.sync.client import connect as websocket_connect
from websockets.exceptions import InvalidStatus, ConnectionClosed
from tools.bootstrap_auth import bootstrap
from security.auth import get_auth, AuthConfig, Principal, verify_password
from security.wire import encode
from inmem.byte_data_db import ByteDataDB
from inmem.state_machine_applier import StateMachineApplier
from inmem.kv_client import KVClient
from raft.raft_server import Raft
from raft.raft_rpc import create_rpc_server, NODE_METHODS, CLIENT_METHODS
from raft.raft_state import RaftState
from raft.raft_websocket_manager import WebSocketManager
from security import http as http_auth
import websocket_server as web


class SecurityIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="raft-auth-test-")
        cls.cwd = Path.cwd()
        cls.old_env = os.environ.get("RAFT_AUTH_CONFIG")
        cls.config_path = bootstrap(Path(cls.temp.name) / "credentials")
        os.environ["RAFT_AUTH_CONFIG"] = str(cls.config_path)
        get_auth.cache_clear()
        cls.auth = get_auth()
        cls.passwords = json.loads((cls.config_path.parent / "passwords.json").read_text())
        os.chdir(cls.temp.name)
        cls.nodes, cls.dbs, cls.servers, cls.threads = {}, {}, {}, []
        cls.cluster = {}
        for node_id in ("A", "B", "C"):
            db = ByteDataDB()
            node = Raft(node_id, logs_file_path=str(Path(cls.temp.name) / f"{node_id}.jsonl"),
                        state_machine_applier=StateMachineApplier(db))
            server = create_rpc_server(node, db, "127.0.0.1", 0)
            cls.nodes[node_id], cls.dbs[node_id], cls.servers[node_id] = node, db, server
            cls.cluster[node_id] = {"host": "127.0.0.1", "port": server.port}
            thread = threading.Thread(target=server.start, daemon=True)
            thread.start()
            cls.threads.append(thread)
        for node_id, node in cls.nodes.items():
            node.add_peer_connections({k: v for k, v in cls.cluster.items() if k != node_id})
            node.next_index = {k: 0 for k in node.raft_terms.peers}
            node.match_index = {k: -1 for k in node.raft_terms.peers}
            web.ws_manager.register_node(node_id, node)
        web.CLUSTER_CONFIG = cls.cluster
        cls.listener = socket.socket()
        cls.listener.bind(("127.0.0.1", 0))
        cls.port = cls.listener.getsockname()[1]
        cls.origin = f"https://localhost:{cls.port}"
        cls.auth.origins = [cls.origin]
        cls.web_server = uvicorn.Server(uvicorn.Config(web.app, log_level="error", ws="websockets-sansio", proxy_headers=False, **cls.auth.web_tls()))
        cls.web_thread = threading.Thread(target=cls.web_server.run, kwargs={"sockets": [cls.listener]}, daemon=True)
        cls.web_thread.start()
        deadline = time.monotonic() + 5
        while not cls.web_server.started and time.monotonic() < deadline:
            time.sleep(.02)
        if not cls.web_server.started:
            raise RuntimeError("HTTPS test server did not start")
        cls.context = ssl.create_default_context(cafile=cls.auth.path("ca.crt"))

    @classmethod
    def tearDownClass(cls):
        cls.web_server.should_exit = True
        cls.web_thread.join(5)
        for server in cls.servers.values():
            server.close()
        for thread in cls.threads:
            thread.join(3)
        for node in cls.nodes.values():
            node.kill()
        web.ws_manager.clients.clear()
        web.ws_manager.raft_nodes = {}
        web.ws_manager.event_loop = None
        http_auth._sessions.clear()
        os.chdir(cls.cwd)
        if cls.old_env is None:
            os.environ.pop("RAFT_AUTH_CONFIG", None)
        else:
            os.environ["RAFT_AUTH_CONFIG"] = cls.old_env
        get_auth.cache_clear()
        cls.temp.cleanup()

    def rpc(self, identity="direct-client", node="A"):
        return self.auth.connect(**self.cluster[node], identity=identity, expected_node=node)

    def request(self, method, route, user=None, password=None, body=None, headers=None):
        conn = http.client.HTTPSConnection("localhost", self.port, context=self.context, timeout=5)
        hdrs = dict(headers or {})
        if user:
            password = password if password is not None else self.passwords[user]
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"
        if body is not None:
            body = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        try:
            conn.request(method, route, body, hdrs)
            result = conn.getresponse()
            return result.status, dict(result.getheaders()), result.read()
        finally:
            conn.close()

    def login(self, user="viewer"):
        status, headers, _ = self.request("POST", "/auth/login", user, headers={"Origin": self.origin})
        self.assertEqual(status, 200)
        cookie = headers["set-cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=strict", cookie)
        return cookie.split(";", 1)[0]

    def test_01_missing_config_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                get_auth.__wrapped__()

    def test_02_password_hashes(self):
        for user, password in self.passwords.items():
            encoded = self.auth.users[user]["password_hash"]
            self.assertNotIn(password, self.config_path.read_text())
            self.assertTrue(verify_password(password, encoded))
            self.assertFalse(verify_password("incorrect", encoded))

    def test_03_plain_rpc_rejected(self):
        conn = rpyc.connect(**self.cluster["A"], config={"sync_request_timeout": 1})
        try:
            with self.assertRaises(Exception):
                conn.root.get_leader()
        finally:
            conn.close()

    def test_04_tls_requires_client_certificate(self):
        with self.assertRaises((ssl.SSLError, OSError, EOFError)):
            with socket.create_connection(("127.0.0.1", self.cluster["A"]["port"]), timeout=2) as sock:
                with self.context.wrap_socket(sock, server_hostname="localhost") as tls:
                    tls.sendall(b"x")
                    tls.recv(1)

    def test_05_wrong_server_identity_rejected(self):
        with self.assertRaises(Exception):
            self.auth.connect(**self.cluster["A"], identity="direct-client", expected_node="B")

    def test_06_unregistered_certificate_rejected(self):
        # Certificate is CA-trusted, but absent from the identity allowlist.
        identity = self.auth.identities["https"] if "https" in self.auth.identities else {
            "cert": "https.crt", "key": "https.key"}
        context = ssl.create_default_context(cafile=self.auth.path("ca.crt"))
        context.load_cert_chain(self.auth.path(identity["cert"]), self.auth.path(identity["key"]))
        with socket.create_connection(("127.0.0.1", self.cluster["A"]["port"]), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                with self.assertRaises((OSError, EOFError)):
                    from rpyc.utils.factory import connect_stream
                    from rpyc.core.stream import SocketStream
                    conn = connect_stream(SocketStream(tls), config={"sync_request_timeout": 1})
                    conn.root.get_leader()

    def test_07_role_matrix(self):
        before = [(n.raft_terms.current_term, n.raft_terms.voted_for, list(n.raft_terms.logs))
                  for n in self.nodes.values()]
        for identity, forbidden in [("B", CLIENT_METHODS), ("direct-client", NODE_METHODS)]:
            with self.rpc(identity) as conn:
                for method in forbidden | {"read_log", "append_log_entries", "_raft", "__dict__", "get_service_name"}:
                    with self.subTest(identity=identity, method=method):
                        with self.assertRaises(PermissionError):
                            getattr(conn.root, method)
        after = [(n.raft_terms.current_term, n.raft_terms.voted_for, list(n.raft_terms.logs))
                 for n in self.nodes.values()]
        self.assertEqual(before, after)

    def test_08_spoofed_node_identity(self):
        before = self.nodes["A"].raft_terms.current_term
        with self.rpc("B") as conn:
            for method, payload in [
                ("send_vote_request", {"candidate_id": "C", "current_term": 999, "last_log_index": 0, "last_log_term": 0}),
                ("send_health_check_request", {"leader_id": "C", "current_term": 999, "prev_log_index": -1,
                                               "prev_log_term": 0, "entries": [], "leader_commit": -1}),
            ]:
                with self.assertRaises(PermissionError):
                    getattr(conn.root, method)(encode(payload))
        self.assertEqual(before, self.nodes["A"].raft_terms.current_term)

    def test_09_strict_payloads_no_proxy_access(self):
        with self.rpc() as conn:
            for payload in [{"key": "x"}, "{}", "not-json", encode({"key": "x", "field": "f", "timestamp": 1,
                                                                      "value": "v", "command": "ARBITRARY"})]:
                with self.subTest(payload=payload):
                    with self.assertRaises(Exception):
                        conn.root.set_kv(payload)

    def test_10_election_and_replication(self):
        self.nodes["A"].request_vote()
        self.assertEqual(self.nodes["A"].raft_terms.state, RaftState.leader)
        client = KVClient(self.cluster, identity="direct-client")
        try:
            self.assertEqual(client._discover_leader(), "A")
            result = client.set("security-key", "field", "SECRET-KV-SENTINEL", timestamp=100)
            self.assertTrue(result["success"], result)
            self.replicate()
            for node_id in self.nodes:
                self.assertEqual(client.get("security-key", "field", 101, node_id)["value"], "SECRET-KV-SENTINEL")
            self.assertEqual(client.scan("security-key", 101)["fields"], [("field", "SECRET-KV-SENTINEL")])
            self.assertEqual(client.scan_by_prefix("security-key", "fi", 101)["fields"], [("field", "SECRET-KV-SENTINEL")])
            self.assertTrue(client.delete("security-key", "field", 102)["success"])
            self.replicate()
            for node_id in self.nodes:
                self.assertFalse(client.get("security-key", "field", 103, node_id)["success"])
        finally:
            client.close()

    def replicate(self):
        target = len(self.nodes["A"].raft_terms.logs) - 1
        for _ in range(20):
            self.nodes["A"].send_health_checks()
            if all(node.raft_terms.commit_index >= target for node in self.nodes.values()):
                return
        self.fail(f"Replication did not reach index {target}")

    def test_11_stale_vote_is_application_rejection(self):
        with self.rpc("B") as conn:
            result = conn.root.send_vote_request(encode({"candidate_id": "B", "current_term": 0,
                                                         "last_log_index": 0, "last_log_term": 0}))
            self.assertIs(result, False)

    def test_12_concurrent_connection_roles_are_isolated(self):
        def query(identity):
            with self.rpc(identity) as conn:
                if identity == "B":
                    with self.assertRaises(PermissionError):
                        conn.root.get_leader()
                else:
                    self.assertEqual(json.loads(conn.root.get_leader())["node_id"], "A")
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(query, ["B", "direct-client"] * 6))

    def test_13_http_role_matrix(self):
        routes = [("GET", "/health", {"viewer", "operator"}),
                  ("GET", "/cluster/status", {"viewer", "operator"}),
                  ("GET", "/kv-store?key=absent&field=f", {"kv-client"}),
                  ("POST", "/kv-store", {"kv-client"}),
                  ("DELETE", "/kv-store?key=absent&field=f", {"kv-client"}),
                  ("POST", "/auth/login", {"viewer", "operator"})]
        for method, route, allowed in routes:
            for user in (None, "viewer", "operator", "kv-client"):
                with self.subTest(method=method, route=route, user=user):
                    body = {"key": "http-key", "field": "f", "value": "v"} if method == "POST" and route == "/kv-store" else None
                    status, _, _ = self.request(method, route, user, body=body)
                    self.assertEqual(status, 401 if user is None else (200 if user in allowed else 403))
        self.assertEqual(self.request("GET", "/health", "viewer", password="wrong")[0], 401)
        self.assertEqual(self.request("GET", "/health", "unknown", password="wrong")[0], 401)

    def test_14_docs_disabled(self):
        for route in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.request("GET", route)[0], 404)

    def test_15_websocket_requires_session_and_origin(self):
        uri = f"wss://localhost:{self.port}/ws"
        cookie = self.login()
        for headers, origin in [({}, self.origin), ({"Cookie": cookie}, "https://evil.invalid"),
                                ({"Cookie": cookie}, None)]:
            with self.assertRaises(InvalidStatus):
                with websocket_connect(uri, ssl=self.context, origin=origin, additional_headers=headers):
                    pass
        # Client role cannot create a browser session.
        self.assertEqual(self.request("POST", "/auth/login", "kv-client")[0], 403)

    def test_16_websocket_snapshot_and_live_redaction(self):
        cookie = self.login()
        # Ensure a private command exists in the log when the UI connects.
        self.nodes["A"].append_log_entries(encode({"type": "SET", "key": "SECRET-KV-SENTINEL",
                                                   "field": "f", "value": "SECRET-KV-SENTINEL", "timestamp": 200}))
        with websocket_connect(f"wss://localhost:{self.port}/ws", ssl=self.context, origin=self.origin,
                               additional_headers={"Cookie": cookie}) as ws:
            snapshots = []
            expected = sum(1 + len(n.raft_terms.logs) for n in self.nodes.values())
            for _ in range(expected):
                snapshots.append(ws.recv(timeout=3))
            for message in snapshots:
                self.assertNotIn("SECRET-KV-SENTINEL", message)
                self.assertNotIn('"command"', message)
            future = asyncio.run_coroutine_threadsafe(web.ws_manager.broadcast_kv_store_update(
                "A", 20, {"command": "SECRET-KV-SENTINEL"}, {"value": "SECRET-KV-SENTINEL"}),
                web.ws_manager.event_loop)
            future.result(3)
            message = json.loads(ws.recv(timeout=3))
            self.assertEqual(message["type"], "entry_applied")
            self.assertNotIn("value", message)
            self.assertNotIn("log_entry", message)
            future = asyncio.run_coroutine_threadsafe(web.ws_manager._broadcast_now({
                "type": "heartbeat", "leader_id": "A", "responses": {"secret": "SECRET-KV-SENTINEL"},
                "command": "SECRET-KV-SENTINEL"}), web.ws_manager.event_loop)
            future.result(3)
            self.assertNotIn("SECRET-KV-SENTINEL", ws.recv(timeout=3))

    def test_17_logout_revokes_open_websocket(self):
        cookie = self.login()
        with websocket_connect(f"wss://localhost:{self.port}/ws", ssl=self.context, origin=self.origin,
                               additional_headers={"Cookie": cookie}) as ws:
            status, _, _ = self.request("POST", "/auth/logout", headers={"Cookie": cookie, "Origin": self.origin})
            self.assertEqual(status, 200)
            with self.assertRaises(ConnectionClosed):
                while True:
                    ws.recv(timeout=3)

    def test_18_session_expiry(self):
        cookie = self.login()
        token = cookie.split("=", 1)[1]
        with http_auth._lock:
            principal, _ = http_auth._sessions[token]
            http_auth._sessions[token] = (principal, time.time() - 1)
        with self.assertRaises(InvalidStatus):
            with websocket_connect(f"wss://localhost:{self.port}/ws", ssl=self.context, origin=self.origin,
                                   additional_headers={"Cookie": cookie}):
                pass

    def test_19_http_kv_roundtrip(self):
        status, _, result = self.request("POST", "/kv-store", "kv-client",
                                         body={"key": "roundtrip", "field": "f", "value": "v"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(result)["success"])
        self.replicate()
        status, _, result = self.request("GET", "/kv-store?key=roundtrip&field=f", "kv-client")
        self.assertEqual(json.loads(result)["value"], "v")
        status, _, result = self.request("DELETE", "/kv-store?key=roundtrip&field=f", "kv-client")
        self.assertTrue(json.loads(result)["success"])
        self.replicate()
        status, _, result = self.request("GET", "/kv-store?key=roundtrip&field=f", "kv-client")
        self.assertFalse(json.loads(result)["success"])

    def test_20_client_reconnect(self):
        client = KVClient(self.cluster, identity="direct-client")
        try:
            self.assertEqual(client._discover_leader(), "A")
            client._connections["A"].close()
            self.assertEqual(client._discover_leader(), "A")
        finally:
            client.close()

    def test_21_leader_change_and_client_retry(self):
        client = KVClient(self.cluster, identity="direct-client")
        try:
            self.assertEqual(client._discover_leader(), "A")
            self.nodes["B"].request_vote()
            self.assertEqual(self.nodes["B"].raft_terms.state, RaftState.leader)
            self.assertEqual(self.nodes["A"].raft_terms.state, RaftState.follower)
            result = client.set("after-election", "f", "v", 300)
            self.assertTrue(result["success"], result)
            self.assertEqual(client._leader_id, "B")
            target = result["index"]
            for _ in range(5):
                self.nodes["B"].send_health_checks()
            self.assertTrue(all(node.raft_terms.commit_index >= target for node in self.nodes.values()))
            self.assertEqual(client.get("after-election", "f", 301)["value"], "v")
        finally:
            client.close()

    def test_22_expiry_closes_active_socket(self):
        cookie = self.login("operator")
        token = cookie.split("=", 1)[1]
        with websocket_connect(f"wss://localhost:{self.port}/ws", ssl=self.context, origin=self.origin,
                               additional_headers={"Cookie": cookie}) as ws:
            ws.recv(timeout=3)
            with http_auth._lock:
                principal, _ = http_auth._sessions[token]
                http_auth._sessions[token] = (principal, time.time() - 1)
            with self.assertRaises(ConnectionClosed):
                while True:
                    ws.recv(timeout=3)

    def test_23_http_write_rejects_raw_command(self):
        status, _, _ = self.request("POST", "/kv-store", "kv-client", body={
            "key": "x", "field": "f", "value": "v", "command": "ARBITRARY"})
        self.assertEqual(status, 422)

    def test_24_untrusted_ca_rejected(self):
        # Trusting the HTTPS leaf instead of the issuing CA must not verify a node.
        context = ssl.create_default_context(cafile=self.auth.path("https.crt"))
        context.load_cert_chain(self.auth.path("direct-client.crt"), self.auth.path("direct-client.key"))
        with socket.create_connection(("127.0.0.1", self.cluster["A"]["port"]), timeout=2) as sock:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(sock, server_hostname="localhost")

    def test_25_logout_rejects_cross_origin(self):
        cookie = self.login()
        status, _, _ = self.request("POST", "/auth/logout", headers={
            "Cookie": cookie, "Origin": "https://evil.invalid"})
        self.assertEqual(status, 403)
        self.assertIsNotNone(http_auth.session_principal(cookie.split("=", 1)[1]))

    def test_26_logout_requires_session(self):
        status, _, _ = self.request("POST", "/auth/logout", headers={"Origin": self.origin})
        self.assertEqual(status, 401)
        status, _, _ = self.request("POST", "/auth/logout", headers={"Origin": self.origin,
                                                                     "Cookie": "__Host-raft-session=invalid"})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
