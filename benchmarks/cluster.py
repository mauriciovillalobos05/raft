"""Isolated three-node harness; uses real RPC, state machines and persistence."""
from contextlib import contextmanager
import os
import asyncio
from pathlib import Path
import tempfile
import threading
import time
from inmem.byte_data_db import ByteDataDB
from inmem.state_machine_applier import StateMachineApplier
from inmem.kv_client import KVClient
from raft.raft_rpc import create_rpc_server
from raft.raft_server import Raft
from raft.raft_websocket_manager import WebSocketManager
from security.auth import get_auth
from security.transport import EVIDENCE


class Cluster:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="raft-pqc-cluster-")
        self.cwd = Path.cwd()
        os.chdir(self.temp.name)
        self.nodes, self.servers, self.threads, self.config = {}, {}, [], {}
        self.stop = threading.Event()
        self.pump = None
        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.loop_thread.start()
        WebSocketManager.get_ws_manager().set_event_loop(self.loop)
        for node_id in ("A", "B", "C"):
            db = ByteDataDB()
            node = Raft(node_id, logs_file_path=str(Path(self.temp.name) / f"{node_id}.jsonl"),
                        state_machine_applier=StateMachineApplier(db))
            server = create_rpc_server(node, db, "127.0.0.1", 0)
            self.nodes[node_id], self.servers[node_id] = node, server
            self.config[node_id] = {"host": "127.0.0.1", "port": server.port}
            thread = threading.Thread(target=server.start, daemon=True)
            thread.start()
            self.threads.append(thread)
        for node_id, node in self.nodes.items():
            node.add_peer_connections({k: v for k, v in self.config.items() if k != node_id})
            node.next_index = {k: 0 for k in node.raft_terms.peers}
            node.match_index = {k: -1 for k in node.raft_terms.peers}

    def probe_topology(self):
        auth = get_auth()
        for local in self.nodes:
            for peer in self.nodes:
                if local != peer:
                    conn = auth.connect(**self.config[peer], identity=local, expected_node=peer)
                    conn.close()
        for identity in ("direct-client", auth.gateway_identity):
            for peer in self.nodes:
                conn = auth.connect(**self.config[peer], identity=identity, expected_node=peer)
                conn.close()
        self.wait_for_evidence()

    @staticmethod
    def wait_for_evidence():
        # Server records acceptance after the final client acknowledgment.
        time.sleep(.03)

    def elect(self, node_id="A"):
        start = time.perf_counter()
        self.nodes[node_id].request_vote()
        if self.nodes[node_id].raft_terms.state.name != "leader":
            raise RuntimeError("Election failed")
        return (time.perf_counter() - start) * 1000

    def start_replication(self, interval=.01):
        def drive():
            while not self.stop.is_set():
                for node in self.nodes.values():
                    if not node.killed() and node.raft_terms.state.name == "leader":
                        node.send_health_checks()
                self.stop.wait(interval)
        self.pump = threading.Thread(target=drive, daemon=True)
        self.pump.start()

    def committed(self, index):
        return sum(n.raft_terms.commit_index >= index for n in self.nodes.values()) >= 2

    def wait_commit(self, index, timeout=10):
        deadline = time.monotonic() + timeout
        while not self.committed(index):
            if time.monotonic() > deadline:
                raise TimeoutError(f"Index {index} did not commit")
            time.sleep(.001)

    def close(self):
        self.stop.set()
        if self.pump:
            self.pump.join(10)
        for node in self.nodes.values():
            node.kill()
        for server in self.servers.values():
            server.close()
        for thread in self.threads:
            thread.join(5)
        asyncio.run_coroutine_threadsafe(asyncio.sleep(.01), self.loop).result(3)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.loop_thread.join(3)
        self.loop.close()
        manager = WebSocketManager.get_ws_manager()
        if manager.event_loop is self.loop:
            manager.event_loop = None
        os.chdir(self.cwd)
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
