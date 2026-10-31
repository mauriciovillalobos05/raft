#!/usr/bin/env python3
"""
Modified start_cluster.py that allows test access to the RaftCluster object

This version is used when running RAFT resilience tests.
It exposes a global cluster object that tests can access directly.

Usage:
    python start_cluster_with_test_hook.py

Then in another terminal:
    python test_raft_resilience_with_cluster.py
"""

import threading
import time
import uvicorn
from raft.raft_websocket_manager import WebSocketManager
from websocket_server import app
from raft.raft_server import Raft
from raft.raft_rpc import create_rpc_server
from security.auth import get_auth
from inmem.byte_data_db import ByteDataDB
from inmem.state_machine_applier import StateMachineApplier

CLUSTER_CONFIG = {
    "A": {"host": "127.0.0.1", "port": 5001},
    "B": {"host": "127.0.0.1", "port": 5002},
    "C": {"host": "127.0.0.1", "port": 5003},
}

WEBSOCKET_HOST = "0.0.0.0"
WEBSOCKET_PORT = 8765

# Global cluster object for testing
global_cluster = None


class RaftCluster:
    def __init__(self, config, ws_manager):
        auth = get_auth()
        for node_id in config:
            auth.authenticator(str(node_id))
        self.config = config
        self.servers = {}
        self.nodes = {}
        self.ws_manager = ws_manager

    def start_node(self, node_id, start_timers=False):
        print(f"\n[Cluster] Starting Node {node_id}...")

        db = ByteDataDB.get_instance()
        applier = StateMachineApplier(db)

        peers_config = {
            nid: cfg for nid, cfg in self.config.items() if nid != node_id
        }

        raft_node = Raft(
            node_id=node_id,
            peers_config=peers_config,
            logs_file_path=f"raft_node_{node_id}.jsonl",
            state_machine_applier=applier,
        )

        raft_node.ws_manager = self.ws_manager
        print(f"WS manager instance in RAFT: {id(self.ws_manager)}, [Node {node_id}] WebSocket manager assigned")

        node_config = self.config[node_id]

        server = create_rpc_server(
            raft_node, db, node_config["host"], node_config["port"],
        )

        print(f"[Node {node_id}] RPC server listening on {node_config['host']}:{node_config['port']}")

        self.servers[node_id] = server
        self.nodes[node_id] = raft_node

        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        if start_timers:
            raft_node.start_raft_node()

        print(f"[Node {node_id}] ✓ Started successfully")

    def start_all_nodes(self):
        print("\n" + "=" * 60)
        print("RAFT Cluster Startup - Phase 1: Initialize RPC Servers")
        print("=" * 60)

        for node_id in sorted(self.config.keys()):
            self.start_node(node_id, start_timers=False)

        print("\n[Cluster] All RPC servers started. Waiting for stabilization...")
        time.sleep(1)

        # Register all RAFT servers with WebSocketManager for state sync
        for node_id, node in self.nodes.items():
            self.ws_manager.register_node(node_id, node)
        print(f"[Cluster] ✓ All RAFT nodes registered with WebSocketManager")

        print("\n" + "=" * 60)
        print("RAFT Cluster Startup - Phase 2: Begin Leader Election")
        print("=" * 60)

        for node_id, node in self.nodes.items():
            print(f"[Cluster] Starting election timer for Node {node_id}")
            node.start_raft_node()

        print("\n[Cluster] All nodes ready for leader election!")

    def wait_for_leader(self, timeout=10):
        print(f"\n[Cluster] Waiting up to {timeout} seconds for leader election...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            for node_id, node in self.nodes.items():
                if node.raft_terms.state.name == "leader":
                    print(f"\n✨ [CLUSTER] Node {node_id} elected as LEADER in term {node.raft_terms.current_term}")
                    return node_id
            time.sleep(0.5)

        print("[Cluster] ⚠️  No leader elected within timeout")
        return None

    def print_cluster_status(self):
        print("\n" + "=" * 60)
        print("CLUSTER STATUS")
        print("=" * 60)

        for node_id in sorted(self.nodes.keys()):
            node = self.nodes[node_id]
            print(f"\nNode {node_id}:")
            print(f"  State:        {node.raft_terms.state.name.upper()}")
            print(f"  Term:         {node.raft_terms.current_term}")
            print(f"  Voted For:    {node.raft_terms.voted_for}")
            print(f"  Last Log:     index={node.raft_terms.last_log_index}, term={node.raft_terms.last_log_term}")
            print(f"  Commit Index: {node.raft_terms.commit_index}")


def start_uvicorn():
    config = uvicorn.Config(app=app, host=WEBSOCKET_HOST, port=WEBSOCKET_PORT, log_level="info", ws="websockets-sansio", proxy_headers=False, **get_auth().web_tls())
    server = uvicorn.Server(config)
    server.run()


global_cluster = None

def start_cluster_for_tests():
    auth = get_auth()
    auth.web_tls()
    auth.server_context(auth.gateway_identity)
    for node_id in CLUSTER_CONFIG:
        auth.authenticator(str(node_id))
    global global_cluster

    print("\n" + "=" * 60)
    print("RAFT Cluster with WebSocket Server (TEST MODE)")
    print("=" * 60)
    print(f"WebSocket Port: {WEBSOCKET_PORT}")
    print(f"React should connect to: wss://localhost:{WEBSOCKET_PORT}/ws")

    # Start WebSocket server
    ws_thread = threading.Thread(target=start_uvicorn, daemon=True)
    ws_thread.start()
    time.sleep(2)

    # Create cluster & store globally
    ws_manager = WebSocketManager.get_ws_manager()
    print("WS manager instance:", id(ws_manager))

    cluster = RaftCluster(CLUSTER_CONFIG, ws_manager)
    global_cluster = cluster

    cluster.start_all_nodes()
    return cluster

def main():
    auth = get_auth()
    auth.web_tls()
    auth.server_context(auth.gateway_identity)
    for node_id in CLUSTER_CONFIG:
        auth.authenticator(str(node_id))
    cluster = start_cluster_for_tests()

    # Optional: leader election / status printing
    time.sleep(2)
    cluster.print_cluster_status()
    leader_id = cluster.wait_for_leader(timeout=15)
    time.sleep(1)
    cluster.print_cluster_status()

    if leader_id:
        print("\n" + "=" * 60)
        print("✨ LEADER ELECTION SUCCESSFUL!")
        print("=" * 60)
        print(f"\nCluster is running with Node {leader_id} as leader.")
        print(f"WebSocket server is broadcasting on port {WEBSOCKET_PORT}")
        print(f"\nConnect your React app to: wss://localhost:{WEBSOCKET_PORT}/ws")
        print(f"\n✅ TEST MODE: RaftCluster object exposed as global_cluster")
        print(f"Run: python test_raft_resilience_with_cluster.py\n")
    else:
        print("\n" + "=" * 60)
        print("⚠️  LEADER ELECTION FAILED")
        print("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[Cluster] Shutting down...")
        for node_id, node in cluster.nodes.items():
            node.kill()
        print("[Cluster] ✓ All nodes stopped")

if __name__ == "__main__":
    main()