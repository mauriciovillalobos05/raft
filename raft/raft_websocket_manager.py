# raft/raft_websocket_manager.py

import json
import threading
import asyncio
from datetime import datetime, timezone
from typing import Dict, List
from fastapi import WebSocket

class WebSocketManager:
    _instance = None

    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.client_checks = {}
        self.lock = threading.Lock()
        self.event_loop: asyncio.AbstractEventLoop | None = None
        self.raft_server = None  # Reference to RAFT server
        print("WebSocketManager initialized")

    @classmethod
    def get_ws_manager(cls) -> "WebSocketManager":
        if cls._instance is None:
            cls._instance = WebSocketManager()
        return cls._instance

    def register_node(self, node_id: str, raft_server):
        """Register a RAFT node"""
        if not hasattr(self, 'raft_nodes'):
            self.raft_nodes = {}
        self.raft_nodes[node_id] = raft_server
        print(f"[WebSocketManager] Node {node_id} registered")
        
    
    def get_registered_nodes(self):
        """Get all registered nodes"""
        return getattr(self, 'raft_nodes', {})

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """CRITICAL: Call this from the running FastAPI thread to register the loop"""
        self.event_loop = loop
        print(f"WebSocketManager event loop set: {id(loop)}")

    def _make_serializable(self, obj):
        """Convert objects to JSON-serializable format"""
        if obj is None:
            return None
        if isinstance(obj, (bool, int, float, str)):
            return obj
        if isinstance(obj, dict):
            try:
                return {str(k): self._make_serializable(v) for k, v in obj.items()}
            except Exception:
                return str(obj)
        if isinstance(obj, (list, tuple)):
            try:
                return [self._make_serializable(v) for v in obj]
            except Exception:
                return str(obj)
        try:
            return str(obj)
        except Exception:
            return "unknown"

    async def on_client_connect(self, websocket):
        """Send metadata only, to the newly authenticated subscriber."""
        for node_id, node in self.get_registered_nodes().items():
            with node.lock:
                state = node.raft_terms
                snapshot = {
                    "type": "node_state_change", "node_id": str(node_id),
                    "new_state": state.state.name, "current_term": state.current_term,
                    "last_log_index": state.last_log_index,
                    "last_log_term": state.last_log_term,
                    "commit_index": state.commit_index,
                }
                entries = [{"type": "log_entry", "node_id": str(node_id),
                            "log_index": i, "committed": i <= state.commit_index}
                           for i in range(len(state.logs))]
            if not await self._send_to_client(websocket, json.dumps(snapshot)):
                return
            for entry in entries:
                if not await self._send_to_client(websocket, json.dumps(entry)):
                    return

    async def add_client(self, websocket: WebSocket, authorized=None):
        with self.lock:
            self.clients.add(websocket)
            self.client_checks[websocket] = authorized
            print(f"[WebSocketManager] Client connected. Total clients: {len(self.clients)}")

    async def remove_client(self, websocket: WebSocket):
        with self.lock:
            self.clients.discard(websocket)
            self.client_checks.pop(websocket, None)
            print(f"[WebSocketManager] Client disconnected. Total clients: {len(self.clients)}")

    async def broadcast_heartbeat(
        self,
        leader_id: str,
        current_term: int,
        last_log_index: int,
        last_log_term: int,
        followers: List[str],
        peer_responses: Dict | None = None,
    ):
        print("broadcast_heartbeat EXECUTING")
        if peer_responses is None:
            peer_responses = {}

        message = {
            "type": "heartbeat",
            "leader_id": str(leader_id),
            "current_term": int(current_term),
            "last_log_index": int(last_log_index),
            "last_log_term": int(last_log_term),
            "followers": [str(f) for f in followers],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "responses": self._make_serializable(peer_responses),
        }
        await self._broadcast_now(message)

    async def broadcast_peer_response(self, leader_id: str, peer_id: str,
                                      success: bool, result):
        if result is None:
            result = {}
            
        result = self._make_serializable(result)

        message = {
            "type": "peer_response",
            "leader_id": str(leader_id),
            "peer_id": str(peer_id),
            "success": bool(success),
            "term": result['term'] if result['success'] else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)

    async def broadcast_node_state_change(self, node_id: str, new_state: str, current_term: int):
        message = {
            "type": "node_state_change",
            "node_id": str(node_id),
            "new_state": str(new_state),
            "current_term": int(current_term),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)

    async def broadcast_log_entry(self, node_id: str, log_entry: Dict, log_index: int, committed: bool = False):
        print(f"broadcast_log_entry EXECUTING {node_id}")
        message = {
            "type": "log_entry",
            "node_id": str(node_id),
            "log_index": int(log_index),
            "committed": bool(committed),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)
    
    async def broadcast_vote_request(self, node_id: int, current_term: int, last_log_index: int, last_log_term: int):
        print(f"broadcast vote request EXECUTING {node_id}")
        message = {
            "type": "vote_request",
            "node_id": str(node_id),
            "current_term": current_term,
            "last_log_index": last_log_index,
            "last_log_term": last_log_term,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)
    
    async def broadcast_vote_response(self, node_id: int, voted_for: int, current_term: int, last_log_index: int, last_log_term: int):
        print(f"broadcast vote response EXECUTING {node_id}")
        message = {
            "type": "vote_response",
            "node_id": str(node_id),
            "voted_for": voted_for,
            "current_term": current_term,
            "last_log_index": last_log_index,
            "last_log_term": last_log_term,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)
    
    async def broadcast_election_result(self, node_id: int, election_result: bool, voted_by: List[int], current_term: int, last_log_index: int, last_log_term: int):
        print(f"broadcast election result {node_id}")
        message = {
            "type": "election_result",
            "node_id": str(node_id),
            "election_result": election_result,
            "voted_by": voted_by,
            "current_term": current_term,
            "last_log_index": last_log_index,
            "last_log_term": last_log_term,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)
    
    async def broadcast_entries_committed(
        self,
        node_id: str,
        committed_until_index: int,
        current_term: int,
    ):
        """Broadcast when entries are committed (majority replicated)."""
        message = {
            "type": "entries_committed",
            "node_id": str(node_id),
            "committed_until_index": int(committed_until_index),
            "current_term": int(current_term),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._broadcast_now(message)
    
    async def broadcast_kv_store_update(
        self,
        node_id: str,
        log_index: int,
        log_entry: Dict,
        result: str | None = None,
    ):
        """Only expose application progress; never keys, fields, values or commands."""
        await self._broadcast_now({
            "type": "entry_applied", "node_id": str(node_id),
            "log_index": int(log_index), "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def _broadcast_now(self, message: Dict):
        allowed = {
            "heartbeat": {"leader_id", "current_term", "last_log_index", "last_log_term", "followers"},
            "peer_response": {"leader_id", "peer_id", "success", "term"},
            "node_state_change": {"node_id", "new_state", "current_term"},
            "log_entry": {"node_id", "log_index", "committed"},
            "vote_request": {"node_id", "current_term", "last_log_index", "last_log_term"},
            "vote_response": {"node_id", "voted_for", "current_term", "last_log_index", "last_log_term"},
            "election_result": {"node_id", "election_result", "voted_by", "current_term", "last_log_index", "last_log_term"},
            "entries_committed": {"node_id", "committed_until_index", "current_term"},
            "entry_applied": {"node_id", "log_index"},
        }
        fields = allowed.get(message.get("type"))
        if fields is None:
            return
        message = {k: v for k, v in message.items() if k in fields | {"type", "timestamp"}}
        if not self.clients:
            return

        try:
            message_json = json.dumps(message)
        except Exception as e:
            print(f"[WebSocketManager] JSON serialization failed: {e}")
            return

        disconnected: list[WebSocket] = []

        with self.lock:
            clients_snapshot = list(self.clients)

        for client in clients_snapshot:
            try:
                await self._send_to_client(client, message_json)
            except Exception as e:
                print(f"[WebSocketManager] Error sending to client: {e}")
                disconnected.append(client)

        for client in disconnected:
            await self.remove_client(client)

    async def _send_to_client(self, client, message):
        authorized = self.client_checks.get(client)
        if authorized is not None and not authorized():
            await client.close(code=1008)
            await self.remove_client(client)
            return False
        await client.send_text(message)
        return True

    def get_client_count(self) -> int:
        with self.lock:
            return len(self.clients)