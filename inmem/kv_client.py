import json
import os
from security.auth import get_auth
from security.wire import encode
from typing import Optional, Dict, Any, List, Tuple
from inmem.kv_command import create_set_command, create_delete_command


class KVClient:
    """Client for the distributed KV store backed by RAFT consensus."""
    
    def __init__(self, cluster_config: Dict[str, Dict[str, Any]], identity=None):
        
        """
        Initialize client with cluster configuration.
        
        Args:
            cluster_config: Dict of node_id -> {"host": str, "port": int}
                Example: {
                    "A": {"host": "localhost", "port": 5001},
                    "B": {"host": "localhost", "port": 5002},
                    ...
                }
        """
        self.cluster_config = cluster_config
        self.identity = identity or os.environ.get("RAFT_CLIENT_ID", "kv-gateway")
        auth = get_auth()
        if auth.identities[self.identity]["role"] != "client":
            raise PermissionError("KVClient requires a client certificate")
        self._leader_id: Optional[str] = None
        self._connections: Dict[str, Any] = {}
    
    def _get_connection(self, node_id: str):
        """Get or create RPC connection to a node."""
        
        try:
            # Check if connection exists and is valid
            if node_id in self._connections and self._connections[node_id] is not None:
                # Test if connection is alive
                try:
                    self._connections[node_id].ping()
                    return self._connections[node_id]
                except:
                    # Connection is dead, close and recreate
                    self._close_connection(node_id)
            
            # Create new connection
            node_info = self.cluster_config.get(node_id)
            if not node_info:
                raise ValueError(f"Unknown node: {node_id}")
        
            conn = get_auth().connect(
                node_info['host'], node_info['port'],
                identity=self.identity, expected_node=str(node_id),
            )
            
            self._connections[node_id] = conn
            return conn
        
        except Exception as e:
            print(f"[KVClient] Failed to connect to {node_id}: {e}")
            self._connections[node_id] = None
            raise
    
    def _close_connection(self, node_id: str):
        """Close connection to a node."""
        
        if node_id not in self._connections:
            return

        try:
            if self._connections[node_id] is not None:
                self._connections[node_id].close()
        except:
            pass
        
        self._connections[node_id] = None
    
    def _discover_leader(self) -> Optional[str]:
        """Try to find the current leader by querying all nodes."""
        
        if not self.cluster_config:
            print(f"[KVClient] No nodes present in the cluster config")
            return None
        
        for node_id in self.cluster_config:
            try:
                # Get or create connection
                conn = self._get_connection(node_id)
                
                # Query for leader info
                result = json.loads(conn.root.get_leader())
                
                # Check if this node knows the leader
                if result["state"] == "leader":
                    self._leader_id = result["node_id"]
                    print(f"[KVClient] Discovered leader: {self._leader_id}")
                    return self._leader_id
                
                # If node knows who the leader is
                if result["leader_id"]:
                    self._leader_id = result["leader_id"]
                    print(f"[KVClient] Discovered leader: {self._leader_id}")
                    return self._leader_id
                    
            except Exception as e:
                print(f"[KVClient] Could not query {node_id} for leader: {e}")
                self._close_connection(node_id)
                continue
        
        return None
    
    def _send_to_leader(self, command: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
        """Send a write command to the leader with retry logic."""
        
        # Serialize the command that is sent through the network
        operation = command["type"]
        payload = {k: v for k, v in command.items() if k != "type"}
        
        for attempt in range(max_retries):
            
            # Discover leader if we don't know who it is
            if not self._leader_id:
                self._discover_leader()
            
            if not self._leader_id:
                return {
                    "success": False,
                    "error": "NO_LEADER",
                    "message": "Could not find leader after discovery attempts"
                }

            try:
                # Get connection to leader
                conn = self._get_connection(self._leader_id)
                
                # Send command to leader
                method = conn.root.set_kv if operation == "SET" else conn.root.delete_kv
                result = json.loads(method(encode(payload)))
                
                # Success - return result
                if result["success"]:
                    return result

                # Not leader error - update leader hint and retry
                if result["error"] == "NOT_LEADER":
                    print(f"[KVClient] {self._leader_id} is not leader, retrying...")
                    self._leader_id = result["leader_hint"]
                    continue
                
                # Other error - return to caller
                return result
                
            except Exception as e:
                print(f"[KVClient] Error sending to leader {self._leader_id}: {e}")
                self._close_connection(self._leader_id)
                self._leader_id = None
                continue
        
        return {
            "success": False,
            "error": "MAX_RETRIES",
            "message": f"Failed after {max_retries} attempts"
        }

    # ------------------------------------------------------------------
    # Public API - These mirror ByteDataDB but go through RAFT
    # ------------------------------------------------------------------
    
    def set(self, key: str, field: str, value: str, timestamp: int, ttl: Optional[int] = None) -> Dict[str, Any]:
        """
        Set a field value (goes through RAFT consensus).
        
        Returns:
            {"success": True, "index": log_index, "term": term} on success
            {"success": False, "error": str, "message": str} on failure
        """
        command = create_set_command(key, field, value, timestamp, ttl)
        return self._send_to_leader(command=command)
    
    def get(self, key: str, field: str, timestamp: int, node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a field value (reads from committed state machine).
        
        Args:
            key: Record key
            field: Field name
            timestamp: Timestamp for TTL check
            node_id: Optional specific node to read from (default: any available node)
        
        Returns:
            {"success": True, "value": str} if found
            {"success": False, "error": "NOT_FOUND"} if not found or expired
        """
        
        # Determine which node to read from
        # Priority: specified node -> leader -> first available node
        target_node = node_id
        if not target_node:
            target_node = self._leader_id if self._leader_id else list(self.cluster_config.keys())[0]
        
        try:
            conn = self._get_connection(target_node)
            result = json.loads(conn.root.read_kv(encode({"key": key, "field": field, "timestamp": timestamp})))
                                    
            return {
                "success": result["success"], 
                "value": result["value"]
            }
                    
        except Exception as e:
            print(f"[KVClient] Error reading from {target_node}: {e}")
            self._close_connection(target_node)
            return {
                "success": False,
                "error": "CONNECTION_ERROR",
                "message": str(e)
            }
    
    def delete(self, key: str, field: str, timestamp: int) -> Dict[str, Any]:
        """
        Delete a field (goes through RAFT consensus).
        
        Returns:
            {"success": True, "index": log_index, "term": term} on success
            {"success": False, "error": str, "message": str} on failure
        """
        command = create_delete_command(key, field, timestamp)
        return self._send_to_leader(command=command)
    
    def scan(self, key: str, timestamp: int, node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan all fields for a key.
        
        Returns:
            {"success": True, "fields": [(field_name, value), ...]}
        """
        # Determine which node to read from
        target = node_id
        if not target:
            target = self._leader_id if self._leader_id else list(self.cluster_config.keys())[0]
        
        try:
            conn = self._get_connection(target)
            result = json.loads(conn.root.scan_kv(encode({"key": key, "timestamp": timestamp})))
            
            return {
                "success": result["success"],
                "fields": [tuple(field) for field in result["fields"]]  # Convert list netref to local list
            }
        
        except Exception as e:
            print(f"[KVClient] Error scanning from {target}: {e}")
            self._close_connection(target)
            return {
                "success": False,
                "error": "CONNECTION_ERROR",
                "message": str(e)
            }
    
    def scan_by_prefix(self, key: str, prefix: str, timestamp: int, node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan fields matching a prefix for a key.
        
        Returns:
            {"success": True, "fields": [(field_name, value), ...]}
        """
        target = node_id
        if not target:
            target = self._leader_id if self._leader_id else list(self.cluster_config.keys())[0]
        
        try:
            conn = self._get_connection(target)
            result = json.loads(conn.root.scan_kv_by_prefix(encode({"key": key, "prefix": prefix, "timestamp": timestamp})))
            
            return {
                "success": result["success"],
                "fields": [tuple(field) for field in result["fields"]]  # Convert list netref to local list
            }
                    
        except Exception as e:
            print(f"[KVClient] Error scanning from {target}: {e}")
            self._close_connection(target)
            return {
                "success": False,
                "error": "CONNECTION_ERROR",
                "message": str(e)
            }
    
    def close(self):
        """Close all connections."""
        for node_id in list(self._connections.keys()):
            self._close_connection(node_id)