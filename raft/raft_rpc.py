"""Authenticated, role-limited RPyC entry points. Wire messages are JSON strings."""
if __name__ == "__main__":
    from security.launcher import ensure_launched
    ensure_launched("raft.raft_rpc")

import rpyc
from rpyc.utils.server import ThreadedServer
from raft.raft_server import Raft
from raft.vote_arguments import VoteArguments
from raft.health_check_arguments import HealthCheckArguments
from inmem.byte_data_db import ByteDataDB
from inmem.state_machine_applier import StateMachineApplier
from inmem.kv_command import create_set_command, create_delete_command, serialize_command
from security.auth import get_auth, Principal, RPC_CONFIG
from security.wire import Vote, Heartbeat, Set, Read, Key, ScanPrefix, decode, encode

NODE_METHODS = {"send_vote_request", "send_health_check_request"}
CLIENT_METHODS = {"set_kv", "delete_kv", "read_kv", "scan_kv", "scan_kv_by_prefix", "get_leader"}


class RaftService(rpyc.Service):
    def __init__(self, raft, db):
        self._raft, self._db = raft, db
        self._principal = None

    def on_connect(self, conn):
        principal = conn._config.get("credentials")
        if not isinstance(principal, Principal) or principal.role not in {"node", "client"}:
            raise PermissionError("Authenticated RPC identity required")
        if principal.role == "node" and principal.identity not in {str(peer) for peer in self._raft.raft_terms.peers}:
            raise PermissionError("Node is not a member of this peer group")
        self._principal = principal

    def _authorize(self, method):
        allowed = NODE_METHODS if self._principal and self._principal.role == "node" else (
            CLIENT_METHODS if self._principal and self._principal.role == "client" else set())
        if method not in allowed:
            raise PermissionError("RPC operation forbidden")

    def _rpyc_getattr(self, name):
        # Includes magic attributes and inherited service methods: deny by default.
        method = name.removeprefix("exposed_")
        self._authorize(method)
        return getattr(self, "exposed_" + method)

    def exposed_send_vote_request(self, payload):
        self._authorize("send_vote_request")
        vote = decode(payload, Vote)
        if vote.candidate_id != self._principal.identity:
            raise PermissionError("Candidate identity does not match certificate")
        return self._raft.handle_request_vote(VoteArguments(**vote.model_dump()))

    def exposed_send_health_check_request(self, payload):
        self._authorize("send_health_check_request")
        heartbeat = decode(payload, Heartbeat)
        if heartbeat.leader_id != self._principal.identity:
            raise PermissionError("Leader identity does not match certificate")
        result = self._raft.handle_health_check_request(HealthCheckArguments(**heartbeat.model_dump()))
        return encode(result)

    def exposed_set_kv(self, payload):
        self._authorize("set_kv")
        args = decode(payload, Set)
        command = create_set_command(**args.model_dump())
        return encode(self._raft.append_log_entries(serialize_command(command)))

    def exposed_delete_kv(self, payload):
        self._authorize("delete_kv")
        args = decode(payload, Read)
        command = create_delete_command(**args.model_dump())
        return encode(self._raft.append_log_entries(serialize_command(command)))

    def exposed_get_leader(self):
        self._authorize("get_leader")
        return encode(self._raft.get_leader_info())

    def exposed_read_kv(self, payload):
        self._authorize("read_kv")
        args = decode(payload, Read)
        value = self._db.get_at(args.key, args.field, args.timestamp)
        return encode({"success": value is not None, "value": value if value is not None else "NOT_FOUND"})

    def exposed_scan_kv(self, payload):
        self._authorize("scan_kv")
        args = decode(payload, Key)
        record = self._db.get_record(args.key)
        return encode({"success": True, "fields": record.scan_fields(args.timestamp) if record else []})

    def exposed_scan_kv_by_prefix(self, payload):
        self._authorize("scan_kv_by_prefix")
        args = decode(payload, ScanPrefix)
        record = self._db.get_record(args.key)
        return encode({"success": True, "fields": record.scan_fields_by_prefix(args.prefix, args.timestamp) if record else []})


class AuthenticatedThreadedServer(ThreadedServer):
    def _serve_client(self, sock, credentials):
        try:
            return super()._serve_client(sock, credentials)
        except (OSError, EOFError):
            # Peers may disconnect immediately after a failed identity check.
            return
        finally:
            sock.close()


def create_rpc_server(raft, db, host, port):
    # RPyC instantiates this class for EVERY connection; only Raft/DB are shared.
    class ConnectionService(RaftService):
        def __init__(self):
            super().__init__(raft, db)

    return AuthenticatedThreadedServer(
        ConnectionService, hostname=host, port=port,
        authenticator=get_auth().authenticator(str(raft.raft_terms.id)),
        protocol_config=RPC_CONFIG.copy(),
    )


def run_server(host="127.0.0.1", port=5001, node_id="A", peers_config=None):
    get_auth().authenticator(str(node_id))  # Validate before creating state/threads.
    db = ByteDataDB.get_instance()
    raft_node = Raft(node_id=node_id, peers_config=peers_config or {},
                     logs_file_path=f"raft_node_{node_id}.log",
                     state_machine_applier=StateMachineApplier(db))
    server = create_rpc_server(raft_node, db, host, port)
    raft_node.start_raft_node()
    try:
        server.start()
    finally:
        raft_node.kill()
        server.close()


if __name__ == "__main__":
    run_server()
