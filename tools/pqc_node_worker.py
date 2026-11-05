"""Isolated node used by mixed-runtime integration tests."""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
import time
from inmem.byte_data_db import ByteDataDB
from inmem.state_machine_applier import StateMachineApplier
from raft.raft_rpc import create_rpc_server
from raft.raft_server import Raft


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--status", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.cluster).read_text())
    status = Path(args.status).resolve()
    os.chdir(args.state_directory)
    db = ByteDataDB()
    node = Raft(args.node, peers_config={k: v for k, v in config.items() if k != args.node},
                logs_file_path=str(Path(args.state_directory) / "node.jsonl"), state_machine_applier=StateMachineApplier(db))
    info = config[args.node]
    server = create_rpc_server(node, db, info["host"], info["port"])
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *args: stop.set())
    node.start_raft_node()
    try:
        while not stop.wait(.05):
            data = {"term": node.raft_terms.current_term, "state": node.raft_terms.state.name, "ready": True}
            temporary = status.with_suffix(".tmp")
            temporary.write_text(json.dumps(data))
            temporary.replace(status)
    finally:
        node.kill()
        server.close()
        thread.join(5)


if __name__ == "__main__":
    main()
