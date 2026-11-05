"""Report local capability and optionally actual classified peer connections."""
import argparse
import json
import os
from security.auth import get_auth
from security.transport import EVIDENCE, get_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", default=os.environ.get("RAFT_CLIENT_ID", "direct-client"))
    parser.add_argument("--peer", action="append", default=[], help="NODE_ID:HOST:PORT")
    args = parser.parse_args()
    auth = get_auth()
    result = {"profile": get_policy().profile, "classes": {c: get_policy().requirement(c) for c in get_policy().classes},
              "runtime": auth.check_capability(args.identity), "observations": []}
    for peer in args.peer:
        node, host, port = peer.split(":")
        try:
            conn = auth.connect(host, int(port), args.identity, node)
            conn.close()
        except Exception as exc:
            result["observations"].append({"peer": node, "error": type(exc).__name__})
    result["observations"].extend(EVIDENCE.records)
    result["transport"] = EVIDENCE.snapshot()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
