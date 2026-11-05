"""Conservative, window-scoped claims based on identities, topology and evidence."""
from collections import defaultdict
import time
from security.transport import EXCLUSIONS, CLASSES, HYBRID


def report(records, node_ids, direct_clients=("direct-client",), gateway="kv-gateway", window_start=None, window_end=None, evidence_complete=True):
    node_ids = list(node_ids)
    if not node_ids or len(set(node_ids)) != len(node_ids) or any(type(n) is not str or not n for n in node_ids):
        raise ValueError("Supply complete, unique node identities for the evidence window")
    records = list(records)
    end = window_end if window_end is not None else time.time()
    start = window_start if window_start is not None else min((r.get("timestamp", end) for r in records), default=end)
    records = [r for r in records if start <= r.get("timestamp", -1) <= end]
    anomalies, paired_hybrid = [], set()
    unclassified = sorted({r.get("class", "missing") for r in records if r.get("class") not in CLASSES})
    by_connection = defaultdict(list)
    for r in records:
        if r.get("connection_id"):
            by_connection[r["connection_id"]].append(r)
    for connection_id, observations in by_connection.items():
        def signature(r):
            edge = (r.get("local_identity"), r.get("peer_identity"))
            if r.get("direction") == "accepted":
                edge = edge[::-1]
            return (r.get("class"), r.get("key_exchange_group"), r.get("tls_version"), r.get("cipher"), edge)
        signatures = {signature(r) for r in observations}
        if len(signatures) > 1 or any(r["outcome"] == "anomaly" for r in observations):
            anomalies.append(connection_id)
        elif ({r.get("direction") for r in observations} == {"dialed", "accepted"}
              and all(r.get("requirement") == "hybrid-required" and r.get("key_exchange_group") == HYBRID
                      and r.get("tls_version") == "TLSv1.3" and r.get("protection") == "hybrid"
                      and r.get("outcome") == "accepted" and r.get("peer_agreed") for r in observations)):
            paired_hybrid.add(connection_id)
    node_edges = {(a, b) for a in node_ids for b in node_ids if a != b}
    paths = {
        "direct-kv": {"client-node": {(c, n) for c in direct_clients for n in node_ids}, "node-peer": node_edges},
        "http-kv": {"browser-https": set(), "gateway-node": {(gateway, n) for n in node_ids}, "node-peer": node_edges},
        "restricted-logs": {"log-access": set()},
    }
    claims = {}
    for name, path in paths.items():
        reasons, evaluated = ([] if evidence_complete else ["evidence window truncated"]), False
        for transport_class, required_edges in path.items():
            if transport_class == "browser-https":
                reasons.append("browser-https: classical v1 exception")
                evaluated = True
                continue
            relevant = [r for r in records if r["class"] == transport_class]
            if not relevant:
                reasons.append(f"{transport_class}: no observed connections")
                continue
            evaluated = True
            verified_edges = set()
            for r in relevant:
                if (r.get("requirement") == "hybrid-required" and r.get("protection") == "hybrid"
                        and r.get("key_exchange_group") == "X25519MLKEM768" and r.get("tls_version") == "TLSv1.3"
                        and r.get("outcome") == "accepted" and r.get("peer_agreed")
                        and r.get("connection_id") in paired_hybrid):
                    edge = (r["local_identity"], r["peer_identity"])
                    verified_edges.add(edge if r["direction"] == "dialed" else edge[::-1])
                else:
                    reasons.append(f"{transport_class}: {r.get('outcome')} / {r.get('protection')} / {r.get('requirement')}")
            for a, b in sorted(required_edges - verified_edges):
                reasons.append(f"{transport_class}: unverified hop {a}->{b}")
        if anomalies and any(r["class"] in path and r.get("connection_id") in anomalies for r in records):
            reasons.append("disagreeing observations: anomaly")
        if unclassified:
            reasons.append("unclassified evidence: " + ", ".join(unclassified))
        claims[name] = {"status": "not-evaluated" if unclassified else ("hybrid-verified" if not reasons else ("partial" if evaluated else "not-evaluated")),
                        "reasons": sorted(set(reasons)), "exclusions": EXCLUSIONS}
    return {"window_start": start, "window_end": end, "membership": list(node_ids),
            "anomalies": anomalies, "claims": claims}
