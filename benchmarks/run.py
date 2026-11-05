"""Reproducible classical/preferred/policy comparison using real Raft RPC.

Coordinator: python -m benchmarks.run --output benchmarks/results
Worker processes always start through security.launcher. No normal cluster ports
or state files are used. Default measurements implement PQC_PLAN.md in full.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low = int(position)
    return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (position - low)


def worker(args):
    import ssl
    from benchmarks.cluster import Cluster
    from inmem.kv_client import KVClient
    from security.auth import get_auth
    from security.claims import report
    from security.transport import EVIDENCE, get_policy
    output = Path(args.fragment).resolve()
    result = {"profile": get_policy().profile, "trial": args.trial,
              "runtime": {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION,
                          "platform": platform.platform()},
              "parameters": {"handshakes": args.handshakes, "duration_seconds": args.duration,
                             "warmup_seconds": args.warmup, "value_bytes": 1024,
                             "replication_driver_interval_seconds": .01}, "workloads": []}
    # Existing Raft code logs payloads verbosely. Keep benchmark samples/artifacts
    # metadata-only and avoid console I/O dominating the measurements.
    with open(os.devnull, "w") as quiet:
        saved_stdout = sys.stdout
        sys.stdout = quiet
        try:
            with Cluster() as cluster:
                auth = get_auth()
                auth.check_capability("direct-client")
                handshakes = []
                for _ in range(args.handshakes):
                    start, cpu = time.perf_counter(), time.process_time()
                    conn = auth.connect(**cluster.config["A"], identity="direct-client", expected_node="A")
                    elapsed, cpu_elapsed = time.perf_counter() - start, time.process_time() - cpu
                    conn.close()
                    # Dialed evidence contains this socket's TLS-only byte counts.
                    evidence = next(r for r in reversed(EVIDENCE.records) if r["direction"] == "dialed")
                    handshakes.append({"connection_ready_ms": elapsed * 1000, "process_cpu_ms": cpu_elapsed * 1000,
                                       "tls_handshake_ms": evidence.get("tls_handshake_ms"),
                                       "tls_bytes_sent": evidence["tls_bytes_sent"],
                                       "tls_bytes_received": evidence["tls_bytes_received"],
                                       "group": evidence["key_exchange_group"]})
                result["handshakes"] = handshakes
                result["election_ms"] = cluster.elect()
            for concurrency in (1, 8):
                EVIDENCE.reset()
                with Cluster() as cluster:
                    cluster.probe_topology()
                    election_ms = cluster.elect()
                    cluster.start_replication()
                    clients = [KVClient(cluster.config, identity="direct-client") for _ in range(concurrency)]
                    for client in clients:
                        client._discover_leader()
                    durations, commits, errors = [], [], []

                    def load(client, worker_id, seconds, record):
                        deadline = time.monotonic() + seconds
                        sequence = 0
                        samples, commit_samples, failures = [], [], []
                        while time.monotonic() < deadline:
                            sequence += 1
                            started = time.perf_counter()
                            stamp = time.time_ns() // 1000
                            # Replace one field per worker to bound committed DB size.
                            response = client.set(f"benchmark-{worker_id}", "value", "x" * 1024, stamp)
                            if not response.get("success"):
                                failures.append(response.get("error", "WRITE_FAILED"))
                                break
                            try:
                                cluster.wait_commit(response["index"])
                            except TimeoutError:
                                failures.append("COMMIT_TIMEOUT")
                                break
                            committed_at = time.perf_counter()
                            read = client.get(f"benchmark-{worker_id}", "value", time.time_ns() // 1000, node_id="A")
                            if read.get("value") != "x" * 1024:
                                failures.append("READ_MISMATCH")
                                break
                            if record:
                                samples.append((time.perf_counter() - started) * 1000)
                                commit_samples.append((committed_at - started) * 1000)
                        return samples, commit_samples, failures

                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        warmup = list(pool.map(lambda item: load(item[1], item[0], args.warmup, False), enumerate(clients)))
                        if any(row[2] for row in warmup):
                            raise RuntimeError(f"Warmup failed: {warmup}")
                        start, cpu = time.perf_counter(), time.process_time()
                        samples = list(pool.map(lambda item: load(item[1], item[0], args.duration, True), enumerate(clients)))
                        elapsed, cpu_elapsed = time.perf_counter() - start, time.process_time() - cpu
                    for latency, commit, failure in samples:
                        durations.extend(latency)
                        commits.extend(commit)
                        errors.extend(failure)
                    for client in clients:
                        client.close()
                    cluster.stop.set()
                    cluster.pump.join(10)
                    cluster.wait_for_evidence()
                    snapshot = EVIDENCE.snapshot()
                    claims = report(EVIDENCE.records, list(cluster.nodes), window_start=snapshot["window_start"],
                                    evidence_complete=snapshot["dropped_records"] == 0)
                    result["workloads"].append({"concurrency": concurrency, "completed_transactions": len(durations),
                        "completed_kv_operations": len(durations) * 2, "elapsed_seconds": elapsed,
                        "transactions_per_second": len(durations) / elapsed, "kv_operations_per_second": len(durations) * 2 / elapsed,
                        "p50_ms": percentile(durations, .50), "p95_ms": percentile(durations, .95), "p99_ms": percentile(durations, .99),
                        "write_to_commit_p50_ms": percentile(commits, .50), "write_to_commit_p95_ms": percentile(commits, .95),
                        "transaction_latencies_ms": durations, "write_to_commit_latencies_ms": commits,
                        "process_cpu_seconds": cpu_elapsed, "election_ms": election_ms, "errors": errors,
                        "transport": snapshot, "claim_report": claims})
        finally:
            sys.stdout = saved_stdout
    output.write_text(json.dumps(result, indent=2) + "\n")
    if any(w["errors"] for w in result["workloads"]):
        raise RuntimeError("Benchmark contained failed operations; inspect raw result")


def coordinator(args):
    from tools.bootstrap_auth import bootstrap
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="raft-pqc-bench-credentials-") as directory:
        config = bootstrap(Path(directory) / "credentials")
        env = dict(os.environ, RAFT_AUTH_CONFIG=str(config))
        env.pop("RAFT_PQC_EVIDENCE", None)
        profiles = ["classical", "hybrid-preferred", "policy"]
        for trial in range(1, args.trials + 1):
            order = profiles[(trial - 1) % 3:] + profiles[:(trial - 1) % 3]
            for profile in order:
                fragment = output / f"{profile}-{trial}.json"
                print(f"trial {trial}/{args.trials}: {profile} ({args.duration}s per concurrency)", flush=True)
                command = [sys.executable, "-m", "security.launcher", "--profile", profile, "-m", "benchmarks.run",
                           "--worker", "--trial", str(trial), "--fragment", str(fragment),
                           "--duration", str(args.duration), "--warmup", str(args.warmup), "--handshakes", str(args.handshakes)]
                completed = subprocess.run(command, env=env, capture_output=True, text=True)
                if completed.returncode:
                    (output / "failure.log").write_text(completed.stdout + completed.stderr)
                    raise RuntimeError(f"Benchmark worker failed: {profile}; see {output / 'failure.log'}")
                rows.append(json.loads(fragment.read_text()))
                write_report(output, rows)


def write_report(output, results):
    fields = ["profile", "trial", "concurrency", "transactions_per_second", "kv_operations_per_second", "p50_ms", "p95_ms", "p99_ms",
              "write_to_commit_p50_ms", "write_to_commit_p95_ms", "election_ms", "process_cpu_seconds", "errors", "fallbacks", "rejections"]
    with (output / "raw.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for result in results:
            for w in result["workloads"]:
                row = {k: w.get(k) for k in fields}
                row.update(profile=result["profile"], trial=result["trial"], errors=len(w["errors"]),
                           fallbacks=sum(c["count"] for c in w["transport"]["counts"] if c["outcome"] == "fallback"),
                           rejections=sum(c["count"] for c in w["transport"]["counts"] if "rejection" in c["outcome"]))
                writer.writerow(row)
    lines = ["# PQC benchmark results", "", "Measured with real three-node Raft RPC and separate TLS contexts.", "",
             "Each transaction writes a 1 KiB value, waits for majority commit, then reads it back. Both KV operations are counted.",
             "Replication is driven every 10 ms for all profiles; production timers and consensus code are unchanged.",
             "CPU is whole-process CPU (three nodes plus load generator). TLS record bytes exclude TCP/IP and the evidence preface.", "",
             "| Profile | Concurrency | Trials | KV ops/s (mean) | Transaction p50 ms (mean) | p95 ms (mean) | p99 ms (mean) |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for profile in ("classical", "hybrid-preferred", "policy"):
        selected = [r for r in results if r["profile"] == profile]
        for concurrency in (1, 8):
            cases = [w for r in selected for w in r["workloads"] if w["concurrency"] == concurrency]
            if cases:
                mean = lambda key: statistics.mean(w[key] for w in cases)
                lines.append(f"| {profile} | {concurrency} | {len(cases)} | {mean('kv_operations_per_second'):.2f} | {mean('p50_ms'):.2f} | {mean('p95_ms'):.2f} | {mean('p99_ms'):.2f} |")
    lines.extend(["", "| Profile | Connection-ready p50 ms | TLS handshake p50 ms | Mean process CPU ms/connection | Mean TLS record bytes/connection | Election ms (mean) |",
                  "| --- | ---: | ---: | ---: | ---: | ---: |"])
    for profile in ("classical", "hybrid-preferred", "policy"):
        selected = [r for r in results if r["profile"] == profile]
        hs = [h for r in selected for h in r["handshakes"]]
        if hs:
            lines.append(f"| {profile} | {percentile([h['connection_ready_ms'] for h in hs], .5):.3f} | {percentile([h['tls_handshake_ms'] for h in hs], .5):.3f} | {statistics.mean(h['process_cpu_ms'] for h in hs):.3f} | {statistics.mean(h['tls_bytes_sent'] + h['tls_bytes_received'] for h in hs):.0f} | {statistics.mean(r['election_ms'] for r in selected):.3f} |")
    lines += ["", "Counters below are endpoint observations (dialed and accepted sides), not unique connections.",
              "", "| Profile | Accepted observations | Fallback observations | Required-class rejections | Anomalies | Failed transactions |",
              "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for profile in ("classical", "hybrid-preferred", "policy"):
        selected = [r for r in results if r["profile"] == profile]
        counters = [c for r in selected for w in r["workloads"] for c in w["transport"]["counts"]]
        count = lambda outcome: sum(c["count"] for c in counters if c["outcome"] == outcome)
        failures = sum(len(w["errors"]) for r in selected for w in r["workloads"])
        lines.append(f"| {profile} | {count('accepted')} | {count('fallback')} | {count('required-class-rejection')} | {count('anomaly')} | {failures} |")
    lines += ["", "| Profile | Direct-path claim statuses | HTTP-path claim statuses |", "| --- | --- | --- |"]
    for profile in ("classical", "hybrid-preferred", "policy"):
        cases = [w for r in results if r["profile"] == profile for w in r["workloads"]]
        if cases:
            direct = sorted({w["claim_report"]["claims"]["direct-kv"]["status"] for w in cases})
            http = sorted({w["claim_report"]["claims"]["http-kv"]["status"] for w in cases})
            lines.append(f"| {profile} | {', '.join(direct)} | {', '.join(http)} |")
    if results:
        with (output / "handshakes.csv").open("w", newline="") as file:
            keys = ["profile", "trial", "sample", "connection_ready_ms", "tls_handshake_ms", "process_cpu_ms", "tls_bytes_sent", "tls_bytes_received", "group"]
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            for r in results:
                for index, handshake in enumerate(r["handshakes"]):
                    writer.writerow(dict(handshake, profile=r["profile"], trial=r["trial"], sample=index))
        with (output / "latencies.csv").open("w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["profile", "trial", "concurrency", "sample", "transaction_ms", "write_to_commit_ms"])
            for r in results:
                for w in r["workloads"]:
                    for index, pair in enumerate(zip(w["transaction_latencies_ms"], w["write_to_commit_latencies_ms"])):
                        writer.writerow([r["profile"], r["trial"], w["concurrency"], index, *pair])
    if results:
        lines += ["", "Runtime: `" + json.dumps(results[0]["runtime"]) + "`.",
                  "", "Raw per-trial JSON contains every latency sample, counters, requirements and window-scoped claim reports. See raw.csv for the trial table.",
                  "Classical and hybrid-preferred profiles cannot earn hybrid-verified value-path claims: those classes were not hybrid-required.",
                  "Policy claims additionally require matched hybrid evidence across the full configured topology; HTTP paths remain partial due to the browser exception.",
                  "Exclusions: classical certificate authentication, browser HTTPS/WSS, and stored data. These measurements do not establish post-quantum authentication."]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="benchmarks/results")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--warmup", type=float, default=5)
    parser.add_argument("--handshakes", type=int, default=100)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--fragment")
    args = parser.parse_args()
    if args.trials < 1 or args.duration <= 0 or args.warmup < 0 or args.handshakes < 1:
        parser.error("Invalid benchmark parameters")
    worker(args) if args.worker else coordinator(args)


if __name__ == "__main__":
    main()
