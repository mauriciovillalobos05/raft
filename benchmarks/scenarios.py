"""Focused PQC connection, quorum and emulated-link experiments.

Run: raft-venv/bin/python -m benchmarks.scenarios --output benchmarks/scenario-results
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import json
import os
from pathlib import Path
import platform
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

from benchmarks.run import percentile


class LinkProxy:
    """Opaque TCP relay with per-chunk delay and seeded recovery stalls.

    A 1460-byte relay chunk models a segment. A sampled loss adds 200 ms
    recovery delay before forwarding the original bytes, preserving TLS.
    This is an impairment model, not a kernel packet-loss emulator.
    """
    def __init__(self, target, delay_ms=0, loss=0, seed=0):
        self.target, self.delay, self.loss = target, delay_ms / 1000, loss
        self.random = random.Random(seed)
        self.lock = threading.Lock()
        self.stalls = 0
        self.chunks = 0
        self.sockets = []
        self.threads = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                incoming, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                outgoing = socket.create_connection(self.target, timeout=5)
                incoming.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                outgoing.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                incoming.settimeout(.1)
                outgoing.settimeout(.1)
                with self.lock:
                    self.sockets.extend([incoming, outgoing])
                for source, destination in ((incoming, outgoing), (outgoing, incoming)):
                    thread = threading.Thread(target=self.relay, args=(source, destination), daemon=True)
                    self.threads.append(thread)
                    thread.start()
            except OSError:
                incoming.close()

    def relay(self, source, destination):
        try:
            while not self.stop.is_set():
                try:
                    data = source.recv(1460)
                except socket.timeout:
                    continue
                if not data:
                    break
                with self.lock:
                    self.chunks += 1
                    lost = self.random.random() < self.loss
                    self.stalls += int(lost)
                if self.stop.wait(self.delay + (.2 if lost else 0)):
                    break
                destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(2)


def summary(samples, elapsed, cpu, errors):
    return {'completed': len(samples), 'elapsed_s': elapsed, 'operations_s': len(samples) / elapsed,
            'cpu_s': cpu, 'p50_ms': percentile(samples, .5), 'p95_ms': percentile(samples, .95),
            'p99_ms': percentile(samples, .99), 'latencies_ms': samples, 'errors': errors}


def connections(args):
    from benchmarks.cluster import Cluster
    from security.auth import get_auth
    from security.transport import EVIDENCE
    from security.wire import encode
    result = []
    conditions = [('direct', 0, 0)] if args.case == 'connections' else [
        ('relay-baseline', 0, 0), ('delay-10ms', 10, 0), ('delay-10ms-loss-stalls-1pct', 10, .01)]
    with Cluster() as cluster, ExitStack() as stack:
        cluster.elect()
        cluster.start_replication()
        auth = get_auth()
        auth.check_capability('direct-client')
        for label, delay, loss in conditions:
            endpoint = cluster.config['A'].copy()
            proxy = None
            if label != 'direct':
                proxy = LinkProxy((endpoint['host'], endpoint['port']), delay, loss, args.trial)
                stack.callback(proxy.close)
                endpoint['port'] = proxy.port
            modes = ('pooled', 'fresh', 'burst')
            for mode in modes:
                EVIDENCE.reset()
                pooled = None
                if mode == 'pooled':
                    pooled = auth.connect(**endpoint, identity='direct-client', expected_node='A')
                def operation(sequence):
                    started = time.perf_counter()
                    conn = pooled
                    try:
                        if conn is None:
                            conn = auth.connect(**endpoint, identity='direct-client', expected_node='A')
                        key = f'{label}-{mode}-{sequence}'
                        response = json.loads(conn.root.set_kv(encode({
                            'key': key, 'field': 'field', 'value': 'x' * 1024,
                            'timestamp': time.time_ns() // 1000})))
                        if not response.get('success'):
                            raise RuntimeError(f'Write failed: {response}')
                        cluster.wait_commit(response['index'])
                        read = json.loads(conn.root.read_kv(encode({
                            'key': key, 'field': 'field', 'timestamp': time.time_ns() // 1000})))
                        if not read.get('success') or read.get('value') != 'x' * 1024:
                            raise RuntimeError('Committed read mismatch')
                        return (time.perf_counter() - started) * 1000, None
                    except Exception as exc:
                        return None, f'{type(exc).__name__}: {exc}'
                    finally:
                        if conn is not None and pooled is None:
                            conn.close()
                before_stalls = proxy.stalls if proxy else 0
                before_chunks = proxy.chunks if proxy else 0
                start, cpu = time.perf_counter(), time.process_time()
                with ThreadPoolExecutor(max_workers=8 if mode == 'burst' else 1) as pool:
                    outcomes = list(pool.map(operation, range(args.samples)))
                elapsed, cpu = time.perf_counter() - start, time.process_time() - cpu
                if pooled:
                    pooled.close()
                cluster.wait_for_evidence()
                errors = [error for _, error in outcomes if error]
                rows = [r for r in EVIDENCE.records if r['direction'] == 'dialed'
                        and r['local_identity'] == 'direct-client']
                result.append(dict(summary([ms for ms, error in outcomes if error is None], elapsed, cpu, errors),
                    condition=label, mode=mode, initial_pool_handshake_excluded=(mode == 'pooled'),
                    new_connections=len(rows) - int(mode == 'pooled'),
                    handshake_samples=[{k: r.get(k) for k in ('key_exchange_group', 'tls_handshake_ms',
                        'tls_bytes_sent', 'tls_bytes_received', 'hello_retries')} for r in rows],
                    simulated_recovery_stalls=(proxy.stalls - before_stalls) if proxy else 0,
                    relay_chunks=(proxy.chunks - before_chunks) if proxy else 0))
    return result


def quorum(args):
    from benchmarks.cluster import Cluster
    from inmem.kv_client import KVClient
    from security.transport import EVIDENCE
    results = []
    for capable in (3, 2, 1):
        EVIDENCE.reset()
        with Cluster() as cluster, ExitStack() as stack:
            config = Path(cluster.temp.name) / 'cluster.json'
            config.write_text(json.dumps(cluster.config))
            for node_id in list('ABC')[capable:]:
                cluster.servers[node_id].close()
                cluster.nodes[node_id].kill()
                state = Path(cluster.temp.name) / node_id
                state.mkdir()
                status = state / 'status.json'
                command = [sys.executable, '-m', 'security.launcher', '--profile', 'classical',
                    '-m', 'tools.pqc_node_worker', '--node', node_id, '--cluster', str(config),
                    '--state-directory', str(state), '--status', str(status)]
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                def cleanup(process=process):
                    process.terminate()
                    try:
                        process.wait(12)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                stack.callback(cleanup)
                deadline = time.monotonic() + 8
                while not status.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('Classical worker failed to start')
                    time.sleep(.03)
            started = time.perf_counter()
            cluster.nodes['A'].request_vote()
            election_ms = (time.perf_counter() - started) * 1000
            elected = cluster.nodes['A'].raft_terms.state.name == 'leader'
            cluster.start_replication(interval=.1)
            def write_and_commit(leader, stamp):
                client = KVClient({leader: cluster.config[leader]}, identity='direct-client')
                try:
                    response = client.set('scenario', 'field', 'x' * 1024, stamp)
                    if not response.get('success'):
                        return False
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        count = sum(n.raft_terms.commit_index >= response['index']
                            for n in cluster.nodes.values() if not n.killed())
                        if count >= 2:
                            return True
                        time.sleep(.01)
                    return False
                finally:
                    client.close()
            committed = write_and_commit('A', time.time_ns() // 1000) if elected else False
            before_votes = dict(cluster.nodes['A'].received_votes)
            cluster.servers['A'].close()
            cluster.nodes['A'].kill()
            recovered = False
            recovery_ms = None
            if capable >= 2:
                started = time.perf_counter()
                cluster.nodes['B'].request_vote()
                recovered = cluster.nodes['B'].raft_terms.state.name == 'leader'
                if recovered:
                    recovered = write_and_commit('B', time.time_ns() // 1000)
                recovery_ms = (time.perf_counter() - started) * 1000
            rejected = [r for r in EVIDENCE.records if r.get('outcome') == 'required-class-rejection']
            row = {'hybrid_nodes': capable, 'membership': 3, 'majority': 2,
                   'initial_leader': elected, 'initial_commit': committed, 'votes': before_votes,
                   'election_attempt_ms': election_ms, 'leader_failure_recovered_and_committed': recovered,
                   'recovery_attempt_ms': recovery_ms, 'required_class_rejections': len(rejected),
                   'rejection_peers': sorted({r['peer_identity'] for r in rejected})}
            expected = (elected == (capable >= 2) and committed == (capable >= 2) and recovered == (capable == 3))
            row['passed'] = expected
            results.append(row)
    return results


def worker(args):
    import ssl
    output = Path(args.fragment).resolve()
    with open(os.devnull, 'w') as quiet, redirect_stdout(quiet), redirect_stderr(quiet):
        rows = quorum(args) if args.case == 'quorum' else connections(args)
    result = {'case': args.case, 'profile': os.environ['RAFT_PQC_PROFILE'], 'trial': args.trial,
              'runtime': {'python': sys.version, 'openssl': ssl.OPENSSL_VERSION, 'platform': platform.platform()},
              'samples_per_mode': args.samples, 'rows': rows}
    output.write_text(json.dumps(result, indent=2) + '\n')
    failed = any(not r['passed'] for r in rows) if args.case == 'quorum' else any(r['errors'] for r in rows)
    if failed:
        raise RuntimeError(f'Scenario failed; inspect {output}')


def write_report(output):
    files = sorted(output.glob('*.json'))
    experiments = [json.loads(path.read_text()) for path in files]
    lines = ['# Focused PQC scenario results', '',
        'Measured on 2026-11-04. Trial IDs ' + ', '.join(str(t) for t in sorted({e['trial'] for e in experiments}))
        + '. Transactions per mode per trial ' + ', '.join(str(n) for n in sorted({e['samples_per_mode'] for e in experiments})) + '. '
        'Each transaction writes 1,024 bytes, waits for majority commit, then verifies a read from the leader. '
        'Burst mode uses eight workers. Pooled and fresh modes use one worker.', '',
        'Reproduce with `raft-venv/bin/python -m benchmarks.scenarios --trials 3 --samples 60`.', '',
        'Only the connection, mixed-capability quorum, and emulated network scenarios were run. '
        'Each worker starts through `security.launcher` using temporary credentials and isolated cluster state.', '',
        '## Runtime', '', json.dumps(experiments[0]['runtime']), '',
        '## Connection and network experiments', '',
        'Latency is the full write/commit/read transaction, including connection setup for fresh and burst modes. '
        'The initial pooled connection is established before timing. Each table cell is the median of the '
        'available trial-level metrics. Tail percentiles have only 60 samples per trial in this run and are exploratory.', '',
        '| Case | Profile | Condition | Mode | Transactions/s | p50 ms | p95 ms | p99 ms | CPU s | Errors |',
        '| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    groups = {}
    for experiment in experiments:
        if experiment['case'] == 'quorum':
            continue
        for row in experiment['rows']:
            key = (experiment['case'], experiment['profile'], row['condition'], row['mode'])
            groups.setdefault(key, []).append(row)
    for key, rows in sorted(groups.items()):
        values = [statistics.median(r[field] for r in rows)
                  for field in ('operations_s', 'p50_ms', 'p95_ms', 'p99_ms', 'cpu_s')]
        lines.append('| ' + ' | '.join(key) + ' | ' + ' | '.join(f'{v:.3f}' for v in values)
                     + f" | {sum(len(r['errors']) for r in rows)} |")
    completed = sum(r['completed'] for rows in groups.values() for r in rows)
    errors = sum(len(r['errors']) for rows in groups.values() for r in rows)
    lines += ['', f'The connection and network runs completed {completed:,} transactions '
              f'({completed * 2:,} KV operations) with {errors} workload errors. '
              'Quorum writes are counted separately below.', '']
    if ('network', 'policy', 'delay-10ms', 'fresh') in groups:
        def median_metric(profile, condition, mode, field):
            return statistics.median(r[field] for r in groups[('network', profile, condition, mode)])
        classical = median_metric('classical', 'delay-10ms', 'fresh', 'p50_ms')
        hybrid = median_metric('policy', 'delay-10ms', 'fresh', 'p50_ms')
        pooled = median_metric('policy', 'delay-10ms', 'pooled', 'p50_ms')
        tail = median_metric('policy', 'delay-10ms-loss-stalls-1pct', 'fresh', 'p99_ms')
        lines += [f'With the emulated delay, fresh-connection median transaction latency was '
            f'{classical:.2f} ms for classical TLS and {hybrid:.2f} ms for hybrid-required TLS. '
            f'The hybrid pooled median was {pooled:.2f} ms. With recovery stalls, the hybrid fresh '
            f'p99 was {tail:.2f} ms. These measurements associate connection reuse with lower '
            'transaction setup cost under this model. The small sample and host scheduling do '
            'not establish statistical significance of profile differences.', '']
    lines += ['', '## TLS observations', '',
        '| Profile | Client handshakes | Median TLS ms | Mean TLS record bytes | HelloRetryRequests | Groups |',
        '| --- | ---: | ---: | ---: | ---: | --- |']
    for profile in ('classical', 'policy'):
        samples = [sample for e in experiments if e['case'] == 'connections' and e['profile'] == profile
                   for r in e['rows'] for sample in r['handshake_samples']]
        lines.append(f"| {profile} | {len(samples)} | "
            f"{statistics.median(s['tls_handshake_ms'] for s in samples):.3f} | "
            f"{statistics.mean(s['tls_bytes_sent'] + s['tls_bytes_received'] for s in samples):.1f} | "
            f"{sum(s['hello_retries'] for s in samples)} | "
            + ', '.join(sorted({s['key_exchange_group'] for s in samples})) + ' |')
    lines += ['', '## Mixed-capability quorum', '',
        'Membership remains three and majority remains two. Hybrid-capable nodes use the strict policy profile. '
        'Other nodes run the existing node worker in a separate classical-only comparison process. '
        'Those comparison peers permit classical connections to each other. The one-hybrid-node case '
        'tests whether strict candidate A can win; it does not establish that a separate classical '
        'majority can never elect its own leader. '
        'The candidate A invokes the normal RequestVote path explicitly. After an initial commit, A is stopped '
        'and B invokes RequestVote when B is hybrid-capable. Recovery requires another majority commit. '
        'These are controlled election attempts, not measurements of randomized failure detection. '
        'A failed attempt duration is not time to recovery.', '',
        '| Hybrid nodes | Trials passed | Initial election/commit | Recovery and new commit after A fails | Median election attempt ms | Rejected connections |',
        '| ---: | ---: | --- | --- | ---: | ---: |']
    for capable in (3, 2, 1):
        rows = [r for e in experiments if e['case'] == 'quorum' for r in e['rows'] if r['hybrid_nodes'] == capable]
        recovery = (f"{sum(r['leader_failure_recovered_and_committed'] for r in rows)}/{len(rows)}"
                    if capable >= 2 else 'Not attempted; no initial hybrid leader')
        lines.append(f"| {capable} | {sum(r['passed'] for r in rows)}/{len(rows)} | "
            f"{sum(r['initial_leader'] and r['initial_commit'] for r in rows)}/{len(rows)} | "
            f"{recovery} | "
            f"{statistics.median(r['election_attempt_ms'] for r in rows):.3f} | "
            f"{sum(r['required_class_rejections'] for r in rows)} |")
    stalls = sum(r['simulated_recovery_stalls'] for e in experiments if e['case'] == 'network' for r in e['rows'])
    lines += ['', '## Network model and limitations', '',
        'An opaque TCP relay forwards up to 1,460 bytes per read without terminating TLS. '
        'Conditions are a relay baseline, 10 ms delay per forwarded chunk in each direction, '
        'and that delay plus a seeded 1% probability of a 200 ms recovery stall per chunk. '
        f'The timed workloads sampled {stalls} recovery stalls. Seeds equal trial numbers. '
        'Thread scheduling and TCP read boundaries can change random draw assignment across runs. '
        'This models delayed delivery and loss recovery. It does not drop IP packets, implement TCP congestion '
        'control, or establish performance under actual 1% packet loss. The nominal 20 ms round trip applies '
        'to one chunk in each direction. Larger TLS flights may incur several sequential chunk delays. '
        'Compare impaired rows with the relay baseline. Only client-to-A traffic traverses the relay. '
        'Raft replication remains local. CPU includes relay and cluster threads in the worker process.', '',
        'Three nodes share one macOS host. The harness drives replication every 10 ms. '
        'Within a worker, conditions execute in baseline, delay, then recovery-stall order; each uses '
        'pooled, fresh, then burst mode and shares growing cluster state. '
        'Profile order alternates between trials. Background host activity is uncontrolled. '
        'Capacity, long-term stability, WAN consensus behavior, genuine packet-loss behavior and enterprise '
        'fleet throughput require separate deployments. The classical-only workers simulate a capability '
        'restriction using an explicit profile, not older TLS implementations. '
        'Session resumption is disabled by the existing transport. '
        'PQC coverage here concerns hybrid key establishment; certificate signatures remain classical.', '',
        '## Implications for enterprise deployment and the paper', '',
        '- Budget for new connections during bursts and recovery, and measure the tail latency of complete transactions. '
        'Compare pooled and fresh rows at the same concurrency. Burst rows have eight workers, so their throughput '
        'difference also includes concurrency.',
        '- A compatible majority can commit while an incompatible member is excluded, but a three-node cluster with '
        'only two compatible members loses progress when either fails. Rollout planning must preserve quorum '
        'connectivity through the intended failure budget.',
        '- TLS policy affects which RequestVote messages can arrive. The vote decision still follows Raft term, '
        'log freshness and voting rules, and the majority uses full membership. No PQC connection score elects a leader.',
        '- The network experiment illustrates sensitivity to delayed TLS flights and recovery stalls. Validate '
        'actual packet loss, geographic links, proxy compatibility and realistic reconnect rates before sizing a fleet.',
        '- These observations support a bounded evaluation in the paper. The tables report measurements from this '
        'host and workload, and the deployment implications identify conditions an enterprise should validate.', '']
    (output / 'REPORT.md').write_text('\n'.join(lines))


def coordinator(args):
    from tools.bootstrap_auth import bootstrap
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='raft-scenario-auth-') as directory:
        config = bootstrap(Path(directory) / 'credentials')
        env = dict(os.environ, RAFT_AUTH_CONFIG=str(config))
        env.pop('RAFT_PQC_EVIDENCE', None)
        for trial in range(1, args.trials + 1):
            for case in ([args.case] if args.case else ('connections', 'quorum', 'network')):
                profiles = ['policy'] if case == 'quorum' else ['classical', 'policy']
                if trial % 2 == 0:
                    profiles.reverse()
                for profile in profiles:
                    fragment = output / f'{case}-{profile}-{trial}.json'
                    print(f'trial {trial}/{args.trials} {case} {profile}', flush=True)
                    command = [sys.executable, '-m', 'security.launcher', '--profile', profile,
                        '-m', 'benchmarks.scenarios', '--worker', '--case', case, '--trial', str(trial),
                        '--samples', str(args.samples), '--fragment', str(fragment)]
                    completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=600)
                    if completed.returncode:
                        raise RuntimeError(completed.stdout + completed.stderr)
    write_report(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='benchmarks/scenario-results')
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--samples', type=int, default=60)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--case', choices=('connections', 'quorum', 'network'))
    parser.add_argument('--trial', type=int, default=1)
    parser.add_argument('--fragment')
    args = parser.parse_args()
    if args.samples < 1 or args.trials < 1:
        parser.error('samples and trials must be positive')
    worker(args) if args.worker else coordinator(args)


if __name__ == '__main__':
    main()
