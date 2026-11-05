"""TLS negotiation, policy, path claims and mixed-capability Raft tests."""
import copy
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools.bootstrap_auth import bootstrap
from security.auth import get_auth, AuthConfig, Principal
from security.transport import (Policy, get_policy, EVIDENCE, HandshakeTrace, parse_server_hello,
    observe_socket, configure_context, enforce, agree, TransportError, HYBRID, CLASSICAL, HRR_RANDOM)
from security.claims import report


def hello(group=0x11EC, retry=False):
    share = struct.pack('!H', group) if retry else struct.pack('!HH', group, 4) + b'KEY!'
    extensions = b'\x00\x2b\x00\x02\x03\x04' + struct.pack('!HH', 51, len(share)) + share
    body = b'\x03\x03' + (HRR_RANDOM if retry else b'R' * 32) + b'\x00\x13\x02\x00' + struct.pack('!H', len(extensions)) + extensions
    return b'\x02' + len(body).to_bytes(3, 'big') + body


class ParserAndClaimsTests(unittest.TestCase):
    def test_01_final_group_and_hrr(self):
        trace = HandshakeTrace()
        trace.observe('read', 22, 2, hello(retry=True))
        self.assertIsNone(trace.group)
        self.assertEqual(trace.hello_retries, 1)
        trace.observe('read', 22, 2, hello())
        self.assertEqual(trace.group, HYBRID)
        self.assertIsNotNone(trace.connection_id)
        self.assertEqual(parse_server_hello(hello(0x1d))[0], CLASSICAL)

    def test_02_malformed_or_unknown_evidence(self):
        for data in (b'', hello()[:-1], hello(0x1234), b'\x01' + hello()[1:], hello() + b'x'):
            with self.subTest(data=data[:5]):
                with self.assertRaises(ValueError):
                    parse_server_hello(data)
        trace = HandshakeTrace()
        trace.observe('read', 22, 2, hello()[:-1])
        self.assertIsNotNone(trace.error)

    def test_03_policy_classes(self):
        policy = Policy(profile='policy')
        for name in ('node-peer', 'gateway-node', 'client-node', 'log-access'):
            self.assertEqual(policy.requirement(name), 'hybrid-required')
        self.assertEqual(policy.requirement('telemetry'), 'hybrid-preferred')
        self.assertEqual(policy.requirement('browser-https'), 'classical')
        with self.assertRaises(TransportError):
            policy.requirement('unknown')
        self.assertEqual(policy.classify(Principal('kv-gateway', 'client'), 'kv-gateway'), 'gateway-node')
        self.assertEqual(policy.classify(Principal('external', 'client'), 'kv-gateway'), 'client-node')
        with self.assertRaises(TransportError):
            policy.classify(Principal('viewer', 'ui'), 'kv-gateway')

    def test_04_policy_refuses_unclassified_or_weakened_classes(self):
        original = Path('security/transport-policy.toml').resolve().read_text()
        for changed in (original.replace('node-peer = "hybrid-required"', 'node-peer = "hybrid-preferred"'),
                        original.replace('telemetry = "hybrid-preferred"', ''), original + '\nunknown = ["node-peer"]\n'):
            with tempfile.NamedTemporaryFile('w', suffix='.toml') as f:
                f.write(changed)
                f.flush()
                with self.assertRaises(ValueError):
                    Policy(f.name)

    def evidence(self):
        records = []
        edges = [('node-peer', a, b) for a in 'ABC' for b in 'ABC' if a != b]
        edges += [('client-node', 'direct-client', n) for n in 'ABC']
        edges += [('gateway-node', 'kv-gateway', n) for n in 'ABC']
        for i, (kind, a, b) in enumerate(edges):
            for direction, local, peer in [('dialed', a, b), ('accepted', b, a)]:
                records.append({'connection_id': str(i), 'class': kind, 'direction': direction,
                    'local_identity': local, 'peer_identity': peer, 'tls_version': 'TLSv1.3',
                    'key_exchange_group': HYBRID, 'protection': 'hybrid', 'outcome': 'accepted',
                    'peer_agreed': True, 'requirement': 'hybrid-required', 'timestamp': 100})
        return records

    def test_05_complete_path_and_http_exception(self):
        result = report(self.evidence(), list('ABC'), window_start=90, window_end=110)
        self.assertEqual(result['claims']['direct-kv']['status'], 'hybrid-verified')
        self.assertEqual(result['claims']['http-kv']['status'], 'partial')
        self.assertIn('browser-https', str(result['claims']['http-kv']['reasons']))
        self.assertEqual(result['claims']['restricted-logs']['status'], 'not-evaluated')
        self.assertTrue(all(c['exclusions'] for c in result['claims'].values()))

    def test_06_injected_classical_hop(self):
        records = self.evidence()
        records[0].update(key_exchange_group=CLASSICAL, protection='classical', outcome='required-class-rejection')
        result = report(records, list('ABC'), window_start=90, window_end=110)
        self.assertEqual(result['claims']['direct-kv']['status'], 'partial')
        self.assertTrue(result['anomalies'])
        self.assertIn('node-peer', str(result['claims']['direct-kv']['reasons']))

    def test_07_missing_window_or_membership_is_not_verified(self):
        self.assertEqual(report([], list('ABC'))['claims']['direct-kv']['status'], 'not-evaluated')
        records = self.evidence()
        result = report(records, list('ABCD'), window_start=90, window_end=110)
        self.assertEqual(result['claims']['direct-kv']['status'], 'partial')
        self.assertIn('D', str(result['claims']['direct-kv']['reasons']))
        result = report(records, list('ABC'), window_start=90, window_end=110, evidence_complete=False)
        self.assertEqual(result['claims']['direct-kv']['status'], 'partial')
        self.assertEqual(report(records, list('ABC'), window_start=101)['claims']['direct-kv']['status'], 'not-evaluated')

    def test_08_nonrequired_hybrid_does_not_earn_claim(self):
        records = self.evidence()
        for r in records:
            r['requirement'] = 'hybrid-preferred'
        self.assertEqual(report(records, list('ABC'), window_start=90, window_end=110)['claims']['direct-kv']['status'], 'partial')

    def test_09_one_sided_or_identity_mismatch_is_not_verified(self):
        records = self.evidence()
        one_side = [r for r in records if r['direction'] == 'dialed']
        self.assertEqual(report(one_side, list('ABC'), window_start=90, window_end=110)['claims']['direct-kv']['status'], 'partial')
        records[1]['local_identity'] = 'IMPOSTOR'
        result = report(records, list('ABC'), window_start=90, window_end=110)
        self.assertTrue(result['anomalies'])
        self.assertEqual(result['claims']['direct-kv']['status'], 'partial')

    def test_10_unclassified_claim_and_empty_membership(self):
        records = self.evidence()
        records.append(dict(records[0], **{'class': 'unclassified'}))
        self.assertEqual(report(records, list('ABC'), window_start=90, window_end=110)['claims']['direct-kv']['status'], 'not-evaluated')
        with self.assertRaises(ValueError):
            report(self.evidence(), [])


class TransportIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='raft-pqc-tests-')
        cls.old_config = os.environ.get('RAFT_AUTH_CONFIG')
        cls.auth_path = bootstrap(Path(cls.temp.name) / 'auth')
        os.environ['RAFT_AUTH_CONFIG'] = str(cls.auth_path)
        get_auth.cache_clear()
        cls.auth = get_auth()
        cls.auth.check_capability('A')

    @classmethod
    def tearDownClass(cls):
        get_auth.cache_clear()
        if cls.old_config is None:
            os.environ.pop('RAFT_AUTH_CONFIG', None)
        else:
            os.environ['RAFT_AUTH_CONFIG'] = cls.old_config
        cls.temp.cleanup()

    def contexts(self, server_group=None, client_group=None, kind='node-peer'):
        server = self.auth.server_context('A')
        configure_context(server, kind)
        client = ssl.create_default_context(cafile=self.auth.path('ca.crt'))
        client.load_cert_chain(self.auth.path('B.crt'), self.auth.path('B.key'))
        configure_context(client, kind)
        if server_group:
            server.set_ecdh_curve(server_group)
        if client_group:
            client.set_ecdh_curve(client_group)
        return server, client

    def memory_handshake(self, server, client):
        si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
        s = server.wrap_bio(si, so, server_side=True)
        c = client.wrap_bio(ci, co, server_hostname='localhost')
        done = set()
        for _ in range(30):
            for name, conn in [('s', s), ('c', c)]:
                if name not in done:
                    try:
                        conn.do_handshake()
                        done.add(name)
                    except ssl.SSLWantReadError:
                        pass
            if co.pending:
                si.write(co.read())
            if so.pending:
                ci.write(so.read())
            if len(done) == 2:
                return s, c
        self.fail('Handshake did not complete')

    def test_01_each_class_measures_actual_group(self):
        for kind in get_policy().classes:
            with self.subTest(kind=kind):
                s, c = self.memory_handshake(*self.contexts(kind=kind))
                record = observe_socket(c, kind, 'dialed', 'B', 'A')
                enforce(record)
                expected = CLASSICAL if kind == 'browser-https' or get_policy().profile == 'classical' else HYBRID
                self.assertEqual(record['key_exchange_group'], expected)
                self.assertEqual(record['tls_version'], 'TLSv1.3')
                self.assertFalse(c.session.has_ticket)
                self.assertFalse(c.session_reused)
                self.assertFalse(s.session_reused)
                self.assertGreater(record['tls_bytes_sent'], 0)

    def test_02_required_classical_rejected_both_sides(self):
        for kind in ('node-peer', 'gateway-node', 'client-node', 'log-access'):
            s, c = self.memory_handshake(*self.contexts(client_group=CLASSICAL, kind=kind))
            for connection, direction, local, peer in [(s, 'accepted', 'A', 'B'), (c, 'dialed', 'B', 'A')]:
                record = observe_socket(connection, kind, direction, local, peer)
                if get_policy().profile == 'policy':
                    with self.assertRaises(TransportError):
                        enforce(record)
                else:
                    enforce(record)

    def test_03_preferred_fallback_warns_and_counts(self):
        if get_policy().profile == 'classical':
            self.skipTest('Classical comparison has no hybrid-preferred classes')
        s, c = self.memory_handshake(*self.contexts(client_group=CLASSICAL, kind='telemetry'))
        dial = observe_socket(c, 'telemetry', 'dialed', 'B', 'A')
        accepted = observe_socket(s, 'telemetry', 'accepted', 'A', 'B')
        enforce(dial)
        enforce(accepted)
        # Use local socketpair to exercise the exact bounded agreement framing.
        a, b = socket.socketpair()
        errors = []
        def serve():
            try:
                agree(a, accepted, server=True)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        with self.assertLogs('raft.transport', level='WARNING'):
            thread.start()
            agree(b, dial)
            thread.join(3)
        a.close(); b.close()
        self.assertFalse(errors)
        self.assertTrue(any(r['outcome'] == 'fallback' and r['class'] == 'telemetry' for r in EVIDENCE.records))

    def test_04_reject_tls12_and_missing_callback(self):
        server, client = self.contexts()
        client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ssl.SSLError):
            self.memory_handshake(server, client)
        server, client = self.contexts()
        client._msg_callback = None
        _, c = self.memory_handshake(server, client)
        with self.assertRaises(TransportError):
            observe_socket(c, 'node-peer', 'dialed', 'B', 'A')

    def test_05_peer_observation_disagreement(self):
        from security.transport import _send, _receive
        s, c = self.memory_handshake(*self.contexts())
        record = observe_socket(c, 'node-peer', 'dialed', 'B', 'A')
        a, b = socket.socketpair()
        def lie():
            peer = _receive(a)
            peer.update(local_identity='A', peer_identity='B', key_exchange_group='WRONG')
            _send(a, peer)
        thread = threading.Thread(target=lie)
        thread.start()
        with self.assertRaises(TransportError):
            agree(b, record)
        thread.join(3)
        a.close(); b.close()
        self.assertTrue(any(r['outcome'] == 'anomaly' for r in EVIDENCE.records))

    def test_06_browser_does_not_weaken_rpc(self):
        browser, _ = self.contexts(kind='browser-https')
        self.assertEqual(self.memory_handshake(browser, self.contexts()[1])[1]._raft_trace.group, CLASSICAL)
        _, rpc = self.memory_handshake(*self.contexts())
        self.assertEqual(rpc._raft_trace.group, CLASSICAL if get_policy().profile == 'classical' else HYBRID)

    def test_07_independent_openssl_client(self):
        context = self.auth.server_context('A')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen()
        group = CLASSICAL if get_policy().profile == 'classical' else HYBRID
        observations, errors = [], []
        def accept():
            try:
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as tls:
                    observations.append(observe_socket(tls, 'node-peer', 'accepted', 'A', 'B'))
                    tls.recv(1)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=accept)
        thread.start()
        command = ['openssl', 's_client', '-connect', f'127.0.0.1:{listener.getsockname()[1]}', '-tls1_3',
                   '-groups', group, '-CAfile', self.auth.path('ca.crt'), '-cert', self.auth.path('B.crt'),
                   '-key', self.auth.path('B.key'), '-verify_return_error', '-brief', '-no_ticket']
        result = subprocess.run(command, input='', capture_output=True, text=True, timeout=8)
        thread.join(5); listener.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(errors)
        self.assertIn(group, result.stderr + result.stdout)
        self.assertEqual(observations[0]['key_exchange_group'], group)

    def test_07b_real_hello_retry_request(self):
        if get_policy().profile == 'classical':
            self.skipTest('Classical profile never requests a hybrid share')
        context = self.auth.server_context('A')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen()
        observations, errors = [], []
        def accept():
            try:
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as tls:
                    observations.append(observe_socket(tls, 'node-peer', 'accepted', 'A', 'B'))
                    tls.recv(1)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=accept)
        thread.start()
        command = ['openssl', 's_client', '-connect', f'127.0.0.1:{listener.getsockname()[1]}', '-tls1_3',
                   '-groups', 'X25519:X25519MLKEM768', '-CAfile', self.auth.path('ca.crt'),
                   '-cert', self.auth.path('B.crt'), '-key', self.auth.path('B.key'), '-brief', '-no_ticket']
        result = subprocess.run(command, input='', capture_output=True, text=True, timeout=8)
        thread.join(5); listener.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(errors)
        self.assertEqual(observations[0]['key_exchange_group'], HYBRID)
        self.assertEqual(observations[0]['hello_retries'], 1)

    def test_08_independent_openssl_server(self):
        group = CLASSICAL if get_policy().profile == 'classical' else HYBRID
        reserved = socket.socket(); reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]; reserved.close()
        command = ['openssl', 's_server', '-accept', f'127.0.0.1:{port}', '-tls1_3', '-groups', group,
                   '-cert', self.auth.path('A.crt'), '-key', self.auth.path('A.key'),
                   '-CAfile', self.auth.path('ca.crt'), '-Verify', '1', '-verify_return_error', '-naccept', '1', '-no_ticket']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            client = self.contexts()[1]
            deadline = time.monotonic() + 5
            while True:
                try:
                    raw = socket.create_connection(('127.0.0.1', port), timeout=1)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline:
                        self.fail('OpenSSL server did not start')
                    time.sleep(.02)
            with client.wrap_socket(raw, server_hostname='localhost') as tls:
                record = observe_socket(tls, 'node-peer', 'dialed', 'B', 'A')
                self.assertEqual(record['key_exchange_group'], group)
                enforce(record)
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_09_no_unclassified_listener_or_spoofed_class(self):
        with self.assertRaises(TransportError):
            self.auth.authenticator('A', listener='unknown')
        with self.assertRaises(TransportError):
            self.auth.connect('127.0.0.1', 1, 'direct-client', 'A', transport_class='telemetry')

    def test_09b_classical_peers_rejected_by_real_rpc_listener(self):
        if get_policy().profile != 'policy':
            self.skipTest('Required-class listener rejection applies to policy')
        from benchmarks.cluster import Cluster
        EVIDENCE.reset()
        with Cluster() as cluster:
            for identity, kind in [('B', 'node-peer'), ('kv-gateway', 'gateway-node'), ('direct-client', 'client-node')]:
                context = ssl.create_default_context(cafile=self.auth.path('ca.crt'))
                context.load_cert_chain(self.auth.path(identity + '.crt'), self.auth.path(identity + '.key'))
                configure_context(context, kind)
                context.set_ecdh_curve(CLASSICAL)
                raw = socket.create_connection(('127.0.0.1', cluster.config['A']['port']), timeout=3)
                with context.wrap_socket(raw, server_hostname='localhost') as tls:
                    # Simulate a caller ignoring its own required-class check.
                    # The accepting side must still close before RPyC dispatch.
                    try:
                        tls.sendall(b'not-allowed-to-reach-rpc')
                        self.assertEqual(tls.recv(1), b'')
                    except (ssl.SSLError, ConnectionResetError):
                        pass
            cluster.wait_for_evidence()
            for kind in ('node-peer', 'gateway-node', 'client-node'):
                self.assertTrue(any(r['class'] == kind and r['direction'] == 'accepted'
                                    and r['outcome'] == 'required-class-rejection' for r in EVIDENCE.records))
            self.assertEqual(cluster.nodes['A'].raft_terms.current_term, 0)
            self.assertEqual(cluster.nodes['A'].raft_terms.logs, [])

    def test_09c_dialer_rejects_classical_server_before_sending_rpc(self):
        if get_policy().profile != 'policy':
            self.skipTest('Required-class dialer rejection applies to policy')
        for identity in ('B', 'kv-gateway', 'direct-client'):
            context = self.auth.server_context('A')
            context.set_ecdh_curve(CLASSICAL)
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen()
            received, errors = [], []
            def accept():
                try:
                    raw, _ = listener.accept()
                    with context.wrap_socket(raw, server_side=True) as tls:
                        received.append(tls.recv(1))
                except (ssl.SSLEOFError, ConnectionResetError):
                    received.append(b'')
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=accept)
            thread.start()
            with self.assertRaises(TransportError):
                self.auth.connect('127.0.0.1', listener.getsockname()[1], identity, 'A')
            thread.join(5); listener.close()
            self.assertFalse(errors)
            self.assertEqual(received, [b''])

    def test_09d_diagnostic_forwards_identity_and_peer(self):
        from benchmarks.cluster import Cluster
        with Cluster() as cluster:
            peer = f"A:127.0.0.1:{cluster.config['A']['port']}"
            command = [sys.executable, '-m', 'security.launcher', '--profile', get_policy().profile,
                       '--diagnostic', '--identity', 'kv-gateway', '--peer', peer]
            result = subprocess.run(command, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data['profile'], get_policy().profile)
            observations = [r for r in data['observations'] if 'direction' in r]
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0]['class'], 'gateway-node')
            self.assertEqual(observations[0]['peer_identity'], 'A')
            expected = CLASSICAL if get_policy().profile == 'classical' else HYBRID
            self.assertEqual(observations[0]['key_exchange_group'], expected)

    def test_10_mixed_capability_cluster(self):
        if get_policy().profile != 'policy':
            self.skipTest('Isolation requirement applies to policy profile')
        from benchmarks.cluster import Cluster
        from inmem.kv_client import KVClient
        EVIDENCE.reset()
        with Cluster() as cluster:
            cluster.servers['C'].close()
            cluster.nodes['C'].kill()
            config_file = Path(cluster.temp.name) / 'cluster.json'
            config_file.write_text(json.dumps(cluster.config))
            state = Path(cluster.temp.name) / 'classical-C'; state.mkdir()
            status = state / 'status.json'
            command = [sys.executable, '-m', 'security.launcher', '--profile', 'classical', '-m', 'tools.pqc_node_worker',
                       '--node', 'C', '--cluster', str(config_file), '--state-directory', str(state), '--status', str(status)]
            with open(os.devnull, 'w') as quiet:
                process = subprocess.Popen(command, stdout=quiet, stderr=quiet)
            try:
                deadline = time.monotonic() + 5
                while not status.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        self.fail('Classical node did not start')
                    time.sleep(.03)
                cluster.elect('A')
                cluster.start_replication(interval=.1)
                client = KVClient(cluster.config, identity='direct-client')
                try:
                    response = client.set('mixed', 'field', 'secret', 100)
                    self.assertTrue(response['success'])
                    cluster.wait_commit(response['index'])
                    initial_term = cluster.nodes['A'].raft_terms.current_term
                    # Exercise C's actual randomized election timer at least twice.
                    deadline = time.monotonic() + 23
                    while json.loads(status.read_text())['term'] < 2 and time.monotonic() < deadline:
                        time.sleep(.1)
                    self.assertGreaterEqual(json.loads(status.read_text())['term'], 2)
                    self.assertEqual(cluster.nodes['A'].raft_terms.current_term, initial_term)
                    self.assertEqual(cluster.nodes['A'].raft_terms.state.name, 'leader')
                    self.assertTrue(cluster.nodes['B'].raft_terms.commit_index >= response['index'])
                    snapshot = report(EVIDENCE.records, list('ABC'))
                    self.assertEqual(snapshot['claims']['direct-kv']['status'], 'partial')
                    self.assertTrue(any(r['outcome'] == 'required-class-rejection' and r['peer_identity'] == 'C' for r in EVIDENCE.records))
                finally:
                    client.close()
            finally:
                process.terminate(); process.wait(timeout=12)


if __name__ == '__main__':
    unittest.main()
