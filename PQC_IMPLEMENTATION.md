# PQC implementation and verification

This implements the data-flow policy in `PQC_PLAN.md`.

The default `policy` profile requires hybrid key exchange for every value-bearing
RPC class. Post-quantum protection applies to key establishment, **not certificate
authentication**, browser traffic, or stored data.

## What carries values, and how it is protected

| Class | Actual use in this repository | Default requirement |
| --- | --- | --- |
| `node-peer` | Votes and AppendEntries/heartbeats share a listener and can carry replicated commands | Hybrid required |
| `gateway-node` | HTTP gateway uses a client certificate and real RPC sockets for KV operations and leader discovery | Hybrid required |
| `client-node` | Direct KVClient reads, scans, writes, deletes, and leader discovery | Hybrid required |
| `log-access` | Reserved policy class; no remote read_log or raw log submission endpoint exists | Hybrid required if ever implemented |
| `browser-https` | HTTP KV API, browser UI assets, and WSS telemetry | Classical X25519, explicit v1 exception |
| `telemetry` | Metadata policy class; current telemetry is produced in process and delivered through browser WSS/HTTPS, not a separate RPC service | Hybrid preferred if an RPC service is added |

Inspection resolved the plan's unverified assumptions:

- Followers return NOT_LEADER; KVClient discovers/retries against the leader.
  Followers do not forward client commands.
- Node and client methods share an RPC listener. The accepted class is inferred
  from the **verified certificate identity**, never from the requested RPC method
  or a caller-supplied weaker label. Node-only messages inherit the strict
  `node-peer` policy because the same class also replicates values.
- The gateway makes socket connections to nodes, even in the combined launcher.
  Internal telemetry production is an in-process operation, not another network hop.
- The authentication baseline already removed remote log access and stripped
  commands, keys, fields and values from dashboard events and initial snapshots.

## Code map

| File | Responsibility |
| --- | --- |
| `security/transport-policy.toml` | Complete class/listener inventory; refuses missing, unknown, or weakened value-class classifications |
| `security/openssl/hybrid.cnf` | TLS 1.3, explicit hybrid-first and classical key shares, group-priority tuples |
| `security/openssl/classical.cnf` | TLS 1.3, X25519-only comparison profile |
| `security/launcher.py` | Select profile/policy, set OpenSSL configuration, exec a fresh Python process before TLS imports |
| `security/transport.py` | Runtime/capability checks, TLS context settings, ServerHello parser, handshake byte accounting, class enforcement, paired evidence agreement, counters and optional audit files |
| `security/browser.py` | Record server-observed HTTPS/WSS negotiation before processing HTTP, without mistaking a TLS peer for a signed-in user |
| `security/auth.py` | Existing CA/fingerprint/role authentication plus measured transport enforcement on both dialing and accepting sides |
| `security/claims.py` | Conservative membership- and window-scoped path claims; flags missing hops, anomalies and incomplete evidence |
| `security/diagnostic.py` | Show configured requirements, exact runtime, local negotiated capability and optional actual peer observations |
| `tools/pqc_report.py` | Build a claim report from metadata-only audit files from participating processes |
| `raft/raft_server.py`, `inmem/kv_client.py` | Explicitly label outbound node and KV connections; public operations and consensus logic are unchanged |
| `websocket_server.py` | Separate classical browser context; aggregate transport counts in authenticated `/cluster/status` |
| `benchmarks/cluster.py`, `benchmarks/run.py` | Isolated real three-node benchmark harness, raw samples, CSV and comparison report |
| `pqc_tests/test_pqc.py`, `tools/run_pqc_tests.py` | Negotiation/policy/claim/mixed-cluster tests and all-profile test runner |

## New execution flow

1. Supported application entry points automatically re-exec through the launcher
   before importing TLS libraries. Direct client programs use the launcher
   explicitly. The profile and OpenSSL configuration must agree; bypassed setup
   fails before a listener or RPC connection starts.
2. Startup verifies the tested CPython 3.14 / OpenSSL 3.6 runtime and TLS callback
   hook. A fresh MemoryBIO handshake proves that the actual local library can
   negotiate the expected group. This is an in-memory algorithm probe, not a
   network connection; its disabled certificate validation is confined to the
   probe. Real connections retain CA, hostname, certificate fingerprint, role,
   and node-ID checks.
3. A real RPC TLS handshake uses the configured group list. The callback parses
   the final ServerHello key-share extension, ignores HelloRetryRequest as final
   evidence, and records the actual group and TLS version. Cipher-suite names
   are recorded separately and are never treated as proof of PQC.
4. After certificate verification, the receiver derives `node-peer`,
   `gateway-node`, or `client-node` from the peer's identity. The dialer derives
   the same class locally and refuses inconsistent explicit labels.
5. Both ends enforce the class before RPyC starts. TLS must be 1.3 with recognized
   negotiation evidence. A required class rejects X25519; preferred classes may
   accept it, emit a warning and increment fallback counts. Comparison profiles
   are explicit overrides and cannot earn strict value-path claims.
6. A bounded, length-prefixed metadata exchange inside the authenticated TLS
   connection compares both sides' group, cipher, version, identity, class and
   connection ID. A final acknowledgment completes agreement. Disagreement is
   counted as an anomaly and closes the connection before application RPC.
7. Only then is the socket handed to RPyC. Existing authorization, JSON payloads,
   dedicated KV methods and Raft handlers run as before.

The evidence preface is a **transport wire change**. Updated classical-only peers
can use the comparison/preferred profiles, but old bare TLS/RPyC clients must be
updated even though RPC method names and payload schemas are unchanged.

### Runtime constraints

Python 3.14's public curve setter does not accept `X25519MLKEM768`. Therefore the
launcher sets the OpenSSL offered-group list before Python starts. The default
and preferred profiles offer hybrid first and explicit classical support; the
required-class decision is enforced after negotiation on **both** endpoints.
A classical TLS handshake may complete, but a required class cannot send an
application command through it.

Each dialing connection has a configured context; the shared accepting listener
uses a compatible context and applies the identity-derived class before RPC.
The separate browser context explicitly selects X25519 and cannot modify RPC
contexts. Session tickets are disabled and no sessions are supplied for reuse.
The CPython `_msg_callback` hook is a private, pinned dependency: unsupported
runtimes or missing/malformed evidence fail closed rather than claiming PQC.

## Evidence and claims

Accepted RPC connections record class, direction, local and peer identity, group,
TLS version, cipher, requirement, profile, agreement status and timestamp. The
supported groups are exactly X25519MLKEM768 and X25519; unknown groups are rejected.
The connection ID is a SHA-256 hash of the final ServerHello random, allowing
correlation without storing key material. Full-path claims require actual paired
dialed and accepted records, including matching identities, groups and ciphers;
one-sided audit files produce partial claims. TLS record byte counts stop before
the application/evidence exchange. Browser connections are also recorded after TLS completes and before HTTP data
is processed. Their peer identity is explicitly unauthenticated at the TLS stage;
Basic/session authentication happens later. These observations are server-only,
classical evidence and never count as paired hybrid proof. No certificate private
keys, passwords, KV contents, commands or decrypted application traffic are recorded.

`/cluster/status` exposes only aggregate counts by class/outcome. Full metadata
can optionally be written to a process-specific audit file with
`RAFT_PQC_EVIDENCE=/private/path/evidence-{pid}.jsonl`. Counters are endpoint observations, so a locally observed connection has both a
dialed and an accepted record. The in-memory buffer is
bounded; overflow is reported. Callers must mark incomplete windows, and the
benchmark does so automatically, preventing claims from silently using truncated
evidence.

Claim reports require a declared membership and explicit measured window. For a
complete direct-client claim, evidence must cover that client's connections to
all configured nodes and all directed node-peer edges. This intentionally
conservative topology check prevents an isolated or unobserved member from
being omitted. The benchmark explicitly probes the topology within each window.

- `hybrid-verified`: every required hop has agreed hybrid evidence, its class was
  hybrid-required, and there are no relevant rejections, anomalies or missing hops.
- `partial`: a known hop is classical, unobserved, nonrequired, rejected, or has
  conflicting/incomplete evidence; the report names it.
- `not-evaluated`: the path has no relevant observations (for example, disabled
  remote log access).

HTTP value paths are always partial in v1 because `browser-https` is classical,
even when every RPC segment is verified hybrid. Hybrid-preferred comparison runs
also remain partial for value paths: preferring hybrid is not a requirement.
Every claim includes exclusions for classical authentication, browser transport
and stored data.

## Running it

The existing private credential setup remains in `AUTHENTICATION.md`. The exact
runtime used for verification is recorded in the results below.

```bash
source raft-venv/bin/activate
export RAFT_AUTH_CONFIG=/private/tmp/raft-dev-auth/auth.json
python -m security.launcher --diagnostic
python -m security.launcher --profile policy -m start_cluster
# python start_cluster.py also re-execs through the default policy launcher.
```

Direct clients and actual peer diagnostics:

```bash
python -m security.launcher --profile policy my_client.py
python -m security.launcher --diagnostic --identity direct-client --peer A:127.0.0.1:5001
```

Override the policy-file location with `--policy /absolute/path/policy.toml`.
The policy file must still classify all known classes and retain required
protection for value classes. Deliberate comparison overrides use
`--profile hybrid-preferred` or `--profile classical` and print a warning.

Reproduce tests and measurements:

```bash
python -m tools.run_pqc_tests
python -m benchmarks.run --output benchmarks/results
```

Build offline claims from collected observations, using Unix timestamps for
optional `--start` and `--end` boundaries:

```bash
python -m tools.pqc_report --nodes A,B,C --evidence /private/path/evidence-*.jsonl
```

## Verification results

Verified on **2026-10-31** using CPython **3.14.4** and **OpenSSL 3.6.3** on
macOS arm64. Application libraries: FastAPI 0.142.2, Uvicorn 0.54.0, RPyC
6.0.2, and h11 0.16.0.

| Profile | Authentication tests passed | PQC tests passed | Expected skips |
| --- | ---: | ---: | ---: |
| policy | 26 | 24 | 0 |
| hybrid-preferred | 26 | 21 | 3 |
| classical | 26 | 19 | 5 |

**142 passed, 8 intentionally skipped, zero failures/errors.** Every one of the
50 unique cases runs under the default policy. Skips are strict-rejection or
isolation cases that do not apply to permissive comparison profiles, and
hybrid-specific cases that do not apply to the classical profile. The final
HTTP regression checks also verify that real HTTPS observations record X25519
under every profile. Frontend lint/build, Python compilation, and diff checks pass.

The full benchmark completed **15 configuration trials, 1,500 new connections,
30 timed workloads, 35,807 committed write/read transactions and 71,614 KV
operations**, without workload errors, fallback, anomalies, required-class
rejections or dropped evidence.

| Profile | TLS handshake median ms | Mean TLS record bytes | KV ops/s, concurrency 1 | KV ops/s, concurrency 8 |
| --- | ---: | ---: | ---: | ---: |
| classical | 1.468 | 4,613 | 54.00 | 105.24 |
| hybrid-preferred | 1.589 | 6,923 | 53.56 | 105.12 |
| policy | 1.561 | 6,923 | 53.69 | 104.06 |

These are local measurements, not a claim of statistically significant deployment
performance differences. Full percentile, CPU, election, commit-latency and
per-trial data are in the benchmark report. Policy runs report direct KV paths
as `hybrid-verified`; HTTP paths remain `partial`. Classical and preferred
comparison runs report value paths as `partial`.

The full test matrix and benchmark results are recorded alongside this file:

- `benchmarks/test-results/results.json`: per-profile suite outcomes.
- `benchmarks/results/REPORT.md`: measured comparative summary.
- `benchmarks/results/raw.csv`: one row per trial and concurrency.
- `benchmarks/results/handshakes.csv`, `latencies.csv`: individual measured samples.
- `benchmarks/results/<profile>-<trial>.json`: individual handshake and workload
  samples, CPU, negotiation counts and window-scoped path reports.

The test matrix includes real OpenSSL clients and servers, malformed/unknown
ServerHello evidence, class downgrade rejection on both sides, preferred
fallback warnings/counts, identity-derived classification, TLS 1.2 rejection,
classical browser isolation, and a real classical-only node with repeated
randomized election timeouts. The mixed cluster retains A/B quorum, rejects C
before consensus dispatch, and reports the member-inclusive path as partial.

Benchmark methodology: five trials per profile; 100 new connections per trial;
1 KiB values; concurrency 1 and 8; five-second warmup and 30-second measurement.
Each transaction writes, waits for majority commit, and reads the value back.
Two KV operations are counted per successful transaction. All profiles use the
same replication driver invoking existing handlers every 10 ms; this is a
benchmark setting, not a production timer or consensus change. Three nodes and
the load generator run on the same host in one process, so CPU is whole-process
CPU, and measurements are local comparisons rather than deployment predictions.

## Rollout and remaining boundaries

Upgrade runtimes and use the diagnostic on every participating process. Deploy
updated peers with `hybrid-preferred`, collect paired observations with no
fallbacks/anomalies, then coordinate a restart into `policy`. Do not switch a
partial cluster silently. Two incapable nodes in a three-node cluster lose
quorum under required policy; the implementation never automatically downgrades
to recover availability.

Policy epochs, replicated policy changes, automatic catch-up transitions and an
audited emergency downgrade workflow remain separate consensus/operations work.
Browser PQC, ML-DSA signatures and encryption at rest are not implemented. A
valid classical certificate remains necessary even on a hybrid connection.

## Technical references

- [OpenSSL 3.6 configuration](https://docs.openssl.org/3.6/man5/config/): process initialization and system-default TLS settings.
- [OpenSSL group configuration](https://docs.openssl.org/3.6/man3/SSL_CTX_set1_curves/): hybrid groups, predicted key shares and group-priority tuples.
- [CPython 3.14 TLS implementation](https://github.com/python/cpython/blob/3.14/Modules/_ssl.c): the pinned callback and curve-setter implementation.
