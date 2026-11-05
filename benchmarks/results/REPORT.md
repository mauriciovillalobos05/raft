# PQC benchmark results

Measured with real three-node Raft RPC and separate TLS contexts.

Each transaction writes a 1 KiB value, waits for majority commit, then reads it back. Both KV operations are counted.
Replication is driven every 10 ms for all profiles; production timers and consensus code are unchanged.
CPU is whole-process CPU (three nodes plus load generator). TLS record bytes exclude TCP/IP and the evidence preface.

| Profile | Concurrency | Trials | KV ops/s (mean) | Transaction p50 ms (mean) | p95 ms (mean) | p99 ms (mean) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| classical | 1 | 5 | 54.00 | 36.99 | 39.14 | 41.76 |
| classical | 8 | 5 | 105.24 | 150.74 | 165.09 | 196.87 |
| hybrid-preferred | 1 | 5 | 53.56 | 37.27 | 39.47 | 42.92 |
| hybrid-preferred | 8 | 5 | 105.12 | 151.31 | 166.28 | 189.84 |
| policy | 1 | 5 | 53.69 | 37.13 | 39.24 | 42.72 |
| policy | 8 | 5 | 104.06 | 151.09 | 176.08 | 203.78 |

| Profile | Connection-ready p50 ms | TLS handshake p50 ms | Mean process CPU ms/connection | Mean TLS record bytes/connection | Election ms (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| classical | 2.029 | 1.468 | 2.008 | 4613 | 9.464 |
| hybrid-preferred | 2.158 | 1.589 | 2.110 | 6923 | 9.482 |
| policy | 2.123 | 1.561 | 2.065 | 6923 | 9.558 |

Counters below are endpoint observations (dialed and accepted sides), not unique connections.

| Profile | Accepted observations | Fallback observations | Required-class rejections | Anomalies | Failed transactions |
| --- | ---: | ---: | ---: | ---: | ---: |
| classical | 76174 | 0 | 0 | 0 | 0 |
| hybrid-preferred | 75734 | 0 | 0 | 0 | 0 |
| policy | 75570 | 0 | 0 | 0 | 0 |

| Profile | Direct-path claim statuses | HTTP-path claim statuses |
| --- | --- | --- |
| classical | partial | partial |
| hybrid-preferred | partial | partial |
| policy | hybrid-verified | partial |

Runtime: `{"python": "3.14.4", "openssl": "OpenSSL 3.6.3 9 Jun 2026", "platform": "macOS-26.6.2-arm64-arm-64bit-Mach-O"}`.

Raw per-trial JSON contains every latency sample, counters, requirements and window-scoped claim reports. See raw.csv for the trial table.
Classical and hybrid-preferred profiles cannot earn hybrid-verified value-path claims: those classes were not hybrid-required.
Policy claims additionally require matched hybrid evidence across the full configured topology; HTTP paths remain partial due to the browser exception.
Exclusions: classical certificate authentication, browser HTTPS/WSS, and stored data. These measurements do not establish post-quantum authentication.
