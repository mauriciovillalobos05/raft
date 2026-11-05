# Focused PQC scenario results

Measured on 2026-11-04. Trial IDs 1, 2, 3. Transactions per mode per trial 60. Each transaction writes 1,024 bytes, waits for majority commit, then verifies a read from the leader. Burst mode uses eight workers. Pooled and fresh modes use one worker.

Reproduce with `raft-venv/bin/python -m benchmarks.scenarios --trials 3 --samples 60`.

Only the connection, mixed-capability quorum, and emulated network scenarios were run. Each worker starts through `security.launcher` using temporary credentials and isolated cluster state.

## Runtime

{"python": "3.14.4 (main, Apr  7 2026, 13:13:20) [Clang 21.0.0 (clang-2100.0.123.102)]", "openssl": "OpenSSL 3.6.3 9 Jun 2026", "platform": "macOS-26.6.2-arm64-arm-64bit-Mach-O"}

## Connection and network experiments

Latency is the full write/commit/read transaction, including connection setup for fresh and burst modes. The initial pooled connection is established before timing. Each table cell is the median of the available trial-level metrics. Tail percentiles have only 60 samples per trial in this run and are exploratory.

| Case | Profile | Condition | Mode | Transactions/s | p50 ms | p95 ms | p99 ms | CPU s | Errors |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| connections | classical | direct | burst | 48.235 | 161.231 | 166.533 | 182.710 | 1.266 | 0 |
| connections | classical | direct | fresh | 25.766 | 38.335 | 40.265 | 43.485 | 1.832 | 0 |
| connections | classical | direct | pooled | 25.409 | 38.895 | 42.797 | 45.489 | 1.585 | 0 |
| connections | policy | direct | burst | 47.830 | 159.983 | 165.774 | 190.114 | 1.309 | 0 |
| connections | policy | direct | fresh | 25.663 | 38.604 | 40.776 | 44.006 | 1.900 | 0 |
| connections | policy | direct | pooled | 25.203 | 39.793 | 42.612 | 45.017 | 1.645 | 0 |
| network | classical | delay-10ms | burst | 24.216 | 277.178 | 354.704 | 403.357 | 2.233 | 0 |
| network | classical | delay-10ms | fresh | 3.274 | 281.018 | 295.207 | 347.365 | 11.665 | 0 |
| network | classical | delay-10ms | pooled | 7.288 | 135.479 | 147.510 | 167.529 | 5.130 | 0 |
| network | classical | delay-10ms-loss-stalls-1pct | burst | 20.456 | 283.268 | 485.320 | 625.780 | 2.503 | 0 |
| network | classical | delay-10ms-loss-stalls-1pct | fresh | 2.778 | 284.111 | 486.093 | 573.178 | 13.681 | 0 |
| network | classical | delay-10ms-loss-stalls-1pct | pooled | 6.087 | 137.434 | 327.386 | 337.166 | 6.298 | 0 |
| network | classical | relay-baseline | burst | 47.355 | 162.221 | 168.431 | 193.836 | 1.377 | 0 |
| network | classical | relay-baseline | fresh | 25.255 | 39.337 | 41.528 | 43.409 | 1.968 | 0 |
| network | classical | relay-baseline | pooled | 25.590 | 39.157 | 41.803 | 44.245 | 1.598 | 0 |
| network | policy | delay-10ms | burst | 23.717 | 283.826 | 376.914 | 429.099 | 2.261 | 0 |
| network | policy | delay-10ms | fresh | 3.194 | 286.965 | 302.988 | 306.578 | 12.130 | 0 |
| network | policy | delay-10ms | pooled | 7.263 | 136.891 | 142.389 | 167.551 | 5.290 | 0 |
| network | policy | delay-10ms-loss-stalls-1pct | burst | 19.708 | 289.748 | 505.797 | 674.951 | 2.628 | 0 |
| network | policy | delay-10ms-loss-stalls-1pct | fresh | 2.709 | 289.039 | 496.211 | 587.153 | 14.227 | 0 |
| network | policy | delay-10ms-loss-stalls-1pct | pooled | 6.023 | 137.783 | 331.504 | 350.552 | 6.336 | 0 |
| network | policy | relay-baseline | burst | 47.183 | 162.403 | 167.431 | 197.995 | 1.430 | 0 |
| network | policy | relay-baseline | fresh | 25.163 | 39.595 | 42.111 | 43.888 | 2.027 | 0 |
| network | policy | relay-baseline | pooled | 25.212 | 39.287 | 41.943 | 45.558 | 1.654 | 0 |

The connection and network runs completed 4,320 transactions (8,640 KV operations) with 0 workload errors. Quorum writes are counted separately below.

With the emulated delay, fresh-connection median transaction latency was 281.02 ms for classical TLS and 286.97 ms for hybrid-required TLS. The hybrid pooled median was 136.89 ms. With recovery stalls, the hybrid fresh p99 was 587.15 ms. These measurements associate connection reuse with lower transaction setup cost under this model. The small sample and host scheduling do not establish statistical significance of profile differences.


## TLS observations

| Profile | Client handshakes | Median TLS ms | Mean TLS record bytes | HelloRetryRequests | Groups |
| --- | ---: | ---: | ---: | ---: | --- |
| classical | 363 | 2.673 | 4613.0 | 0 | X25519 |
| policy | 363 | 2.900 | 6923.0 | 0 | X25519MLKEM768 |

## Mixed-capability quorum

Membership remains three and majority remains two. Hybrid-capable nodes use the strict policy profile. Other nodes run the existing node worker in a separate classical-only comparison process. Those comparison peers permit classical connections to each other. The one-hybrid-node case tests whether strict candidate A can win; it does not establish that a separate classical majority can never elect its own leader. The candidate A invokes the normal RequestVote path explicitly. After an initial commit, A is stopped and B invokes RequestVote when B is hybrid-capable. Recovery requires another majority commit. These are controlled election attempts, not measurements of randomized failure detection. A failed attempt duration is not time to recovery.

| Hybrid nodes | Trials passed | Initial election/commit | Recovery and new commit after A fails | Median election attempt ms | Rejected connections |
| ---: | ---: | --- | --- | ---: | ---: |
| 3 | 3/3 | 3/3 | 3/3 | 17.451 | 0 |
| 2 | 3/3 | 3/3 | 0/3 | 22.264 | 18 |
| 1 | 3/3 | 0/3 | Not attempted; no initial hybrid leader | 6.805 | 6 |

## Network model and limitations

An opaque TCP relay forwards up to 1,460 bytes per read without terminating TLS. Conditions are a relay baseline, 10 ms delay per forwarded chunk in each direction, and that delay plus a seeded 1% probability of a 200 ms recovery stall per chunk. The timed workloads sampled 253 recovery stalls. Seeds equal trial numbers. Thread scheduling and TCP read boundaries can change random draw assignment across runs. This models delayed delivery and loss recovery. It does not drop IP packets, implement TCP congestion control, or establish performance under actual 1% packet loss. The nominal 20 ms round trip applies to one chunk in each direction. Larger TLS flights may incur several sequential chunk delays. Compare impaired rows with the relay baseline. Only client-to-A traffic traverses the relay. Raft replication remains local. CPU includes relay and cluster threads in the worker process.

Three nodes share one macOS host. The harness drives replication every 10 ms. Within a worker, conditions execute in baseline, delay, then recovery-stall order; each uses pooled, fresh, then burst mode and shares growing cluster state. Profile order alternates between trials. Background host activity is uncontrolled. Capacity, long-term stability, WAN consensus behavior, genuine packet-loss behavior and enterprise fleet throughput require separate deployments. The classical-only workers simulate a capability restriction using an explicit profile, not older TLS implementations. Session resumption is disabled by the existing transport. PQC coverage here concerns hybrid key establishment; certificate signatures remain classical.

## Implications for enterprise deployment and the paper

- Budget for new connections during bursts and recovery, and measure the tail latency of complete transactions. Compare pooled and fresh rows at the same concurrency. Burst rows have eight workers, so their throughput difference also includes concurrency.
- A compatible majority can commit while an incompatible member is excluded, but a three-node cluster with only two compatible members loses progress when either fails. Rollout planning must preserve quorum connectivity through the intended failure budget.
- TLS policy affects which RequestVote messages can arrive. The vote decision still follows Raft term, log freshness and voting rules, and the majority uses full membership. No PQC connection score elects a leader.
- The network experiment illustrates sensitivity to delayed TLS flights and recovery stalls. Validate actual packet loss, geographic links, proxy compatibility and realistic reconnect rates before sizing a fleet.
- These observations support a bounded evaluation in the paper. The tables report measurements from this host and workload, and the deployment implications identify conditions an enterprise should validate.
