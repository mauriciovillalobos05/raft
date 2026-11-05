# Hybrid PQC transport for the pqc branch (data-flow-driven)

## Summary

This version decides which connections must be hybrid by following where sensitive data travels, instead of applying one global profile. It builds on the authentication baseline from `classic-cryptography`, as the original plan did.

Three changes from the original plan:

- **Data-flow classification comes first.** Every connection class is labeled by what it carries: values, metadata or control. Those labels set its requirement.
- **Per-class requirements replace the single profile.** Classes that can carry a KV value, a raw command or a log entry are `hybrid-required`. The rest stay `hybrid-preferred`.
- **Claims follow the path.** "This value is hybrid-protected" is stated only when every hop on its path was hybrid-required and observed hybrid.

Certificate authentication stays classical, and so does the browser HTTPS/WSS link in v1, as an explicit exception. This version adds no post-quantum signatures, no storage encryption and no change to consensus.

## Data-flow classification

Every connection a KV value crosses is `hybrid-required` except the HTTPS/WSS link from HTTP clients, which stays classical in v1.

&#91;embedded content: path of one KV write · 3 hybrid-required classes, 1 classical hop\]

The direct KV client skips the browser hop, so its path can be hybrid end to end. Log files at rest are outside this plan.

The classification is built in three steps:

1. Follow one client write from its origin to the last follower and list every connection it crosses. Each becomes a class.
2. Label each class by what it carries: values, raw commands or log entries (value-bearing), or metadata only.
3. Treat a hop whose content is not yet verified in the code as value-bearing until it is checked.

## Transport classes and requirements

A class is `hybrid-required` when any message on it can carry a KV value, a raw command or a log entry. Metadata-only classes stay `hybrid-preferred`. A class that mixes data takes the strictest requirement of what it carries, and unclassified traffic is refused until someone classifies it.

| Class | Carries | Requirement | Why |
| --- | --- | --- | --- |
| `node-peer` (node to node) | Log entries, terms, commit indexes | `hybrid-required` | Heartbeats and entry replication share one call, so the class cannot be split by message type. |
| `gateway-node` | KV reads, writes, deletes; leader lookup | `hybrid-required` | Carries values. |
| `client-node` (direct KVClient) | KV reads, writes, deletes | `hybrid-required` | Carries values. |
| `log-access` (restricted) | Raw commands | `hybrid-required` | Raw log contents can include values that were later deleted. |
| `browser-https` (HTTPS/WSS, value routes) | KV values for HTTP API clients | `classical` (v1 exception) | Decision carried over from the original plan. Claims for these values cover the RPC segments only. |
| `telemetry` (dashboard, operator) | Metadata only: counts and states, no credentials or KV contents | `hybrid-preferred` on RPC, `classical` in the browser | No values. Separate context so it cannot weaken the RPC classes. |

The three requirement levels mean:

- **`hybrid-required`:** TLS 1.3 with a hybrid group. Classical fallback is not accepted. If the final negotiated group is not hybrid, the connection is closed before any RPC traffic.
- **`hybrid-preferred`:** hybrid offered first, X25519 accepted. Fallback produces a visible warning and a count.
- **`classical`:** X25519 only. Used for the browser context in v1 and for controlled comparison runs.

## Implementation

The work runs in six steps, in this order.

1. **Bring in the security baseline.** Cherry-pick `f96bbf3` onto `pqc`. Preserve certificate identities, role restrictions, dedicated KV methods, restricted logs and the metadata-only UI. Run its 26-test suite before changing transport behavior.
2. **Encode the classification.** Add a repository-owned transport policy that maps every connection class in the table above to its requirement. Startup refuses to run if a listener or an outbound connection has no class.
3. **Give each class its own TLS context.** Where the pinned runtime can restrict the offered groups, `hybrid-required` contexts offer only hybrid groups. Regardless of that, enforce after the handshake: require TLS 1.3 and an allowed, recognized group before creating the RPyC connection, on both the dialing and the accepting side. Never retry with plaintext, unauthenticated TLS or weakened certificate checks.
4. **Define the launcher profiles.** `policy` (default) applies the class table. `hybrid-preferred` and `classical` remain for controlled comparisons. In `policy` and `hybrid-preferred`, require local hybrid support at startup: fallback accommodates classical peers, not a misconfigured local runtime.
5. **Configure OpenSSL before Python initializes TLS.** A launcher selects the profile and starts a fresh Python process with the matching repository-owned OpenSSL configuration, with hybrid key shares first and classical ones explicit. Route all supported startup paths and direct-client examples through it. Keep browser HTTPS/WSS on classical X25519 in a separate context, and test that its settings cannot weaken any RPC context. Target CPython 3.14 with OpenSSL 3.6 and record the exact tested versions. OpenSSL supports process-wide TLS defaults through its [configuration mechanism](https://docs.openssl.org/3.6/man5/config/).
6. **Disable session resumption** so each connection performs a fresh, measurable key exchange.

## Evidence and claim rules

The plan reports what each connection actually negotiated, and it states a protection claim for a data class only when the evidence covers its whole path.

**Per-connection evidence**

- Use Python's TLS message callback to parse the final ServerHello key-share group, handling HelloRetryRequest correctly.
- After the handshake, require TLS 1.3 and an allowed, recognized group before creating the RPyC connection.
- Record `class`, `direction` (dialed or accepted), local and peer identity, `tls_version`, `cipher`, `key_exchange_group` and `protection` (`hybrid` or `classical`).
- Treat the callback as a pinned runtime dependency. Reject the connection when negotiation evidence is unavailable or malformed.
- Compare the two sides: if the dialing and the accepting side report different groups for one connection, record an anomaly.

**Fallback and rejection**

- On `hybrid-preferred` classes, fallback produces a visible warning and a count.
- On `hybrid-required` classes, a non-hybrid result is rejected and counted separately as a required-class rejection, with the peer identity.
- Operator telemetry exposes aggregate counts per class and outcome, without credentials or KV contents.

**Claim rule**

A claim for a data class (for example, KV values written through the gateway) holds only if every class on its path is `hybrid-required` and, in the measured window, every connection on those classes was observed hybrid, with no fallbacks, no unexplained rejections and no anomalies. The report gives each data class one status:

- `hybrid-verified`: the claim holds for the stated window.
- `partial`: names the classical or unverified hop.
- `not-evaluated`: the path has an unclassified or unverified hop.

Every claim is printed with its exclusions: classical certificate authentication, the browser transport and stored data.

## Interfaces and compatibility

The protocol and the data model do not change, but classical peers lose access to value-bearing classes.

- **Launcher:** `--profile policy|hybrid-preferred|classical` (default `policy`), `--policy <file>`, and a startup diagnostic command that prints each class, its requirement, local hybrid support and the observed results.
- **Unchanged:** authenticated RPC payloads, `KVClient` operations, HTTP routes and consensus behavior.
- **Compatibility cost:** a classical-only peer or client can still use `hybrid-preferred` classes through fallback, but it is rejected on `hybrid-required` classes. Old plaintext clients stay unsupported.
- **Preserved:** certificate generation and identity mapping. No ML-DSA certificates, message signatures or storage encryption in this version.

## Tests and comparative measurements

Acceptance requires the security and regression tests to pass, negotiation to be independently verified, and every `hybrid-required` class to show zero classical connections. Performance results are reported without inventing an improvement threshold.

**Tests**

- Retain all 26 baseline authentication tests.
- Per class: hybrid peers negotiate hybrid; a classical-only peer is rejected on a `hybrid-required` class before any RPC traffic, in both connection directions; the same peer falls back with a warning and a count on a `hybrid-preferred` class; the `classical` profile negotiates classical only.
- Mixed-capability cluster: run nodes A and B hybrid-capable and node C classical-only. Check that A and B connect hybrid, that connections involving C are rejected on `node-peer`, that A and B still elect a leader and commit writes, and that C's repeated election timeouts do not disturb them. The claim report must show `partial` for the value path while C is a member.
- Claim logic: an injected classical hop produces `partial` and names the hop; disagreeing observations from the two sides produce an anomaly.
- Reject TLS 1.2, unsupported groups, invalid certificates, spoofed identities and unknown negotiation results.
- Cross-check group classification against independent OpenSSL clients and servers. Test HelloRetryRequest and malformed parser inputs.
- Exercise elections, leader changes, replication, KV operations, reconnects and telemetry isolation under every profile.

**Measurements**

Benchmark identical three-node clusters with identical credentials and connection behavior under three configurations: `classical`, `hybrid-preferred` and `policy`.

- Full-handshake latency, CPU time and TLS record bytes: 100 connections per trial.
- KV throughput and p50, p95 and p99 latency: 1 KiB values, concurrency 1 and 8, five-second warmup and 30-second measurement.
- Election completion and write-to-commit latency.
- Five trials per configuration. Export raw JSON/CSV and a comparison report with fallback counts, rejection counts and runtime versions.

## Rollout

Requirements are switched on only after the evidence shows every node and connection can meet them. Each step is a coordinated restart.

1. **Upgrade the runtime on every node.** The startup diagnostic must show local hybrid support on all of them.
2. **Run every class as `hybrid-preferred`.** Check the negotiated results from both sides. Every connection on a class that will become required must show hybrid with zero fallbacks and zero anomalies.
3. **Switch the required classes to `hybrid-required`.** Use the `policy` profile with the repository-owned class table.
4. **Confirm.** Telemetry shows zero required-class rejections, and the claim report shows `hybrid-verified` for the value paths it can cover.

**Later stage (separate change, touches consensus).** Replicate the policy epoch through the Raft log so every node switches at an agreed log index. That change needs its own plan, because the entry travels over the connections it governs and a node that was down must catch up before it can comply.

## Limits and open decisions

This phase protects transport confidentiality with hybrid key exchange, and only where the evidence says it was negotiated. Classical certificate authentication, the browser transport and stored data stay outside the PQC guarantee.

Because the HTTPS/WSS link that carries values from HTTP clients stays classical in v1, a value written through it is `partial` at best: only its RPC segments can be `hybrid-verified`.

**To verify in the code before the classification is final** (these are unverified assumptions)

- Whether followers forward client writes to the leader, which would add a value-bearing `node-peer` path, or answer with a leader hint.
- Whether node-only and client methods share one listener or service. If they do, a class needs per-method authorization or separate listeners.
- Whether the gateway reaches the nodes through a socket or by in-process calls. All the listeners share one process, and an in-process hop is not a network class.
- Whether `read_log` and the dashboard broadcasts include raw commands or values.

**Open decisions**

- Should the HTTPS/WSS value routes become `hybrid-required` once the browser context can negotiate hybrid?
- What does a node that was down when a policy change committed do until it has applied that change?
- If two of three nodes cannot do hybrid, the `node-peer` class rejects every connection and the cluster loses its quorum. Is that acceptable, or does an emergency downgrade need an audited operator action?
- Should the class table become replicated state in a later stage?
