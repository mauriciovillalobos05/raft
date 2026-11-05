# Authentication and authorization

All application operations require authenticated identities. RPC uses mutual TLS;
HTTP uses Basic authentication over HTTPS. UI/operator login exchanges Basic
credentials for an opaque, server-side session cookie. Public UI assets and the
login form contain no application data. FastAPI documentation routes are disabled.

## Permission map

| Identity | Allowed operations |
| --- | --- |
| RPC node | `send_vote_request`, `send_health_check_request` (AppendEntries/heartbeat), only as a configured peer |
| RPC client | `set_kv`, `delete_kv`, `read_kv`, `scan_kv`, `scan_kv_by_prefix`, `get_leader` |
| HTTP client | `GET`, `POST`, `DELETE /kv-store` |
| HTTP UI/operator | `GET /health`, `GET /cluster/status`, `POST /auth/login`, telemetry `/ws` via session |
| Browser session | Same-origin `POST /auth/logout` to revoke its own session |

`read_log` and raw `append_log_entries` have no remote exposure. Operators have no
KV permission and no implicit log-reading permission. RPyC protocol housekeeping
(e.g. ping) is separate from application operations.

## Code map

| Location | Responsibility |
| --- | --- |
| `security/auth.py` | Load private config, validate certificate fingerprints, establish TLS connections, enforce expected server identity, hash/verify passwords with scrypt |
| `security/http.py` | Basic identity verification, HTTP role dependencies, origin checks, bounded in-memory sessions and revocation |
| `security/wire.py` | Strict JSON request schemas, size limits, rejection of unknown fields; no pickle or caller-object callbacks |
| `raft/raft_rpc.py` | One service instance per connection, role allowlist, node ID binding, dedicated KV command construction, secure server factory |
| `raft/raft_server.py` | Existing consensus logic; outgoing votes and AppendEntries now use authenticated TLS and JSON |
| `inmem/kv_client.py` | Certificate-authenticated KV operations, leader discovery, retries and reconnects |
| `websocket_server.py` | HTTPS API, role checks, browser session endpoints, authenticated receive-only telemetry socket, same-origin UI assets |
| `raft/raft_websocket_manager.py` | Metadata snapshots/live events, explicit event/field allowlist, session checks before sending |
| `client/raft-visualization/src/App.jsx` | UI sign-in/sign-out, same-origin WSS, metadata visualizations; no KV forms or data tables |
| `start_cluster.py`, `start_cluster_test_hook.py` | Validate credentials before starting nodes; start TLS RPC listeners and HTTPS/WSS gateway |
| `tools/bootstrap_auth.py` | Generate temporary development CA, individual certificates, password hashes and private config |
| `security_tests/test_auth.py` | Integration tests using temporary certificates, three real Raft nodes, HTTPS and WebSocket connections |

## Execution flow

1. Startup loads `RAFT_AUTH_CONFIG`; missing/invalid credentials stop startup.
   The supported launchers validate the credentials they will use before election
   threads start. Configuration is cached; changes require a restart.
2. A node connects with its own certificate. The receiver verifies CA trust and
   the configured SHA-256 fingerprint, then creates a connection-specific service.
   The peer must belong to that node's peer group. The vote's `candidate_id` or
   AppendEntries `leader_id` must equal the certificate identity before consensus
   code executes. Authentication success does not imply a vote will be granted.
3. A direct KV client presents its client certificate. The HTTP gateway first
   authenticates an HTTP client with Basic, then uses a separate gateway client
   certificate for backend RPC. Dedicated set/delete RPCs build commands on the
   server and feed the existing Raft replication path. Reads/scans access the
   committed state machine. Writes still acknowledge append/submission rather than
   waiting for commitment; this change does not change existing read consistency.
4. A UI/operator signs in over HTTPS. The password is verified against a scrypt
   hash; a random token is set in a Secure, HttpOnly, SameSite=Strict cookie.
   `/ws` checks the session and an explicit allowed origin before acceptance.
   It sends node/election/replication metadata only. Initial snapshots go only to
   the connecting subscriber. Keys, fields, values, commands, and nested RPC
   response bodies are excluded. Client messages close the read-only socket.
5. Logout revokes the token. Expiry/revocation is checked before telemetry sends
   and at least once a second on idle sockets; affected sockets close with 1008.
   Restarting the gateway invalidates all sessions.

## Local setup and startup

On the PQC branch use CPython 3.14 linked to OpenSSL 3.6. See
[PQC_IMPLEMENTATION.md](PQC_IMPLEMENTATION.md) for transport profiles and claims. From the repository root:

```bash
source raft-venv/bin/activate
pip install -r requirements.txt
# The target directory must not already exist. Keep credentials outside the repo.
python -m tools.bootstrap_auth /private/tmp/raft-dev-auth
export RAFT_AUTH_CONFIG=/private/tmp/raft-dev-auth/auth.json
npm --prefix client/raft-visualization ci
npm --prefix client/raft-visualization run build
python start_cluster.py
```

Open `https://localhost:8765` and sign in as `viewer` or `operator`; generated
passwords are in `/private/tmp/raft-dev-auth/passwords.json`. The local browser must
trust this development CA (`ca.crt`) for HTTPS/WSS. Trust it only in your development
browser/profile. The generated certificates last 30 days and cover localhost and
127.0.0.1. Existing running processes retain their old code until restarted.

HTTP testing uses `kv-client` for KV and `viewer`/`operator` for telemetry. Curl
prompts for the generated password, avoiding passwords in shell history:

```bash
curl --cacert /private/tmp/raft-dev-auth/ca.crt -u viewer https://localhost:8765/health
curl --cacert /private/tmp/raft-dev-auth/ca.crt -u kv-client \
  'https://localhost:8765/kv-store?key=example&field=name'
```

Direct Python clients use their own identity:

```python
from inmem.kv_client import KVClient
from websocket_server import CLUSTER_CONFIG

client = KVClient(CLUSTER_CONFIG, identity="direct-client")
try:
    print(client.set("example", "name", "Alice", timestamp=100))
finally:
    client.close()
```

Raw RPC requests now use JSON strings; for example, `conn.root.read_kv(json.dumps(
{"key": "example", "field": "name", "timestamp": 101}))` returns a JSON string.
`KVClient` preserves its public result dictionaries and scan tuple pairs. Nodes
use string identities (`A`, `B`, `C`); the standalone launcher defaults to `A`.
Old unauthenticated clients and dataclass-proxy RPC payloads are incompatible.

## Deployment and credential lifecycle

The bootstrap tool is for local development. Production certificates must come
from your managed CA and include the actual server DNS/IP SANs. Register each
certificate fingerprint in the private config and assign its node/client role.
Only deploy a process's own private key(s): the combined local cluster needs the
three node keys and gateway key; a separate node needs its own key; a direct
client needs only its own key. Other identities' entries need fingerprints but
not readable private keys. Keep CA signing keys and generated password files away
from runtime hosts. Config paths are relative to the config directory.

HTTP account roles are configured independently of certificate identities.
`allowed_origins` must contain the exact HTTPS UI origin, without a trailing slash;
there is no wildcard CORS policy. Serve the built UI from the gateway, rather than
an HTTP Vite server. Run through the TLS-enabled launchers; proxy headers are not
trusted. Never expose a separate plaintext backend listener.

To rotate a credential, install its replacement cert/key, replace its configured
fingerprint (or password hash), and restart the affected services. Removing a
fingerprint/user and restarting revokes access, including existing connections
and sessions. There is no hot reload or online certificate revocation service.
Session storage is process-local; use one gateway worker with this implementation.

## Verification

```bash
python -m security.launcher -m unittest discover -s security_tests -v
npm --prefix client/raft-visualization run lint
npm --prefix client/raft-visualization run build
```

The suite generates its own temporary credentials and state and binds ephemeral
loopback ports. It does not start or change your normal cluster. It covers missing
configuration, hashed passwords, plaintext/missing/unregistered certificates,
server identity mismatch, node/client permission boundaries, spoofed node IDs,
malformed and proxy payloads, concurrent identity isolation, election/replication,
KV set/read/scan/delete, HTTP role checks, disabled docs, session/origin checks,
telemetry redaction, logout and expiration, reconnects and leader changes.

Verified on 2026-10-30 with Python 3.14: **26 integration tests passed in 4.688s**.
Frontend lint, production build, Python compilation, and `git diff --check` also
passed. This is the focused authentication/regression suite; the older standalone
resilience runner was not run.
