# wstunnel Server URL Redirection (301/302/307/308) Specification & Architecture

## 1. Context & Problem Statement

When using `wstunnel` client with a server URL behind a reverse proxy, CDN (e.g., Cloudflare Rules), or HTTP redirector (e.g., `wss://d1.example.com` redirecting to `wss://d2.example.com`), previous versions of wstunnel aborted with:

```text
ERROR tunnel{id="..." remote="..."}: wstunnel::tunnel::client::client: failed to do websocket handshake with the server wss://d1.example.com:443
Caused by:
    Invalid status code: 301
```

This feature adds support for following HTTP 3xx redirects (`301`, `302`, `307`, `308`) when connecting to remote wstunnel servers over WebSocket and HTTP/2 transports.

### Objectives & Guarantees
1. **Minimal footprint:** Localized and idiomatic changes.
2. **Zero new dependencies:** Relies strictly on existing dependencies (`hyper`, `fastwebsockets`, `url`, `tokio`, `bb8`, `arc-swap`, `parking_lot`).
3. **Zero performance regression:** Normal connections (without redirection) experience **identical performance** to the baseline (no extra round-trips, no additional lock contention, no extra heap allocations).
4. **RFC 9110 standard semantics:** Full compliance with standard HTTP redirect semantics across multiple client connections.
5. **Security & robustness:** Downgrade attack protection, redirect loop detection, configurable hop limit (`--max-redirects`), and cached target fallback to canonical URL.

---

## 2. Architecture & Design

### 2.1 The L4 / L7 Decoupling

In wstunnel, connection establishment is decoupled into two layers:
- **Layer 4 (TCP + TLS):** Extracted into `connect_l4_stream` in `wstunnel/src/tunnel/client/connection_pool/manager.rs`. It resolves DNS, establishes TCP, and completes TLS handshake. Pooled connections from `bb8::Pool<L4StreamManager>` dial the canonical configured address.
- **Layer 7 (HTTP / WebSocket Handshake):** Implemented in `wstunnel/src/tunnel/transport/websocket.rs` and `wstunnel/src/tunnel/transport/http2.rs`. It inspects the HTTP response status. If a 101/200 is received, the tunnel is established immediately. If a 3xx response is received, it follows the redirect chain.

### 2.2 Connection Handling Semantics (RFC 9110)

```mermaid
flowchart TD
    subgraph Conn1 ["Connection 1 (Initial Handshake)"]
        A1["Connect to server URL"] --> B1{"Server Response"}
        B1 -->|101 / 200| C1["Tunnel Established (No Redirection)"]
        B1 -->|301 / 308 (Permanent Chain)| D1["Follow Redirect to Target D2\nUpdate Shared Active Target"]
        B1 -->|302 / 307 (Temporary)| E1["Follow Redirect to Target D2\nKeep Canonical URL as Active Target"]
    end

    subgraph Conn2 ["Connection 2 (Subsequent Connection)"]
        F2["New Tunnel Request"] --> G2{"Active Target"}
        G2 -->|Cached D2 (from 301/308)| H2["Connect directly to D2\n(Skips Redirection Round-Trip!)"]
        G2 -->|Canonical URL (from 302/307)| I2["Connect to Canonical URL\nFollows Redirect Again"]
        H2 -->|If D2 Fails / Dead| J2["Automatic Fallback to Canonical URL\nRe-evaluates Redirection"]
    end
```

#### A. Permanent Redirects (`301 Moved Permanently` / `308 Permanent Redirect`)
- **Semantics (RFC 9110 §15.4.2 & §15.4.9):** The target has permanently moved. All future requests should use the new URI.
- **Behavior:** The client follows the redirect chain to `d2`. If the chain consists exclusively of permanent redirects (`is_permanent_chain == true`), the shared `active_target` is updated to `d2` via `ArcSwap<ActiveTarget>`.
- **Subsequent Connections:** Connect directly to `d2`, skipping the redirect round-trip.
- **Fallback:** If `d2` fails to connect or times out (e.g., target server rotated or restarted), the client logs a warning and automatically falls back to the canonical configured server URL.

#### B. Temporary Redirects (`302 Found` / `307 Temporary Redirect`)
- **Semantics (RFC 9110 §15.4.3 & §15.4.8):** The target temporarily resides elsewhere. The canonical configured URL remains the authoritative target.
- **Behavior:** The client follows the redirect to `d2` for this tunnel, but `active_target` is **not** updated.
- **Subsequent Connections:** Query the canonical server URL again, ensuring dynamic redirects (such as rotating NAT ports) are continually re-evaluated.
- **Mixed Chains:** If any hop in a redirect chain is temporary (`302` or `307`), the entire chain is marked temporary and not cached.

### 2.3 Resolving the redirect target

The `Location` value is resolved against the URL currently being dialed (`{scheme}://{host}:{port}/{prefix}/events`)
following RFC 3986, so absolute URLs, protocol-relative references (`//host/...`), absolute paths and
relative paths all work. Default ports are filled in from the scheme (80 for `ws`/`http`, 443 for
`wss`/`https`), and the scheme is translated per RFC 6455 (`http` → `ws`, `https` → `wss`) while
keeping the transport family the client was started with: a websocket client stays on websocket, an
HTTP/2 client stays on HTTP/2.

The path prefix for the next hop is derived from the resolved path:

| Resolved path | Prefix used | Wire path |
| :--- | :--- | :--- |
| absent, `/` | unchanged (configured prefix) | `/{configured}/events` |
| `/v2/events` | `v2` | `/v2/events` |
| `/events` | empty | `//events` |
| `/v2` | `v2` | `/v2/events` |
| `/v2/events/` | `v2` | `/v2/events` |

Trailing slashes are ignored. Note the difference between "no path" (the target host is the same
service, so the configured prefix is kept) and an explicit `/events`, which means the target serves
the upgrade with an empty prefix — that is spelled `//events` on the wire, which is what a client
configured with `-P ""` sends today.

### 2.4 Connection pooling and redirects

The client keeps a pool of pre-warmed Layer 4 connections so that establishing a tunnel does not pay
a TCP + TLS handshake every time (`-c` / `--connection-min-idle`, default `0`; connections have a
30 s maximum lifetime and the pool reaper tops the idle set back up). The pool's manager is built
from the configured server URL and always dials that address, so a pooled connection only ever
points at the canonical URL.

How the different paths interact with it (websocket and HTTP/2; webtransport has no redirect support
and keeps its session in the pool instead of taking it):

| Situation | Pool used? |
| :--- | :--- |
| First hop of a connection to the canonical URL | yes — one pooled stream is taken for the upgrade request |
| First hop of a connection to a cached redirect target | no — dialed directly |
| Any hop after a redirect, even to the same host | no — dialed directly |
| Connections while a temporary redirect is in play (never cached) | yes — every connection starts at the canonical URL |
| Retry against the canonical URL after a cached target failed | no — dialed directly, deliberately |

**Why redirected hops bypass the pool.** The pool cannot dial a different address; making it follow
the active target would mean rebuilding the pool whenever the target changes (and deciding what to do
when it changes back). Redirection exists to save one round trip, so the simple rule — pool for the
configured URL, direct dial for everything else — is deliberate. It is also why `connect_l4_stream`
was extracted: the transports dial one specific address, while the pool is pinned to the configured
one.

**Consequences worth knowing.**

- *Redirected tunnels are not pre-warmed.* With `-c N > 0`, a direct setup takes a pooled connection
  and pays no handshake, whereas a setup behind a permanent redirect dials the cached target afresh
  (TCP + TLS) for every tunnel. "Skips the redirector" removes one HTTP round trip but gives up the
  warm connection, so under `-c` it is not automatically a latency win. With the default `-c 0` there
  is no pool to give up and the redirect costs exactly the extra round trip.
- *The pool keeps warming the configured URL.* After a permanent redirect, the canonical URL is a
  redirector whose pooled connections are never taken again. Because connections expire after 30 s
  and the reaper keeps `min_idle` slots filled, `-c N` makes the client keep re-establishing N
  connections to an address it no longer uses. With `-c 0` nothing is maintained and the point is
  moot.
- *The pool is not corrupted by a redirect.* Taking a pooled stream leaves its slot empty and
  `has_broken` reports it, so the entry is discarded rather than handed out again; the pool refills
  if it is used later.
- *The fallback retry dials directly.* When a cached target fails, the client re-resolves from the
  canonical URL over a fresh connection instead of borrowing a pooled one: after a long-lived
  redirect those entries may be stale, and a recovery path should not add another way to fail.

Making the pool follow the active target (re-pointing the manager when a permanent redirect is
cached, invalidating it when the cache is reset) would restore pre-warming for redirected setups. It
is deliberately out of scope: it changes pool lifecycle, races with in-flight checkouts, and only
matters as a latency optimisation when `-c` is set.

---

## 3. Configuration & CLI Options

```text
      --max-redirects <INT>
          Maximum number of HTTP redirects (301, 302, 307, 308) to follow for server URL.
          Set to 0 to disable redirect following.
          
          [env: WSTUNNEL_MAX_REDIRECTS=]
          [default: 5]
```

- Default is `5` hops.
- Set to `0` to strictly disallow redirect following.

---

## 4. Security & Edge-Case Protections

| Scenario | Behavior |
| :--- | :--- |
| **Downgrade Attack** (`wss` $\rightarrow$ `ws` or `https` $\rightarrow$ `http`) | Strictly rejected with an error: *"Refusing to downgrade from secure scheme (wss) to insecure scheme (http)"*. |
| **Cleartext to TLS** (`ws` $\rightarrow$ `wss` or `http` $\rightarrow$ `https`) | Synthesizes a TLS connector, inheriting the client's `--tls-verify-certificate` setting. |
| **Redirect Loops** (A $\rightarrow$ B $\rightarrow$ A or A $\rightarrow$ A) | Fast cycle detection using a `HashSet<Url>` with scheme normalization (`http`/`ws` and `https`/`wss`). Triggers loop error immediately. |
| **Custom Host Header** (`-H "Host: ..."`) | Custom host header is preserved on the initial hop (`redirect_count == 0`). On redirected hops, the `Host`/authority is dynamically derived from the redirected target. |
| **TLS SNI Override** (`--tls-sni-override`) | Preserved when redirecting to the same hostname, but automatically reset to `None` if redirected across different hosts to prevent SNI mismatch. |
| **mTLS Client Certificates** | Client certificates and TLS configuration are carried over across redirected hops. |
