# Investigation of wstunnel issue #534

Issue: https://github.com/erebe/wstunnel/issues/534
Checkout: 73cd268 (v10.7.1-10-g73cd268)

## Finding

The pending reverse-tunnel request waits for an incoming application connection before the server completes the WebSocket HTTP upgrade. Therefore the configured WebSocket ping interval does not apply to that pending connection. The client awaits the HTTP handshake without a timeout, so a silently stalled forwarding path can prevent new sessions indefinitely while established sessions continue normally.

Relevant current source:

- wstunnel/src/tunnel/server/handler_websocket.rs:32: awaits handle_tunnel_request before calling upgrade.
- wstunnel/src/tunnel/server/server.rs:151: awaits exec_tunnel; its ReverseTcp and ReverseUnix branches await run_listening_server.
- wstunnel/src/tunnel/server/reverse_tunnel.rs:138: waits on the accepted-connection receiver.
- wstunnel/src/tunnel/transport/websocket.rs:323: awaits fastwebsockets::handshake::client without an enclosing handshake timeout.
- wstunnel/src/tunnel/client/client.rs:201: reverse loop waits for websocket::connect; only a returned error reaches retry/backoff. Lines 278 onward start the ping-capable transfer task after successful handshake and local endpoint connection.
- wstunnel/src/tunnel/transport/io.rs:173: sends WebSocket pings in the transfer loop.

The same delayed upgrade and unbounded client handshake are present in the v10.6.1 sources, the version identified by the follow-up reporter. No v10.6.1 binary was tested.

## Local reproduction

Built the current checkout with:

    cargo build --locked -p wstunnel-cli

Run:

    python3 /tmp/wstunnel-534-investigation/repro.py

The script creates a local echo application, a wstunnel server/client, and a transparent byte proxy. Both wstunnel processes have --websocket-ping-frequency 1s. It establishes an application session, waits five seconds, tries a second session, and verifies the original session still echoes data. All processes, sockets, and listeners created by the script are cleaned up afterward.

Two cases are tested:

| Case | New session after idle | Established session | Client retries |
| --- | --- | --- | --- |
| Proxy forwards normally | Works | Works | 0 |
| Proxy silently stops forwarding a connection after >3s without application bytes | Hangs | Works | 0 |

In both cases, the pending reverse connection has exactly one payload event during the five-second idle period: the HTTP GET upgrade request. It receives no HTTP 101 response and sends no WebSocket pings. Meanwhile the already upgraded connection exchanges ping/pong frames normally. In the failure case, the eventual HTTP 101 response is dropped by the simulated intermediary, and the client creates no replacement waiting connection during observation.

Raw evidence is in control-result.json, idle_drop-result.json, and the corresponding client/server log files in this directory. The proxy records application bytes, not packet captures or kernel TCP probes.

## Scope and limitations

This confirms the code behavior and reproduces the symptoms with a deliberately simulated silent forwarding failure. It does not establish which intermediary, if any, causes the original reporter's approximately 20-minute failure. Normal forwarding succeeds in the control run. The test uses cleartext WebSocket locally; the handshake/ping ordering is shared with WSS, but the original TLS/proxy deployment was not recreated.

TCP keepalive is already enabled by protocols/tcp/server.rs (on Linux: 60s idle, 10s interval, 3 retries). The finding is specifically about WebSocket/application keepalive. A TCP-terminating intermediary can continue acknowledging the local TCP connection while the end-to-end application forwarding path is stalled, so kernel keepalive alone does not rule out this failure. An ordinary FIN/RST is different: it can let the handshake fail and trigger reconnection.

## Repair direction

A bounded wait with reconnection for pending reverse handshakes is a compatible mitigation. It needs tests that timed-out requests release their server-side waiter and do not consume subsequent incoming sessions.

A full protocol fix would complete the WebSocket upgrade while the reverse request waits, allowing ping/pong processing, then use an explicit ready/accepted message before opening the local target or starting the next reverse request. Simply moving the server's upgrade earlier is insufficient: the current client treats handshake completion as an accepted application connection, and dynamic reverse tunnels currently return destination information through handshake response cookies.

No repository source files were modified by this investigation.
