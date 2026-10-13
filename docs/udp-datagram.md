# UDP over WebTransport Datagrams

Forward UDP tunnels can opt into unreliable, unordered QUIC Datagrams:

```cmd
wstunnel.exe client --no-color ^
  -L tcp://127.0.0.1:33389:127.0.0.1:3389 ^
  -L "udp://127.0.0.1:33389:127.0.0.1:3389?transport=datagram" ^
  wts://server.example:9898/
```

Use the updated binary on both ends. The server's existing `wts://` listener or
TLS listener with `--enable-webtransport` enables WebTransport. Existing TLS,
authentication and destination restrictions still apply. RDP is an example;
no port or application receives special treatment.

`?transport=datagram` is a **client-side tunnel option**. Add it only to the
client's `-L udp://...` URI, not to the server command or server URL. The client
negotiates the mode during tunnel setup. The server requires the updated binary
and WebTransport enabled, but no additional Datagram-mode flag:

```sh
wstunnel server wts://0.0.0.0:9898/
```

Keep the existing TLS, authentication and restriction options for your deployment.

`transport=stream` is the default. Datagram mode requires `wts://` and supports
forward `udp://` tunnels. Reverse UDP, SOCKS UDP and transparent UDP retain their
existing stream behavior. Unknown UDP transport names fail parsing. An older
server fails the bounded Datagram handshake; there is no automatic fallback.

Rust library callers constructing `LocalProtocol::Udp` must supply the new
`transport` field (`UdpTransport::Stream` for the existing behavior). Serialized
stream-mode metadata omits the field, and old metadata still defaults to stream.

UDP payloads use QUIC DATAGRAM frames; an ordinary bidirectional stream carries
only the destination JWT, a four-byte `WUD1` readiness acknowledgement, and
association lifetime signals. TCP and legacy UDP keep their stream paths.

Each authenticated WebTransport session has one receiver and at most 64 active
Datagram associations. Each association has an eight-packet bounded queue.
The ten-byte application header is version=1, flags=0, and the QUIC control
stream ID as an unsigned 64-bit big-endian integer. IDs are scoped to the
session and are not reused within it. Unknown IDs cannot create UDP sockets.
Invalid packets and packets arriving after cleanup are dropped.

Payload size is limited by the current WebTransport maximum minus ten bytes.
Oversized packets and full receive queues are dropped; later packets continue
to flow. There is no fragmentation, retransmission, or packet reordering.
Empty UDP packets are supported in Datagram mode.

`timeout_sec` retains its default of 30 seconds; `timeout_sec=0` disables idle
expiration. Datagram activity in either direction refreshes the idle timer.
Control-stream FIN/reset and session failure also clean up associations.
New traffic after timeout or connection loss creates a new association.

Trace logs show association IDs and tx/rx sizes; debug logs show size and parse
drops. Session teardown logs tx/rx, oversize, invalid, queue-full, creation and
expiration counters. Enable debug/trace verbosity using the existing CLI
logging options when diagnosing size limits.

Idle expiration is an expected lifecycle event: it produces the INFO expiration
message and DEBUG tunnel-close diagnostics, not a receive ERROR. Socket/network
timeouts remain errors. On session teardown the WebTransport dependency may
log `failed to read capsule ... UnexpectedEnd`; that message can also represent
an underlying QUIC read error whose original cause the capsule parser discards.
It does not, by itself, indicate malformed UDP payloads.

The send input buffer is reused after framing into independently owned packet
storage, including on oversize drops and send errors. Control-stream FIN remains
an expected closure; unexpected control bytes are protocol errors and other read
errors retain their original cause. These changes preserve the wire format.

## Validation

```text
cargo test --workspace --locked --no-default-features --features ring
cargo build --workspace --release --locked --no-default-features --features ring
```

The tests cover header validation, bounded dispatch, association isolation,
CLI compatibility, TCP and legacy UDP, Datagram round trips, multiple local
sources, empty packets, oversized packet recovery, bidirectional activity,
idle recreation, control closure and reconnect.

Validation recorded on 2026-10-07 with Rust 1.99.0 and the `ring` feature:

| Platform | Workspace tests | Docker proxy test |
| --- | --- | --- |
| Linux / WSL, Docker enabled | 76 passed, 0 failed, no exclusions | Passed |
| Windows GNU | 75 passed, 0 failed, 1 excluded | Not run on Windows |

The expected idle-timeout classification and capsule-parser diagnostics are
included in these results. On both platforms the `ring` configuration also passes
workspace/all-targets Clippy with `-D warnings` after warning cleanup.
Linux also passes all 76 tests with the default `aws-lc-rs` provider, including
PEM-loading, mTLS and certificate/key file-reload coverage after replacing the
unmaintained rustls-pemfile wrapper with the existing PemObject API.
Rust 1.95.0, Windows default `aws-lc-rs` and the
complete upstream nextest/all-features CI matrix remain unvalidated. These test
results do not establish an RDP or WAN performance improvement.

Actual RDP behavior and netem/WireGuard comparisons require an authorized RDP
server and a controllable network. Verify the mstsc UDP source PID, Datagram
trace logs and RDP multitransport events. Compare latency, jitter, loss and CPU
under the RTT/loss/jitter matrix in the supplied handoff document. QUIC Datagrams
remain congestion controlled; this feature does not guarantee a latency gain.
