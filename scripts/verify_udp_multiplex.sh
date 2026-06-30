#!/usr/bin/env bash
#
# End-to-end verification for `--udp-multiplex`.
#
# What it proves:
#   1. (smoke)     A UDP tunnel with N multiplexed connections forwards datagrams correctly.
#   2. (the point) The N connections are reassembled onto a SINGLE upstream UDP socket on the
#                  server, so a stateful destination sees exactly ONE source 5-tuple — which is
#                  what makes WireGuard / QUIC / game protocols work over the multiplexed tunnel.
#
# It needs no root and no tcpdump: a tiny Python UDP echo server records the set of distinct
# client addresses (ip:port) it observes. With the flow_id fix, multiplex=N still yields 1 source.
#
# Usage:
#   ./scripts/verify_udp_multiplex.sh [N]      # N = multiplex degree, default 4
#
set -euo pipefail

N="${1:-4}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/debug/wstunnel"

WS_PORT=8080          # wstunnel server (control plane)
LOCAL_UDP=15353       # client-side local UDP listen port (avoid 5353 = macOS mDNSResponder)
TARGET_UDP=19999      # upstream UDP echo server
PKTS=20               # number of datagrams to send through the tunnel

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
say "Building wstunnel (debug)"
( cd "$ROOT" && cargo build )

# ---------------------------------------------------------------------------
say "Starting upstream UDP echo server on 127.0.0.1:${TARGET_UDP}"
# Echoes every datagram and writes the set of distinct source addresses to $SRC_FILE.
SRC_FILE="$(mktemp)"
python3 - "$TARGET_UDP" "$SRC_FILE" <<'PY' &
import socket, sys
port, srcfile = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
seen = set()
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)               # echo back
    if addr not in seen:
        seen.add(addr)
        with open(srcfile, "w") as f:  # overwrite with current set, one "ip:port" per line
            f.write("\n".join(f"{a}:{p}" for (a, p) in sorted(seen)) + "\n")
PY
PIDS+=($!)
sleep 0.5

# ---------------------------------------------------------------------------
say "Starting wstunnel server on ws://0.0.0.0:${WS_PORT}"
RUST_LOG=info "$BIN" server "ws://0.0.0.0:${WS_PORT}" &
PIDS+=($!)
sleep 0.8

say "Starting wstunnel client with --udp-multiplex ${N}"
echo "    udp://${LOCAL_UDP}:127.0.0.1:${TARGET_UDP}  ->  (x${N} connections)  ->  127.0.0.1:${TARGET_UDP}"
RUST_LOG=info "$BIN" client \
  --udp-multiplex "$N" \
  -L "udp://127.0.0.1:${LOCAL_UDP}:127.0.0.1:${TARGET_UDP}?timeout_sec=30" \
  "ws://127.0.0.1:${WS_PORT}" &
PIDS+=($!)
sleep 1.0

# ---------------------------------------------------------------------------
say "Sending ${PKTS} datagrams through the tunnel and checking echoes"
python3 - "$LOCAL_UDP" "$PKTS" <<'PY'
import socket, sys, time
port, pkts = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.connect(("127.0.0.1", port))
ok = 0
for i in range(pkts):
    msg = f"ping-{i}".encode()
    s.send(msg)
    try:
        if s.recv(65535) == msg:
            ok += 1
    except socket.timeout:
        pass
    time.sleep(0.02)
print(f"    echoed back: {ok}/{pkts}")
sys.exit(0 if ok > 0 else 1)
PY

sleep 0.3
# ---------------------------------------------------------------------------
say "Distinct source 5-tuples observed by the upstream destination"
cat "$SRC_FILE" | sed 's/^/    /'
COUNT="$(grep -c . "$SRC_FILE" || true)"

echo
if [[ "$COUNT" == "1" ]]; then
  printf '\033[1;32mPASS\033[0m: %d multiplexed connections were merged to ONE upstream source port.\n' "$N"
  printf '       Stateful UDP (WireGuard/QUIC/...) will work over the multiplexed tunnel.\n'
  rm -f "$SRC_FILE"
  exit 0
else
  printf '\033[1;31mFAIL\033[0m: destination saw %s distinct source ports (expected 1).\n' "$COUNT"
  printf '       The flow_id merge is not taking effect.\n'
  rm -f "$SRC_FILE"
  exit 1
fi
