#!/usr/bin/env bash
#
# Benchmark a wstunnel transport end to end with iperf3.
#
#   iperf3 -c ──▶ wstunnel client ──[ wts:// | wss:// | https:// ]──▶ wstunnel server ──▶ iperf3 -s
#
# Measures throughput (TCP and UDP), CPU and per-function cost (perf), and memory (peak RSS, plus
# heap allocations when built with the `dhat-heap` feature).
#
# USAGE
#   scripts/bench.sh [options]
#
# WHAT TO MEASURE
#   -t, --transport LIST   transports to run, comma separated: wts, wss, ws, https, http
#                          (default: wts)
#   -m, --mode LIST        throughput, cpu, mem — comma separated, or `all`
#                          (default: throughput,cpu,mem)
#   -d, --duration SECS    seconds per iperf3 run (default: 10)
#   -P, --parallel N       iperf3 parallel streams (default: 1)
#       --udp-rate RATE    iperf3 UDP offered rate, e.g. 2G. 0 = unlimited (default: 0)
#
# WHAT TO RUN IT AGAINST
#   By default every component is spawned locally on loopback. Supply one and it is neither
#   spawned nor measured, and it is left running when the script exits.
#
#   -s, --server TARGET    an existing wstunnel server, as `wts://host:port` or `host:port`.
#                          A scheme pins the transport; a bare host:port keeps --transport, which
#                          is what you want against a server started with --enable-webtransport
#   -i, --iperf3 TARGET    an existing iperf3 server, as `host` or `host:port` (default port 5201)
#       --client-args STR  extra flags passed verbatim to the wstunnel client, e.g. a path prefix
#                          (-P), credentials, or --tls-verify-certificate
#
# HOW TO BUILD AND PROFILE
#       --call-graph MODE  fp | dwarf | lbr | none (default: fp). Only affects --mode cpu.
#                          fp rebuilds with frame pointers into target/fp/; it is the only mode
#                          that reliably resolves user frames in an optimised build
#       --dhat             heap-profile the client (needs the dhat-heap feature; implies a
#                          release-with-symbols build)
#       --profile NAME     cargo profile (default: release-with-symbols)
#       --no-build         use whatever binary is already there
#       --keep-logs        keep empty log files instead of pruning them
#   -h, --help             this text
#
# EXAMPLES
#   scripts/bench.sh                                   # wts: throughput + cpu + mem
#   scripts/bench.sh --transport wts,wss               # compare two transports side by side
#   scripts/bench.sh --mode throughput -d 30 -P 4      # longer run, 4 parallel streams
#   scripts/bench.sh --mode cpu --call-graph fp        # call graphs, not just a flat profile
#   scripts/bench.sh --mode cpu --call-graph none      # flat profile only, skips the rebuild
#   scripts/bench.sh --mode mem --dhat                 # where the client allocates
#   scripts/bench.sh --server wts://bench.example.com:8080
#   scripts/bench.sh --server host:8080 --transport wts,wss,https
#   scripts/bench.sh --server wts://vpn.example.com:443 --iperf3 10.0.0.5:5201
#   scripts/bench.sh --server wts://h:443 --client-args '--tls-verify-certificate -P mypath'
#
# OUTPUT
#   A summary table, plus iperf3 JSON, perf.data, rendered perf reports, dhat profiles and both
#   processes' logs under target/bench/<timestamp>/.
#
# See docs/BENCHMARKING.md for how to read the numbers.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------- options
TRANSPORTS="wts"
MODE="throughput,cpu,mem"
DURATION=10
PARALLEL=1
UDP_RATE="0"          # 0 = unlimited, iperf3 pushes as hard as it can
USE_DHAT=0
CALL_GRAPH="fp"    # fp | dwarf | lbr | none
SERVER=""          # empty = spawn a local wstunnel server
IPERF3=""          # empty = spawn a local iperf3 server
CLIENT_ARGS=""     # extra flags for the wstunnel client (tls, path prefix, credentials, ...)
PROFILE="release-with-symbols"   # keeps symbols so perf can resolve frames
BUILD=1
KEEP_LOGS=0

usage() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--transport)  TRANSPORTS="$2"; shift 2 ;;
    -m|--mode)       MODE="$2"; shift 2 ;;
    -d|--duration)   DURATION="$2"; shift 2 ;;
    -P|--parallel)   PARALLEL="$2"; shift 2 ;;
    --udp-rate)      UDP_RATE="$2"; shift 2 ;;
    --dhat)          USE_DHAT=1; PROFILE="release-with-symbols"; shift ;;
    --call-graph)    CALL_GRAPH="$2"; shift 2 ;;
    -s|--server)     SERVER="$2"; shift 2 ;;
    -i|--iperf3)     IPERF3="$2"; shift 2 ;;
    --client-args)   CLIENT_ARGS="$2"; shift 2 ;;
    --profile)       PROFILE="$2"; shift 2 ;;
    --no-build)      BUILD=0; shift ;;
    --keep-logs)     KEEP_LOGS=1; shift ;;
    -h|--help)       usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

has_mode() { [[ ",$MODE," == *",$1,"* ]] || [[ "$MODE" == "all" ]]; }

# ---------------------------------------------------------------------------- preflight
need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need iperf3
need jq
need ss
has_mode cpu && need perf

# `[::1]:8080` and `host:8080` both have to work, so split on the last colon outside brackets.
split_authority() {
  local a="$1"
  if [[ "$a" == \[*\]:* ]]; then AUTH_HOST="${a%%]:*}]"; AUTH_PORT="${a##*]:}"
  elif [[ "$a" == *:* ]];    then AUTH_HOST="${a%:*}";     AUTH_PORT="${a##*:}"
  else AUTH_HOST="$a"; AUTH_PORT=""
  fi
}

# --server takes either `scheme://host:port` or a bare `host:port`. A scheme pins the transport;
# without one the transport loop still applies, which is what you want against a server started
# with --enable-webtransport, since it serves every scheme on the same port.
SERVER_AUTHORITY=""
if [[ -n "$SERVER" ]]; then
  if [[ "$SERVER" == *://* ]]; then
    TRANSPORTS="${SERVER%%://*}"
    SERVER_AUTHORITY="${SERVER#*://}"
  else
    SERVER_AUTHORITY="$SERVER"
  fi
  SERVER_AUTHORITY="${SERVER_AUTHORITY%%/*}"
  split_authority "$SERVER_AUTHORITY"
  [[ -n "$AUTH_PORT" ]] || { echo "--server needs a port, got: $SERVER" >&2; exit 1; }
fi

IPERF3_HOST=""; IPERF3_PORT=""
if [[ -n "$IPERF3" ]]; then
  split_authority "$IPERF3"
  IPERF3_HOST="$AUTH_HOST"; IPERF3_PORT="${AUTH_PORT:-5201}"
fi

case "$CALL_GRAPH" in
  fp|dwarf|lbr|none) ;;
  *) echo "--call-graph must be one of: fp, dwarf, lbr, none" >&2; exit 1 ;;
esac

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="target/bench/$RUN_ID"
mkdir -p "$OUT_DIR"

FEATURES=()
(( USE_DHAT )) && FEATURES+=(--features dhat-heap)

# Frame pointers are the only call-graph mode that reliably resolves user frames in an optimised
# build: release omits them, DWARF unwinding needs CFI that `panic = "abort"` lets the compiler
# drop, and LBR needs PMU branch-stack support that many chips (AMD Zen included) do not expose.
# The RUSTFLAGS change would invalidate the normal build cache, so it gets its own target dir.
CARGO_ENV=()
TARGET_ROOT="target"
if [[ "$CALL_GRAPH" == "fp" ]] && has_mode cpu; then
  CARGO_ENV=(env RUSTFLAGS="-C force-frame-pointers=yes")
  TARGET_ROOT="target/fp"
fi

if (( BUILD )); then
  echo "==> building wstunnel (profile=$PROFILE call-graph=$CALL_GRAPH ${FEATURES[*]:-})"
  [[ -n "${CARGO_ENV[*]:-}" ]] && echo "    with frame pointers, into $TARGET_ROOT/ (first run rebuilds everything)"
  ${CARGO_ENV[@]+"${CARGO_ENV[@]}"} cargo build -p wstunnel-cli --profile "$PROFILE" \
    --target-dir "$TARGET_ROOT" "${FEATURES[@]}" >/dev/null
fi
# cargo puts `dev` in target/debug, not target/dev
case "$PROFILE" in
  dev|test) TARGET_DIR=debug ;;
  bench)    TARGET_DIR=release ;;
  *)        TARGET_DIR="$PROFILE" ;;
esac
WSTUNNEL="$TARGET_ROOT/$TARGET_DIR/wstunnel"
[[ -x "$WSTUNNEL" ]] || { echo "binary not found: $WSTUNNEL (drop --no-build?)" >&2; exit 1; }

# ---------------------------------------------------------------------------- helpers
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }

# Wait for something to listen on a TCP port, rather than sleeping and hoping.
#
# Checks the listen table instead of connecting: a connection to the tunnel port would be carried
# through the tunnel to iperf3, which takes it for a control connection and then sees it hang up,
# breaking the run that follows.
wait_tcp() {
  local port="$1" tries=100
  while (( tries-- )); do
    ss -ltnH "sport = :$port" 2>/dev/null | grep -q . && return 0
    sleep 0.1
  done
  echo "timed out waiting for a listener on 127.0.0.1:$port" >&2
  return 1
}

# Peak resident set of a process, in MiB. VmHWM is the kernel's own high-water mark, so no
# sampling race: it is the true peak since the process started.
peak_rss_mib() {
  local pid="$1"
  awk '/VmHWM/ {printf "%.1f", $2/1024}' "/proc/$pid/status" 2>/dev/null || echo "n/a"
}

fmt_bits() { awk -v b="$1" 'BEGIN { printf "%.2f Gbit/s", b/1e9 }'; }

# iperf3 reports failures in the JSON and still exits 0, so a run that never transferred anything
# would otherwise show up as a perfectly plausible 0.00 Gbit/s.
iperf_error() { jq -r '.error // empty' "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------- one run
# start_stack <scheme> <local_proto>  ->  sets SRV_PID CLI_PID TUNNEL_PORT IPERF_PORT
start_stack() {
  local scheme="$1" local_proto="$2" tag="$3"
  TUNNEL_PORT="$(free_port)"
  SRV_PID=""; IPERF_PID=""

  if [[ -n "$IPERF3_HOST" ]]; then
    IPERF_HOST="$IPERF3_HOST"; IPERF_PORT="$IPERF3_PORT"
  else
    IPERF_HOST="127.0.0.1"; IPERF_PORT="$(free_port)"
    iperf3 -s -p "$IPERF_PORT" --logfile "$OUT_DIR/$tag.iperf3-server.log" &
    IPERF_PID=$!; PIDS+=("$IPERF_PID")
    wait_tcp "$IPERF_PORT"
  fi

  if [[ -n "$SERVER_AUTHORITY" ]]; then
    SRV_TARGET="$SERVER_AUTHORITY"
  else
    SRV_PORT="$(free_port)"; SRV_TARGET="127.0.0.1:$SRV_PORT"
    RUST_LOG=WARN "$WSTUNNEL" server "$scheme://127.0.0.1:$SRV_PORT" \
      > "$OUT_DIR/$tag.server.log" 2>&1 &
    SRV_PID=$!; PIDS+=("$SRV_PID")
    wait_tcp "$SRV_PORT"
  fi

  # iperf3 always opens its control connection over TCP, even in UDP mode, and on the same port
  # as the data. So a udp run needs both tunnels on that port: tcp carries the control channel,
  # udp carries the payload. TCP and UDP are separate port namespaces, so they do not clash.
  local tunnels=(-L "tcp://$TUNNEL_PORT:$IPERF_HOST:$IPERF_PORT")
  [[ "$local_proto" == "udp" ]] && tunnels+=(-L "udp://$TUNNEL_PORT:$IPERF_HOST:$IPERF_PORT")

  # shellcheck disable=SC2206  # deliberate word splitting: --client-args is a flag string
  local extra=($CLIENT_ARGS)
  RUST_LOG=WARN WSTUNNEL_DHAT_OUT="$PWD/$OUT_DIR/$tag.dhat-heap.json" \
    "$WSTUNNEL" client "${tunnels[@]}" ${extra[@]+"${extra[@]}"} "$scheme://$SRV_TARGET" \
    > "$OUT_DIR/$tag.client.log" 2>&1 &
  CLI_PID=$!; PIDS+=("$CLI_PID")
  wait_tcp "$TUNNEL_PORT"
}

# Only tears down what this script started; anything given with --server or --iperf3 is left alone.
stop_stack() {
  local own=("$CLI_PID")
  [[ -n "$SRV_PID" ]] && own+=("$SRV_PID")
  [[ -n "$IPERF_PID" ]] && own+=("$IPERF_PID")
  kill "${own[@]}" 2>/dev/null || true
  wait "${own[@]}" 2>/dev/null || true
}

# Which pids perf should watch. A remote server is not ours to profile.
measured_pids() {
  if [[ -n "$SRV_PID" ]]; then echo "$CLI_PID,$SRV_PID"; else echo "$CLI_PID"; fi
}

# ---------------------------------------------------------------------------- modes
declare -A RESULT

bench_throughput() {
  local scheme="$1"

  start_stack "$scheme" tcp "$scheme.tcp"
  echo "    tcp  ..."
  iperf3 -c 127.0.0.1 -p "$TUNNEL_PORT" -t "$DURATION" -P "$PARALLEL" -J \
    > "$OUT_DIR/$scheme.tcp.json" 2>&1 || true
  RESULT["$scheme.tcp"]="$(jq -r '.end.sum_received.bits_per_second // 0' "$OUT_DIR/$scheme.tcp.json")"
  RESULT["$scheme.tcp.retrans"]="$(jq -r '.end.sum_sent.retransmits // 0' "$OUT_DIR/$scheme.tcp.json")"
  RESULT["$scheme.tcp.err"]="$(iperf_error "$OUT_DIR/$scheme.tcp.json")"
  [[ -n "${RESULT[$scheme.tcp.err]}" ]] && echo "      tcp FAILED: ${RESULT[$scheme.tcp.err]}"
  stop_stack

  start_stack "$scheme" udp "$scheme.udp"
  echo "    udp  ..."
  iperf3 -c 127.0.0.1 -p "$TUNNEL_PORT" -t "$DURATION" -u -b "$UDP_RATE" -J \
    > "$OUT_DIR/$scheme.udp.json" 2>&1 || true
  # With -b 0 iperf3 offers far more than the tunnel can carry, so `.end.sum` is the *sender's*
  # view — how fast it wrote into the local socket, not what arrived. Its `lost_percent` is only
  # filled in when the server's report makes it back, and is a flat 0 when it does not, which is
  # exactly when the run went wrong. So take goodput from the receiver's own counters and derive
  # loss from the byte counts, both of which are always right.
  RESULT["$scheme.udp.offered"]="$(jq -r '.end.sum.bits_per_second // 0' "$OUT_DIR/$scheme.udp.json")"
  RESULT["$scheme.udp"]="$(jq -r '.end.sum_received.bits_per_second // 0' "$OUT_DIR/$scheme.udp.json")"
  RESULT["$scheme.udp.loss"]="$(jq -r '
      if (.end.sum.bytes // 0) > 0 and (.end | has("sum_received"))
      then 100 * (1 - ((.end.sum_received.bytes // 0) / .end.sum.bytes))
      else (.end.sum.lost_percent // 0) end' "$OUT_DIR/$scheme.udp.json")"
  if [[ "$(jq -r '.end | has("sum_received")' "$OUT_DIR/$scheme.udp.json" 2>/dev/null)" != "true" ]]; then
    RESULT["$scheme.udp.err"]="${RESULT[$scheme.udp.err]:-no receiver report, udp goodput unknown}"
  fi
  RESULT["$scheme.udp.err"]="$(iperf_error "$OUT_DIR/$scheme.udp.json")"
  [[ -n "${RESULT[$scheme.udp.err]}" ]] && echo "      udp FAILED: ${RESULT[$scheme.udp.err]}"
  stop_stack
}

bench_cpu() {
  local scheme="$1"
  start_stack "$scheme" tcp "$scheme.cpu"

  # Counters for both wstunnel processes together: this is the cost of moving the bytes.
  echo "    perf stat ..."
  perf stat -e task-clock,context-switches,cycles,instructions,branch-misses \
    -p "$(measured_pids)" -o "$OUT_DIR/$scheme.perf-stat.txt" -- \
    iperf3 -c 127.0.0.1 -p "$TUNNEL_PORT" -t "$DURATION" -P "$PARALLEL" -J \
    > "$OUT_DIR/$scheme.cpu.iperf3.json" 2>/dev/null || true

  RESULT["$scheme.cpu.tcp"]="$(jq -r '.end.sum_received.bits_per_second // 0' "$OUT_DIR/$scheme.cpu.iperf3.json" 2>/dev/null || echo 0)"
  RESULT["$scheme.task_clock"]="$(awk '/task-clock/ {gsub(",","",$1); print $1; exit}' "$OUT_DIR/$scheme.perf-stat.txt")"
  RESULT["$scheme.instructions"]="$(awk '/instructions/ {gsub(",","",$1); print $1; exit}' "$OUT_DIR/$scheme.perf-stat.txt")"
  RESULT["$scheme.ctx_switches"]="$(awk '/context-switches/ {gsub(",","",$1); print $1; exit}' "$OUT_DIR/$scheme.perf-stat.txt")"

  # Where that CPU goes. The report is the "nb calls" view: samples per function.
  echo "    perf record (call-graph=$CALL_GRAPH) ..."
  local cg=()
  case "$CALL_GRAPH" in
    none)  cg=() ;;
    dwarf) cg=(-g --call-graph dwarf,16384) ;;   # bigger stack dumps, deep async frames
    *)     cg=(-g --call-graph "$CALL_GRAPH") ;;
  esac
  perf record -F 999 "${cg[@]}" -p "$(measured_pids)" \
    -o "$OUT_DIR/$scheme.perf.data" -- \
    iperf3 -c 127.0.0.1 -p "$TUNNEL_PORT" -t "$DURATION" -P "$PARALLEL" \
    >/dev/null 2>&1 || true
  if [[ -s "$OUT_DIR/$scheme.perf.data" ]]; then
    # Two views: self time says which function burns the cycles, inclusive time says which
    # subsystem does. Tunnel profiles are flat, so the cutoff has to be low to show anything.
    perf report -i "$OUT_DIR/$scheme.perf.data" --stdio --no-children --percent-limit 0.3 \
      > "$OUT_DIR/$scheme.perf-self.txt" 2>/dev/null || true
    perf report -i "$OUT_DIR/$scheme.perf.data" --stdio --children --percent-limit 1 \
      > "$OUT_DIR/$scheme.perf-inclusive.txt" 2>/dev/null || true
    RESULT["$scheme.hot"]="$(grep -m1 -oE '^\s+[0-9.]+%.*\[\.\] .*' "$OUT_DIR/$scheme.perf-self.txt" 2>/dev/null | sed -E 's/^\s+//; s/\s+/ /g' | cut -c1-70 || true)"
  fi

  stop_stack
}

bench_mem() {
  local scheme="$1"
  start_stack "$scheme" tcp "$scheme.mem"

  iperf3 -c 127.0.0.1 -p "$TUNNEL_PORT" -t "$DURATION" -P "$PARALLEL" >/dev/null 2>&1 || true

  RESULT["$scheme.rss_client"]="$(peak_rss_mib "$CLI_PID") MiB"
  if [[ -n "$SRV_PID" ]]; then
    RESULT["$scheme.rss_server"]="$(peak_rss_mib "$SRV_PID") MiB"
  else
    RESULT["$scheme.rss_server"]="remote"
  fi

  if (( USE_DHAT )); then
    # dhat writes its profile when the process leaves main, so ask politely and wait for it.
    echo "    dhat: signalling the client to flush ..."
    kill -INT "$CLI_PID" 2>/dev/null || true
    for _ in $(seq 50); do [[ -s "$OUT_DIR/$scheme.mem.dhat-heap.json" ]] && break; sleep 0.1; done
    RESULT["$scheme.dhat_blocks"]="$(jq -r '.pps | length' "$OUT_DIR/$scheme.mem.dhat-heap.json" 2>/dev/null || echo n/a)"
    RESULT["$scheme.dhat_total"]="$(grep -oE 'dhat: Total: *[0-9,]+ bytes in [0-9,]+ blocks' "$OUT_DIR/$scheme.mem.client.log" 2>/dev/null | head -1 || echo '')"
    RESULT["$scheme.dhat_peak"]="$(grep -oE 'dhat: At t-gmax: *[0-9,]+ bytes in [0-9,]+ blocks' "$OUT_DIR/$scheme.mem.client.log" 2>/dev/null | head -1 || echo '')"
  fi

  stop_stack
}

# ---------------------------------------------------------------------------- drive
echo "wstunnel benchmark  run=$RUN_ID  duration=${DURATION}s  parallel=$PARALLEL"
echo "binary=$WSTUNNEL  artifacts=$OUT_DIR"
if [[ -n "$SERVER_AUTHORITY" ]]; then
  echo "server=$SERVER_AUTHORITY (remote, not measured)"
else
  echo "server=local (spawned per run)"
fi
if [[ -n "$IPERF3_HOST" ]]; then
  echo "iperf3=$IPERF3_HOST:$IPERF3_PORT (remote)"
else
  echo "iperf3=local (spawned per run)"
fi
[[ -n "$CLIENT_ARGS" ]] && echo "client-args=$CLIENT_ARGS"
echo

IFS=',' read -ra SCHEMES <<< "$TRANSPORTS"
for scheme in "${SCHEMES[@]}"; do
  echo "==> $scheme"
  has_mode throughput && bench_throughput "$scheme"
  has_mode cpu        && bench_cpu "$scheme"
  has_mode mem        && bench_mem "$scheme"
done

# ---------------------------------------------------------------------------- summary
echo
echo "──────────────────────────────────────────────────────────────────────"
if has_mode throughput; then
printf "%-10s %14s %10s %16s %14s %10s\n" transport "tcp" "retrans" "udp goodput" "udp offered" "udp loss"
for scheme in "${SCHEMES[@]}"; do
  tcp_cell="$(fmt_bits "${RESULT[$scheme.tcp]:-0}")"
  udp_cell="$(fmt_bits "${RESULT[$scheme.udp]:-0}")"
  [[ -n "${RESULT[$scheme.tcp.err]:-}" ]] && tcp_cell="failed"
  [[ -n "${RESULT[$scheme.udp.err]:-}" ]] && udp_cell="failed"
  printf "%-10s %14s %10s %16s %14s %9s%%\n" "$scheme" \
    "$tcp_cell" \
    "${RESULT[$scheme.tcp.retrans]:-0}" \
    "$udp_cell" \
    "$(fmt_bits "${RESULT[$scheme.udp.offered]:-0}")" \
    "$(printf '%.2f' "${RESULT[$scheme.udp.loss]:-0}")"
done
for scheme in "${SCHEMES[@]}"; do
  [[ -n "${RESULT[$scheme.tcp.err]:-}" ]] && echo "  $scheme tcp: ${RESULT[$scheme.tcp.err]}"
  [[ -n "${RESULT[$scheme.udp.err]:-}" ]] && echo "  $scheme udp: ${RESULT[$scheme.udp.err]}"
done
fi

if has_mode cpu; then
  echo
  if [[ -n "$SERVER_AUTHORITY" ]]; then
    echo "(client process only, the server is remote)"
  fi
  printf "%-10s %14s %16s %14s %16s\n" transport "cpu (ms)" "instructions" "ctx switches" "instr/bit"
  for scheme in "${SCHEMES[@]}"; do
    local_bits="${RESULT[$scheme.cpu.tcp]:-0}"
    instr="${RESULT[$scheme.instructions]:-0}"
    per_bit="$(awk -v i="$instr" -v b="$local_bits" -v d="$DURATION" \
      'BEGIN { if (b>0) printf "%.3f", i/(b*d); else print "n/a" }')"
    printf "%-10s %14s %16s %14s %16s\n" "$scheme" \
      "${RESULT[$scheme.task_clock]:-n/a}" "$instr" "${RESULT[$scheme.ctx_switches]:-n/a}" "$per_bit"
  done
fi

if has_mode mem; then
  echo
  printf "%-10s %18s %18s\n" transport "peak rss client" "peak rss server"
  for scheme in "${SCHEMES[@]}"; do
    printf "%-10s %18s %18s\n" "$scheme" \
      "${RESULT[$scheme.rss_client]:-n/a}" "${RESULT[$scheme.rss_server]:-n/a}"
  done
  if (( USE_DHAT )); then
    echo
    for scheme in "${SCHEMES[@]}"; do
      echo "$scheme heap (client):"
      echo "  ${RESULT[$scheme.dhat_total]:-n/a}"
      echo "  ${RESULT[$scheme.dhat_peak]:-n/a}"
      echo "  ${RESULT[$scheme.dhat_blocks]:-n/a} distinct allocation sites"
    done
    echo "full profiles: $OUT_DIR/*.dhat-heap.json"
    echo "view at https://nnethercote.github.io/dh_view/dh_view.html"
  fi
fi

echo
echo "──────────────────────────────────────────────────────────────────────"
echo "artifacts: $OUT_DIR"
if has_mode cpu; then
  echo "  self time:      $OUT_DIR/<scheme>.perf-self.txt"
  echo "  inclusive:      $OUT_DIR/<scheme>.perf-inclusive.txt"
  echo "  interactive:    perf report -i $OUT_DIR/<scheme>.perf.data"
  if [[ "$CALL_GRAPH" == "none" ]]; then
    echo "  (flat profile only, pass --call-graph fp for call graphs)"
  else
    echo "  callers of X:   perf report -i $OUT_DIR/<scheme>.perf.data --stdio --no-children \\"
    echo "                    -g graph,2,callee --symbol-filter=X"
  fi
fi
(( KEEP_LOGS )) || find "$OUT_DIR" -name '*.log' -size -1k -delete 2>/dev/null || true
