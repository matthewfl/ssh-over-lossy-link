#!/usr/bin/env bash
# Run the full test: proxy + ssh-oll server + client (via --run-client), report latency.
# Requires: ssh-oll built, socat, Python 3.
# Usage: ./run_test.sh [--latency-ms N] [--connections N]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

LATENCY_MS=0
CONNECTIONS=4
PORT=19999
TEST_SOCKET="$SCRIPT_DIR/.test-proxy-socket"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --latency-ms) LATENCY_MS="$2"; shift 2 ;;
    --connections) CONNECTIONS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ ! -x ./ssh-oll ]]; then
  echo "Build ssh-oll first: make ssh-oll"
  exit 1
fi

PROXY_FIFO=""
cleanup() {
  if [[ -n "$PROXY_FIFO" && -p "$PROXY_FIFO" ]]; then
    rm -f "$PROXY_FIFO"
  fi
  pkill -f "ssh-oll --server" 2>/dev/null || true
  rm -f "$SCRIPT_DIR/.test-proxy-socket" "$SCRIPT_DIR/client_err.txt" "$SCRIPT_DIR/proxy.log"
}
trap cleanup EXIT

PROXY_FIFO=$(mktemp -u)
mkfifo "$PROXY_FIFO"

echo "=== ssh-oll latency test ==="
echo "Port: $PORT  Connections: $CONNECTIONS  Extra latency: ${LATENCY_MS}ms"
echo ""

# Start proxy in background; it will block reading server path from stdin (the FIFO).
# With --run-client the proxy spawns the client and measures one-way latency.
export SSH_OLL="$SCRIPT_DIR/ssh-oll"
./test_latency_proxy.py --port "$PORT" --connections "$CONNECTIONS" \
  --unix-path "$TEST_SOCKET" \
  --latency-ms "$LATENCY_MS" --run-client < "$PROXY_FIFO" 2>&1 | tee proxy.log &
PROXY_PID=$!

# Give proxy time to bind and prompt
sleep 1

# Start server; it connects to the proxy's TCP port and prints its Unix socket path
SERVER_PATH=$(./ssh-oll --server 127.0.0.1 "$PORT" 2>&1 | head -1)
if [[ -z "$SERVER_PATH" ]]; then
  echo "Failed to get server socket path"
  kill $PROXY_PID 2>/dev/null || true
  exit 1
fi

# Feed path to proxy so it can connect to the server; proxy then spawns client and measures
echo "$SERVER_PATH" > "$PROXY_FIFO"
rm -f "$PROXY_FIFO"
PROXY_FIFO=""

# Wait for proxy (and test) to finish; timeout 15s in case client connections never arrive
for _ in $(seq 1 15); do
  if ! kill -0 $PROXY_PID 2>/dev/null; then
    break
  fi
  sleep 1
done
pkill -f "test_latency_proxy.py" 2>/dev/null || true
kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true

echo ""
echo "=== Results ==="
if grep -q "One-way latency" proxy.log; then
  grep "One-way latency" proxy.log
  exit 0
else
  echo "No latency line in proxy.log."
  echo "If the proxy hung on 'Waiting for client connection(s)', run the steps manually:"
  echo "  1) ./test_latency_proxy.py --port $PORT --unix-path $TEST_SOCKET --run-client"
  echo "  2) In another terminal: ./ssh-oll --server 127.0.0.1 $PORT (paste path when prompted)"
  echo "  3) Or run client yourself: ./ssh-oll --carrier-cmd 'socat UNIX-LISTEN:\$CARRIER_LOCAL,reuseaddr,fork UNIX-CONNECT:\$CARRIER_REMOTE' --server-socket $TEST_SOCKET --connections $CONNECTIONS localhost"
  tail -5 proxy.log
  exit 1
fi
