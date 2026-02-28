#!/usr/bin/env bash
# Example script for testing ssh-oll over a lossy link using Linux tc + netem.
# Usage: ./test.sh [--apply] [--loss PCT] [--delay MS] [--help]
#   --apply   Actually run tc (requires root). Default is dry-run / print commands only.
#   --loss    Packet loss percentage (default 5).
#   --delay   One-way delay in ms (default 50).
#   --help    Show this help.
#
# Prerequisites: ssh-oll built and installed; SSH key access to a test host.
# The script demonstrates configuring netem on the default interface (or LOOPBACK
# for local tests). For real lossy-link testing, run the server on a remote host
# and apply tc on the client's outgoing interface (or both sides).

set -e

LOSS=5
DELAY=50
APPLY=false
# Default: use loopback for local testing; override with IFACE=eth0 ./test.sh
IFACE="${IFACE:-lo}"

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \?//'
    echo "Example (dry-run): $0"
    echo "Example (apply tc, 10% loss, 100ms delay): $0 --apply --loss 10 --delay 100"
    echo "Example (custom interface): IFACE=eth0 $0 --apply"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply) APPLY=true ;;
        --loss)  LOSS="$2"; shift ;;
        --delay) DELAY="$2"; shift ;;
        --help)  usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

echo "=== ssh-oll lossy-link test (tc + netem) ==="
echo "Interface: $IFACE  Loss: ${LOSS}%  Delay: ${DELAY}ms  Apply: $APPLY"
echo ""

# Commands to add loss and delay (ingress is harder; we affect egress only unless using ifb).
# For a quick local test, applying to lo affects both directions on loopback.
ADD="tc qdisc add dev $IFACE root netem loss ${LOSS}% delay ${DELAY}ms"
DEL="tc qdisc del dev $IFACE root netem 2>/dev/null || true"

echo "Add netem (run as root):"
echo "  $ADD"
echo ""
echo "Remove netem later:"
echo "  $DEL"
echo ""

if [[ "$APPLY" == true ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "Error: --apply requires root. Run: sudo $0 --apply $*"
        exit 1
    fi
    $DEL
    $ADD
    echo "Netem applied. Remove with: $DEL"
    echo ""
    echo "In another terminal, connect through ssh-oll, e.g.:"
    echo "  ssh -o ProxyCommand='ssh-oll lossy-ssh-host' user@lossy-ssh-host"
    echo "Or use your ~/.ssh/config Host that uses ProxyCommand ssh-oll."
    echo ""
    read -p "Press Enter to remove netem and exit..."
    $DEL
    echo "Netem removed."
else
    echo "Dry-run. To apply these rules, run: sudo $0 --apply --loss $LOSS --delay $DELAY"
fi
