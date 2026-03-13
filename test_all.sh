#!/usr/bin/env bash
# test_all.sh — run a suite of ssh-oll integration tests with pass/fail criteria.
#
# Each test exercises test_ssh_oll.py with a different network profile and asserts
# latency / throughput bounds.  Exit code is 0 when all tests pass, non-zero otherwise.
#
# Usage:
#   ./test_all.sh                     # run all tests
#   ./test_all.sh fixed-10ms          # run only the named test(s) (prefix match)
#   ./test_all.sh --auto-rerun-failed # rerun failed tests once (for flaky tests)
#   VERBOSE=1 ./test_all.sh           # always print test output
#   SSH_OLL=./ssh-oll ./test_all.sh   # override binary path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_OLL="${SSH_OLL:-${SCRIPT_DIR}/ssh-oll}"
TEST="${SCRIPT_DIR}/test_ssh_oll.py"
VERBOSE="${VERBOSE:-0}"
AUTO_RERUN_FAILED=0
FILTER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto-rerun-failed)
            AUTO_RERUN_FAILED=1
            shift
            ;;
        *)
            FILTER="$1"
            shift
            break
            ;;
    esac
done

# Simulated SSH-auth latency per new carrier connection (0.3 s).  This exercises
# the connection-establishment path without dominating measured latencies.
# Override with INIT_LATENCY=N to use a different value.
INIT_LATENCY="${INIT_LATENCY:-0.3}"

# ── Counters ────────────────────────────────────────────────────────────────
pass=0
fail=0
skip=0
declare -a failed_names=()

# ── Helpers ─────────────────────────────────────────────────────────────────
run_test() {
    local name="$1"; shift
    local run_test_args=("$@")

    # Apply optional filter
    if [[ -n "$FILTER" && "$name" != "$FILTER"* ]]; then
        ((skip++)) || true
        return
    fi

    local max_attempts=1
    [[ "$AUTO_RERUN_FAILED" == "1" ]] && max_attempts=4

    local attempt=1
    local exit_code=1

    while [[ $attempt -le $max_attempts ]]; do
        local logfile
        logfile="$(mktemp /tmp/ssh-oll-test-XXXXXX.log)"
        printf "  %-52s " "$name"

        # Pick a random high port (32768–60999) to avoid TIME_WAIT conflicts between
        # back-to-back tests that all default to port 2222.
        local tcp_port=$(( RANDOM % 28232 + 32768 ))

        # Per-test initial connection latency override: if the first remaining arg is
        # "--init-latency-override N", consume it and use N instead of INIT_LATENCY.
        local test_init_latency="$INIT_LATENCY"
        local py_args=("${run_test_args[@]}")
        if [[ "${py_args[0]:-}" == "--init-latency-override" ]]; then
            test_init_latency="${py_args[1]}"
            py_args=("${py_args[@]:2}")
        fi

        exit_code=0
        python3 "$TEST" --ssh-oll-path "$SSH_OLL" \
            --tcp-port "$tcp_port" \
            --initial-connection-latency "$test_init_latency" \
            "${py_args[@]}" >"$logfile" 2>&1 || exit_code=$?

        if [[ $exit_code -eq 0 ]]; then
            [[ $attempt -gt 1 ]] && echo "PASS (rerun)" || echo "PASS"
            ((pass++)) || true
            rm -f "$logfile"
            break
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            echo "FAIL (rerunning...)"
            if [[ "$VERBOSE" == "1" ]]; then
                sed 's/^/    | /' "$logfile"
            fi
            rm -f "$logfile"
            ((attempt++))
            sleep 2
        else
            echo "FAIL  (exit $exit_code)"
            ((fail++)) || true
            failed_names+=("$name")
            if [[ $exit_code -ne 0 || "$VERBOSE" == "1" ]]; then
                sed 's/^/    | /' "$logfile"
            fi
            rm -f "$logfile"
            break
        fi
    done

    # Brief pause: lets the previous ssh-oll server daemon exit on backend EOF and
    # gives the OS time to release file descriptors and socket resources.
    sleep 2
}

# ── Build check ─────────────────────────────────────────────────────────────
if [[ ! -x "$SSH_OLL" ]]; then
    echo "ERROR: ssh-oll binary not found at $SSH_OLL" >&2
    echo "       Run 'make' first, or set SSH_OLL=/path/to/ssh-oll" >&2
    exit 1
fi

echo "ssh-oll binary: $SSH_OLL"
echo "Running tests..."
echo ""

# ============================================================================
# 1. Fixed low latency — the baseline.
#    Observed: avg ~11 ms, max ~15 ms, ~2800 packets/60 s.
#    Post-warmup avg should settle near 2× the injected latency (both directions).
# ============================================================================
run_test "fixed-10ms" \
    --continuous --continuous-duration 60 \
    --latency-ms 10 \
    --test-max-latency        200 \
    --test-max-average-latency  50 \
    --test-max-average-latency-after-warmup 30 \
    --test-min-packets         500

# ============================================================================
# 2. Fixed medium latency — 100 ms one-way (typical WAN hop).
#    Observed: avg ~101 ms, max ~103 ms, ~600 packets/60 s.
# ============================================================================
run_test "fixed-100ms" \
    --continuous --continuous-duration 60 \
    --latency-ms 100 \
    --test-max-latency        500 \
    --test-max-average-latency 250 \
    --test-max-average-latency-after-warmup 220 \
    --test-min-packets         300

# ============================================================================
# 3. Bimodal random: 95 % at 10 ms, 5 % at 100 ms.
#    Simulates a fast link with infrequent high-latency chunks (e.g. TCP
#    retransmits on the underlying carrier network).
#    Observed: avg ~15 ms, max ~111 ms, ~3500 packets/60 s.
# ============================================================================
run_test "random-10ms-base-100ms-spike-5pct" \
    --continuous --continuous-duration 60 \
    --latency-random \
    --latency-random-low-ms  10  \
    --latency-random-high-ms 100 \
    --latency-random-pct     5   \
    --test-max-latency        500 \
    --test-max-average-latency 100 \
    --test-max-average-latency-after-warmup 35 \
    --test-min-packets        1000

# ============================================================================
# 4. Bimodal random: 95 % at 100 ms, 5 % at 1000 ms.
#    Simulates a WAN link with occasional high-latency bursts.
#    Observed: avg ~107 ms, max ~905 ms, ~730 packets/90 s.
# ============================================================================
run_test "random-100ms-base-1000ms-spike-5pct" \
    --continuous --continuous-duration 90 \
    --latency-random \
    --latency-random-low-ms  100  \
    --latency-random-high-ms 1000 \
    --latency-random-pct     5    \
    --test-max-latency       2000 \
    --test-max-average-latency 350 \
    --test-max-average-latency-after-warmup 250 \
    --test-min-packets        400

# ============================================================================
# 5. Bimodal random: 95 % at 100 ms, 5 % at 2000 ms.
#    The harshest pure-latency test; validates RS redundancy adaptation.
#    Observed: avg ~175 ms, max ~2001 ms, ~1200 packets/120 s.
# ============================================================================
run_test "random-100ms-base-2000ms-spike-5pct" \
    --continuous --continuous-duration 120 \
    --latency-random \
    --latency-random-low-ms  100  \
    --latency-random-high-ms 2000 \
    --latency-random-pct     5    \
    --test-max-latency       5000 \
    --test-max-average-latency 500 \
    --test-max-average-latency-after-warmup 300 \
    --test-min-packets        600

# ============================================================================
# 6. Rare connection death — 0.2 % per-packet probability.
#    RS + retransmit should recover within a few seconds.
#    50 ms base latency so the connection isn't trivially fast.
#    Warmup 30s; post-warmup avg should be close to base latency once settled.
# ============================================================================
run_test "connection-death-0.002-t2c" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --continuous-tcp-to-client-only \
    --latency-ms 50 \
    --connection-death-probability 0.002 \
    --test-max-latency        10000 \
    --test-max-average-latency  800 \
    --test-max-average-latency-after-warmup 300 \
    --test-min-packets           40

run_test "connection-death-0.002-c2t" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --continuous-client-to-tcp-only \
    --latency-ms 50 \
    --connection-death-probability 0.002 \
    --test-max-latency        10000 \
    --test-max-average-latency  800 \
    --test-max-average-latency-after-warmup 300 \
    --test-min-packets           40

# ============================================================================
# 7. Moderate connection death — 1 % per-packet probability.
#    Connections die frequently; retransmit and carrier-floor logic exercised.
#    Run each direction separately to avoid bidirectional livelock under
#    high death rates (combined traffic kills carriers too rapidly).
# ============================================================================
run_test "connection-death-0.01-t2c" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --continuous-tcp-to-client-only \
    --latency-ms 50 \
    --connection-death-probability 0.01 \
    --test-max-latency        20000 \
    --test-max-average-latency 1500 \
    --test-max-average-latency-after-warmup 600 \
    --test-min-packets           15

run_test "connection-death-0.01-c2t" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --continuous-client-to-tcp-only \
    --latency-ms 50 \
    --connection-death-probability 0.01 \
    --test-max-latency        20000 \
    --test-max-average-latency 1500 \
    --test-max-average-latency-after-warmup 600 \
    --test-min-packets           15

# ============================================================================
# 8. Combined: latency spikes + connection death.
#    Both RS adaptation and retransmit recovery must work simultaneously.
#    T2C only to avoid bidirectional livelock under combined stress.
# ============================================================================
run_test "combined-latency-and-death" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --continuous-tcp-to-client-only \
    --latency-random \
    --latency-random-low-ms  50  \
    --latency-random-high-ms 500 \
    --latency-random-pct     5   \
    --connection-death-probability 0.005 \
    --test-max-latency        20000 \
    --test-max-average-latency 1500 \
    --test-max-average-latency-after-warmup 400 \
    --test-min-packets           20

# ============================================================================
# 9b. Stop-then-recover scenario — carriers go dead (but stay open) for a full
#     30-second blackout, with short-lived replacement carriers that also die,
#     then the link recovers after 60 seconds and new carriers work again.
#     This emulates Wi-Fi being turned off and then back on.
#     We only assert that the connection survives and moves a minimum amount of
#     data, and that post-recovery average latency is bounded once things have
#     stabilised again.
# ============================================================================
run_test "wifi-stop-then-recover" \
    --init-latency-override 0.05 \
    --continuous --continuous-duration 90 \
    --latency-ms 50 \
    --scenario-stop-recover \
    --warmup-seconds 70 \
    --test-max-latency        120000 \
    --test-max-average-latency-after-warmup 2000 \
    --test-min-packets           20

# ============================================================================
# 9c. Stop-then-recover HEAVY — concurrent writers flood ≥60 KB per direction
#     through the same 30-second blackout, then verify every byte is delivered
#     after recovery.  Tests both SMALL-path (small chunks) and RS-path (large
#     chunks) retransmission after a prolonged link outage.
#     This test is EXPECTED TO FAIL until ssh-oll's retransmit-after-reconnect
#     logic is confirmed correct.
# ============================================================================
run_test "wifi-stop-then-recover-heavy" \
    --init-latency-override 0.05 \
    --scenario-wifi-heavy \
    --continuous-duration 120 \
    --latency-ms 50 \
    --scenario-stop-recover \
    --wifi-heavy-min-bytes 61440

# ============================================================================
# 10. Auto-adapt disabled (--no-auto) — fixed RS and carrier count.
#    Verifies the non-adaptive path delivers data on a clean 10 ms link.
#    Thresholds are relaxed compared to adaptive mode (no RS tuning).
# ============================================================================
run_test "no-auto-adapt-fixed-10ms" \
    --continuous --continuous-duration 60 \
    --latency-ms 10 \
    --test-max-latency       1000 \
    --test-max-average-latency 300 \
    --test-min-packets         50 \
    --extra-client-args --no-auto

# ============================================================================
# 11. Integrity-only — no latency/throughput criteria; just verify that no
#     payload corruption occurs across a 15-second run.
# ============================================================================
run_test "sanity-integrity" \
    --continuous --continuous-duration 15 \
    --latency-ms 5

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
total=$(( pass + fail + skip ))
echo "Results: ${pass} passed  ${fail} failed  ${skip} skipped  (${total} total)"
if [[ ${#failed_names[@]} -gt 0 ]]; then
    echo "Failed tests:"
    for n in "${failed_names[@]}"; do
        echo "  - $n"
    done
fi
echo "────────────────────────────────────────────────────────"

[[ $fail -eq 0 ]]
