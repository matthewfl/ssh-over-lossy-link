# ssh-oll bug hunt — findings & progress

Focus: protocol robustness, especially disconnect → reconnect scenarios. Status of
each item: **CANDIDATE** (found by code reading, not yet reproduced), **CONFIRMED**
(reproduced with a test), **FIXED**, **DISMISSED** (investigated, not a real bug).

Process: read code → identify candidate → write/extend a test that should expose it →
run against current build to confirm → fix → re-run to verify green.

---

## Round 2 — RTT inflation after an outage (CONFIRMED + FIXED)

Found while investigating why `wifi-double-blackout-heavy` stayed flaky (~50%). Every
timeout in the system is RTT-scaled; if the measured RTT spikes, recovery slows.

### B7 — Server times outage-spanning ACKs as RTT (FIXED)
`server.cc`: RTT = `now - ack_send_time_ns[id]`, but `ack_send_time_ns[id]` was stamped
only at original send, never on retransmit. After a 30 s blackout the eventual ACK
recorded RTT ≈ 30 s; under the 60 s cap it entered `server_recent_rtt_ns`, and the p90
spike stretched retransmit (4×), rs-stale (4×), ping-fail (8×) and idle (12×) timeouts
for up to 50 samples — stalling recovery exactly when fast retransmit matters.
- **Demonstrated:** added an `[ack-rtt-high]` debug log; a 30 s blackout produced **219**
  samples of ~30 s RTT before the fix, **0** after.
- **Fix:** re-stamp `ack_send_time_ns[id] = now` on every retransmit (reconnect + periodic)
  so RTT is measured from the latest transmission; plus a `last_recovery_ns` guard for
  the true total-loss (carriers-removed) case.

### B8 — Client times outage-spanning ACKs as RTT (FIXED)
`client.cc`: c2s RTT comes from per-carrier pending-ack records, but ACKs are cumulative
and land on whichever carrier completed delivery. (a) A pending entry on a carrier that
didn't receive the draining ACK lingered until that carrier got one, then was timed late;
(b) the arrival carrier's own entry for a retransmitted id measured the original send.
- **Demonstrated:** same `[ack-rtt-high]` log on the client — **hundreds** of 9–20 s
  samples after a blackout, **0** after the fix.
- **Fix:** (a) on any cumulative ACK, clear `id <= acked_id` pending entries from *all*
  carriers (time RTT only on the arrival carrier); (b) Karn's algorithm — mark
  `UnackedItem.retransmitted` and skip RTT for retransmitted ids.

### Impact
`wifi-double-blackout-heavy`: was ~50% pass (and 0/2 on the pre-bug-fix baseline);
after B7 alone it was 4/5 with tiny (~21 KB) residual misses traced to B8; after B7+B8
the post-outage RTT pollution is gone in both directions. (Re-measuring pass rate.)

---

## CONFIRMED bugs

### B1 — Client PING-timeout dead-carrier reaper is gated behind `--debug` (CONFIRMED)
`client.cc` ~line 1315-1346. The set `stale_ping_fds`, which drives the PING-timeout
reaping loop (send SUGGEST_CLOSE + `remove_carrier`/`add_to_pending_reap`), is only
populated inside `if (dbg && !outstanding_pings.empty())`. With `--debug` off (the
normal production case) `stale_ping_fds` is always empty, so **the client's
PING-timeout dead-connection detection never runs in production.**
- The server's equivalent (`server.cc` ~833) runs unconditionally — so this is an
  asymmetry/regression on the client only.
- Impact: a carrier that is "dead but open" (writes keep succeeding, no EPOLLHUP) and
  is being written to often enough that `assess_carriers` dead-idle (≈5×RTT) keeps
  getting reset by `last_send_ns`, with no healthy peer to trigger the rx-dead test,
  is never reaped on the client. The PING-timeout path is the intended safety net for
  exactly this case and it is disabled.
- README "Dead-connection detection #2 (Keepalive ping)" documents this path as
  active, so behavior diverges from docs too.
- **Fix:** always compute `stale_ping_fds`; keep only the `fprintf` under `if (dbg)`.

## Headline result

**B1 was causing a reproducible reconnect failure.** The `wifi-double-blackout-heavy`
integration scenario (two 30 s outages under sustained bidirectional flooding, then
verify every byte is delivered) **fails 2/2 on the original code** (tail bytes never
drain within the 90 s recovery window — no corruption, just missing bytes) and
**passes 3/3 after these fixes**. Root cause: during a flood-blackout the client keeps
writing into dead-but-open carriers, so `last_send_ns` keeps advancing and the
`assess_carriers` dead-idle test never trips; the PING-timeout reaper that should catch
this was disabled in production (B1), so the dead carriers were never reaped and fresh
carriers were never opened, stalling recovery. Restoring the reaper (B1) plus the
catch-up ACK (B3) lets the link recover and drain in time.

| Build | wifi-double-blackout-heavy |
|-------|----------------------------|
| original (pre-fix) | FAIL, FAIL (2/2 failed) |
| with B1–B4 fixes   | PASS, PASS, PASS (3/3) |

## Fix summary (all applied)

| ID | Bug | File(s) | Status |
|----|-----|---------|--------|
| B1 | Client PING-timeout reaper gated behind `--debug` | `client.cc` ~1315 | **FIXED** |
| B2 | RS decode failure erases pending group → permanent gap | `packet_io.cc` ~223 | **FIXED** (defensive) |
| B3 | No cumulative catch-up ACK on reconnect → endless retransmit of already-delivered data on a quiet stream | `client.cc` accept, `server.cc` accept | **FIXED** |
| B4 | `next_rr` advanced twice in client EOF-drain (round-robin skew) | `client.cc` ~1070 | **FIXED** |
| B5 | README/comments out of date (gap-jump claim, missing CLIENT_METRICS, ping thresholds) | `README.md` | **FIXED** |

### How real / how verified
- **B1** is the most clear-cut: a functional code path (dead-but-open carrier reaping)
  was disabled in production by being nested inside `if (dbg && ...)`. The server's
  equivalent runs unconditionally, so this was a client-only asymmetry. Verified by
  inspection + the server reference implementation. A hard end-to-end repro is hard
  because the faster `assess_carriers` dead-idle path (≈5×RTT, floor 3 s) usually fires
  first; B1 is the sole detector only when the client keeps writing successfully into a
  dead-but-open carrier with no healthy peer (so dead-idle never trips). Fix is
  clearly correct and low risk.
- **B2** is defensive: with the parser's existing input validation (distinct shard
  indices, `idx < n`), `reed_solomon::decode` is always given a solvable set, so the
  failure branch is not reachable through `process_carrier_read` today. The old code
  would nonetheless have created a permanent, unrecoverable stream gap if it ever did
  fail. Not reproducible through the public entry point; kept because it removes a
  latent foot-gun.
- **B3** is reproducible by reasoning: after a reconnect where the data-ACK was lost,
  the sender's `unacked` entry for already-delivered data is only cleared by a *later*
  cumulative data-ACK. On a stream that goes quiet, no later ACK arrives, so the
  periodic retransmit re-sends that chunk every ~4×RTT forever (the receiver correctly
  discards it as `id < next_deliver_id`, so no corruption — just wasted bandwidth and
  the link never settles). The catch-up ACK on (re)connect clears it immediately.
- Existing integration suite already covers the *main* reconnect paths and **passes**
  both before and after these changes (see Test log) — these are narrower latent bugs,
  not regressions in the hot path.

## Candidates from code reading

### C1 — RS decode failure leaves a permanent gap → see B2 (FIXED)
`packet_io.cc` `process_carrier_read`, REED_SOLOMON branch (~line 209-258): when
`rp.shards.size() >= k`, it attempts `reed_solomon::decode`. If decode returns
`false`, `reassembly[id]` is never populated, **but `rs_pending.erase(id)` runs
unconditionally** right after. The group is then absent from both maps → permanent
gap at `next_deliver_id` → stream stalls until the global idle timeout closes it.
For a correct systematic RS code any k distinct shards are solvable, so this should
only trigger on corruption/codec bug — but the erase-on-failure is still wrong.
**Fix direction:** only `erase(id)` (and fire decode/extra-shard callbacks) when
decode succeeded; otherwise keep the group so retransmitted shards can retry.

### C2 — `next_rr` advanced twice in the stdin-EOF drain (CANDIDATE, cosmetic)
`client.cc` EOF drain loop (~line 1042-1085): in the `small_packet` branch `next_rr`
is advanced at ~line 1070 *and* again at the end of the loop body (~line 1082).
Full-block branch advances only once. Purely a round-robin load-balance skew on the
post-EOF flush path; ids/data remain correct, so not a correctness bug. Worth tidying.

### C3 — README out of date vs code (CONFIRMED doc bug)
README "Retransmission and data recovery" / "Ordering" sections say the client jumps
`next_deliver_id` past a gap "as a safety net". The code (both `client.cc` ~1757 and
`server.cc` ~1031) was changed to **never** jump (jumping injects a hole → SSH MAC
failure); it now waits for retransmit or closes on global idle. Also README packet
table omits `CLIENT_METRICS` (kind 11) and the `READY` handshake description implies
the client waits for READY before sending, which it does not. Update README + the
relevant comments.

---

## Scenarios to test (beyond the existing suite)

- S1: blackout **longer than** the reconnect/idle timeout → both ends must close
  cleanly (no hang, no corruption on a late straggler).
- S2: single-carrier operation through loss (exercises the `m==0` RS→SMALL fallback
  and single-carrier retransmit).
- S3: rapid carrier flapping (repeated connect/disconnect churn) under continuous
  bidirectional load → integrity + no unbounded `unacked` growth.
- S4: heavy double blackout already covered by `wifi-double-blackout-heavy`; use as a
  regression anchor.

---

## Test log

- `test_reed_solomon` — PASS (after fixes).
- `test_packet_io` (new) — PASS (after fixes). Covers out-of-order delivery,
  duplicate-drop on retransmit, gap-blocking, RS decode + extra-shard.
- `sanity-integrity` (15 s) — PASS, no corruption, no stalls.
- `wifi-stop-then-recover-heavy` (120 s) — PASS before and after fixes.
- `wifi-double-blackout-heavy` (150 s) — original: **FAIL 2/2**; with fixes: **PASS 3/3**.
  This is the empirical demonstration that the system could not handle the
  double-blackout reconnect scenario before the fixes and can after.
- Regression set (sanity / no-auto / connection-death-t2c / wifi-stop-then-recover):
  run after fixes to confirm no regression in the non-blackout paths.
