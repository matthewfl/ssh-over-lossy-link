# ssh-oll — TODO / progress

Tracking for the disconnect/reconnect robustness pass. Detailed analysis lives in
[BUGS.md](BUGS.md).

## Done
- [x] Deep read of client/server/packet_io/carrier_adapt for reconnect-path bugs.
- [x] **B1** — client PING-timeout dead-carrier reaper no longer gated behind `--debug`
      (was dead code in production; server side was already correct). `client.cc`.
- [x] **B2** — RS decode failure no longer erases the pending group (was a latent
      permanent-stall). `packet_io.cc`.
- [x] **B3** — send a cumulative catch-up ACK when a carrier (re)connects so a peer
      stops retransmitting already-delivered data forever on a quiet stream after a
      lost-ACK reconnect. `client.cc` + `server.cc`.
- [x] **B4** — fixed `next_rr` double-advance in the client EOF-drain (round-robin
      skew only). `client.cc`.
- [x] **B5** — README/comments brought in line with code: `next_deliver_id` is never
      jumped past a gap; added `CLIENT_METRICS` (kind 11); corrected keepalive-ping
      thresholds and documented the dead-but-open PING-timeout reap.
- [x] New deterministic unit test `test_packet_io.cc` (wired into Makefile + `all`)
      covering out-of-order delivery, duplicate-drop on retransmit, gap-blocking, and
      RS decode/extra-shard. Run with `./test_packet_io`.
- [x] Verified no regression: `test_reed_solomon`, `test_packet_io`, `sanity-integrity`,
      `wifi-stop-then-recover-heavy` all green after fixes.
- [x] **Reproduced + fixed a real reconnect failure:** `wifi-double-blackout-heavy`
      failed 2/2 on the original code (recovery stalls, tail bytes never drain) and
      passes 3/3 after the fixes. Root cause was B1 (the disabled dead-carrier reaper);
      see BUGS.md "Headline result".

## Optional / follow-ups
- [x] **RTT-sample skew after a long blackout** — FIXED (B7 server, B8 client; see
      BUGS.md "Round 2"). Turned out impactful, not minor: it inflated every RTT-scaled
      timeout and was the main driver of `wifi-double-blackout-heavy` flakiness. Server:
      re-stamp `ack_send_time_ns` on retransmit. Client: cross-carrier cumulative-ACK
      clear + Karn's algorithm (skip RTT for retransmitted ids).
- [ ] `reassembly`/`rs_pending` can grow unbounded on the receiver during a sustained
      one-directional gap (sender keeps producing higher ids while a low id is missing).
      In practice the gap is refilled quickly by retransmit; consider a hard cap that
      forces a clean close rather than memory growth under adversarial loss.
- [ ] Asymmetric adaptive idle timeouts: with `--reconnect-timeout 0` (adaptive), the
      two ends derive `global_idle_ns` from their own RTT, so the server can exit before
      the client gives up trying to reconnect to a now-dead socket. Consider having the
      server use `max(local, client-reported)` RTT, or biasing the server's timeout
      longer than the client's.
- [ ] A targeted integration scenario for B1 (continuous one-way send into a
      dead-but-open link with no healthy peer) — skipped for now because it is hard to
      make non-flaky with the current harness (it self-throttles on un-ACKed inflight).
