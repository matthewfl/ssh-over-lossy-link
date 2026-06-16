# ssh-oll refactoring plan

A staged, behavior-preserving plan to reduce the client/server duplication that is the
root cause of the bug class just fixed (B1: the client and server kept separate,
drifting copies of the dead-carrier detection logic). The aim is to make the shared
machinery exist **once**, be **unit-testable**, and stop hiding correctness bugs.

## Goals
- Remove the parallel reimplementations between `client.cc` and `server.cc`.
- Make the trickiest logic (retransmit/re-encode, carrier health, RTT/timeouts)
  shared and directly unit-tested.
- Keep the code single-threaded, dependency-free, and epoll-based — **no behavior
  change**, no protocol change, no performance rewrite.

## Non-goals (explicitly out of scope)
- No wire-protocol changes (the format in `ssholl.h` / README stays fixed).
- No threading, no async framework, no new third-party libraries.
- No tuning of timeouts/adaptation thresholds (that is separate work; a pure refactor
  must reproduce current values exactly).

## Guiding principles
1. **Behavior-preserving.** Every step compiles, passes `test_reed_solomon` +
   `test_packet_io`, and passes the integration suite. Diff should be move-not-rewrite
   wherever possible.
2. **Tests before moves.** Add unit coverage for a piece of logic *before* relocating
   it, so the move is guarded.
3. **Small, independently-revertable steps**, one commit each, suite green between.
4. **Follow the existing good pattern.** `carrier_adapt.{h,cc}` is already the model:
   pure logic, shared by both sides, no I/O. Extend that pattern; don't invent a new one.

## Why this matters (evidence)
- `client.cc` ≈ 1985 lines, `server.cc` ≈ 1268 lines — largely parallel.
- Duplicated, defined separately in each file: `now_ns`, `scaled_ns`,
  `get_effective_rtt_ns`, `struct UnackedItem`, the heavy-backlog calc, the ping /
  dead-detect block, carrier add/reap, and the `flush_carrier_writes` wrapper.
- The RS retransmit/re-encode loop is copy-pasted ~4 times: `client.cc:1015` &
  `client.cc:1698`, `server.cc:657` & `server.cc:991`. This is the code that must
  preserve the original `(n, k, block_size)` or the receiver silently drops shards.
- ~34 raw `…ULL` nanosecond timeout literals in `client.cc`, ~23 in `server.cc`,
  several duplicated across both.
- ~60 `if (dbg)` sites interleave logging with control flow — B1 was logic accidentally
  trapped inside one such block.

---

## Phase 0 — Build the safety net (do first)
The integration suite is slow (~20 min) and the heavy/blackout scenarios are
timing-flaky, so it is a poor guard for a large refactor. Strengthen fast, deterministic
coverage first.

- [ ] Add `test_carrier_adapt.cc` (none exists today) covering `run_adapt`, `merge`,
      `compute_from_deques`, `assess_carriers` — the pure logic that Phase 3 will lean on.
- [ ] Extend `test_packet_io.cc` with a retransmit-shaped case: deliver a partial RS
      group, then feed the *re-encoded* shards (same id/n/k) and assert it completes —
      locks in the invariant Phase 2 depends on.
- [ ] Add a `make check` target that runs all unit tests, and a single fast
      integration smoke (e.g. `sanity-integrity`) so a quick guard exists between steps.

## Phase 1 — Shared timing / RTT / constants (low risk)
Create `net_util.{h,cc}` (or `ssholl_time.h`) in `namespace ssholl`.

- [ ] Move `now_ns()` and a `scaled_ns(mult, min, max, rtt_ns)` free function.
- [ ] Move `get_effective_rtt_ns` as a small struct/functor parameterized by the RTT
      sample deque + optional peer-reported RTT + cold-start hint (client and server
      differ only in those inputs).
- [ ] Name the timeout constants (replace the raw `…ULL` literals): e.g.
      `kPingIdle`, `kPingFailClient`/`kPingFailServer`, `kDeadIdle`, `kGraceAfterConnect`,
      `kRetransmitCheckInterval`, `kRsStale`, `kGlobalIdleMin/Max`, `kSuggestCloseMinInterval`.
      Keep them as the *exact* current values; this step changes names only.
- [ ] Move `struct UnackedItem` (currently defined twice) into a shared header.

## Phase 2 — Shared retransmit/encode helper (highest value)
This is the most duplicated *and* most dangerous code. Extract one helper used by all
four sites and both directions.

- [ ] Add e.g. `packet_io::encode_unacked_item(std::vector<uint8_t>& out, uint64_t id,
      const UnackedItem&)` that, for a SMALL item appends the packet, and for an RS item
      re-encodes parity from `ui.data` using the **stored** `ui.n/ui.k/ui.block_size`
      and appends all `n` shards. (The carrier_id bookkeeping — `small_sent_on` /
      `rs_shard_sent_on` — stays at the call site, since it depends on which carriers are
      chosen, but the byte-production becomes shared.)
- [ ] Replace the four hand-rolled re-encode blocks with calls to it.
- [ ] Unit-test the helper directly (feed its output back through
      `process_carrier_read` and assert decode/delivery).

## Phase 3 — Shared carrier-health orchestration (fixes the B1 class)
`carrier_adapt::assess_carriers` already centralizes the *decision*; the *orchestration*
(send PING when idle, detect stale PING → SUGGEST_CLOSE/reap, compute heavy-backlog) is
still duplicated and is exactly where client/server drifted.

- [ ] Extract the ping/keepalive + stale-ping detection into a shared function returning
      a plan (which fds to ping, which to suggest-close/reap), leaving the actual
      buffer-append / close to the caller (the side-effect policy differs: server only
      suggests, client closes).
- [ ] Extract the heavy-backlog predicate.
- [ ] This guarantees the two sides cannot silently diverge again the way B1 did.

## Phase 4 — Tame debug logging
- [ ] Add a `LOG(dbg, fmt, …)` helper (macro or small inline) so a log line is one call,
      not an `if (dbg) fprintf(...)` block wrapped around — or worse, *around* — control
      flow. Sweep the ~60 sites. This structurally prevents the B1 mistake (logic trapped
      inside a debug guard).

## Phase 5 — Optional: structural split (larger, do last)
Only if Phases 1–4 land cleanly and the appetite is there.
- [ ] Introduce an `Endpoint`/`CarrierSet` type owning `carriers`, `reassembly`,
      `rs_pending`, `unacked`, `next_send_id`, `next_deliver_id`, with `feed_read`,
      `encode_outgoing`, `flush`, `retransmit_due`, `assess_health` methods.
- [ ] `run_client`/`run_server` become thin: an event loop plus the policy differences
      (client launches SSH carriers and is the master; server has a backend socket and
      only suggests closes). Break each giant function into named periodic-task methods.

---

## Sequencing & risk
- **Order:** 0 → 1 → 2 → 3 → 4, each its own commit; 5 is optional and last.
- Phases 1–2 are mechanical and low-risk (move + de-dup). Phase 3 changes the
  most behavior-adjacent code — after it, **always** run `wifi-stop-then-recover-heavy`
  and `wifi-double-blackout-heavy` (the scenarios most sensitive to carrier-health
  timing), not just the fast tests.
- Rollback is per-commit; nothing here is a big-bang rewrite.
- Watch for: accidental change of a timeout value during constant-naming (Phase 1);
  losing the `(n,k,block_size)` preservation in the retransmit helper (Phase 2) — the
  extended `test_packet_io` case guards this.

## Definition of done
- No logic defined twice across `client.cc`/`server.cc` for: timing, RTT, retransmit
  encode, carrier-health, heavy-backlog.
- Shared logic has unit tests; `make check` is green.
- Full integration suite passes (including the heavy/blackout scenarios) with no
  behavior change vs. this branch.
