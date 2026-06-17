# Proposal: probability-bounded carrier count & RS redundancy

Status: proposal / not yet implemented. Motivated by carrier count climbing to ~150
on a 300–500 ms RTT, 1–5 % loss link (all adds `reason=redundancy_pressure`).

## 1. Why it runs away today

`redundancy_pressure` (client.cc) adds one carrier every 25 s whenever
`effective_rs_redundancy > 0.4`. In `auto_adapt` the **server owns** the redundancy
value and pushes it via `SERVER_CONFIG`; the client's local `-0.02` nudge per add is
overwritten right back.

The fatal gap: **the server computes redundancy from link struggle but ignores the
carrier count.** RS redundancy is a *fraction* (parity ÷ data) set by the loss rate;
adding carriers does not change the loss rate, so the fraction never drops below 0.4,
so the trigger never clears. The only stop is the hard `max_connections` cap. On any
persistently lossy link the system therefore grows to the cap.

This is backwards: as shown below, **adding carriers should let you LOWER redundancy**,
not hold it fixed.

## 2. The model

One ordered SSH byte stream is cut into blocks. Each block is an RS group of `n`
shards = `k` data + `m` parity, one shard per carrier; any `k` of `n` reconstruct it.
The block is delivered the instant `k` shards arrive. If **more than `m`** of the `n`
shards are *late* (lost, or stuck behind a TCP retransmit on their carrier ≈ 1 RTT),
fewer than `k` arrive promptly and the stream **stalls** for a retransmit — a
head-of-line block of ~1 RTT (300–500 ms here, which is why we care).

Let `q` = probability a given shard is late (≈ per-carrier packet-loss/recovery
probability), assumed roughly independent across carriers (separate TCP connections).
The number of late shards `L ~ Binomial(n, q)`, and

```
P(stall) = P(L > m) = Σ_{i=m+1}^{n} C(n,i) q^i (1-q)^(n-i)
```

**Goal:** choose `(n, m)` so `P(stall) ≤ ε`, with `ε = 0.001` (0.1 %). For a given `n`
and `q`, pick the smallest `m` that satisfies it; redundancy `r = m / (n-m)`.

Normal approximation (gives the intuition):
`m ≈ n·q + z·√(n·q(1-q))`, `z = Φ⁻¹(1-ε) ≈ 3.09`.
So `m/n → q` and `r → q/(1-q)` as `n → ∞`: with many carriers you need only ~the raw
loss rate in parity; with few carriers the `√n` safety margin dominates and you need a
lot.

## 3. Minimal redundancy vs. carriers (ε = 0.1 %)

`r = m/k` needed to hold the 0.1 % stall bound:

| n | q=1% | q=3% | q=5% |
|----:|----:|----:|----:|
| 10  | 0.25 | 0.43 | 0.67 |
| 15  | 0.15 | 0.25 | 0.36 |
| 20  | 0.18 | 0.25 | 0.33 |
| 30  | 0.11 | 0.20 | 0.25 |
| 40  | 0.08 | 0.18 | 0.21 |
| 60  | 0.07 | 0.13 | 0.18 |
| 80  | 0.07 | 0.11 | 0.16 |
| 150 | 0.04 | 0.09 | 0.13 |
| ∞   | 0.010| 0.031| 0.053|

Two things to read off:

1. **More carriers genuinely help** (each row drops) — the instinct "lots of carriers
   for a bad link" is correct.
2. **Diminishing returns.** Total bytes on the wire ∝ `(1+r)` and is *independent of n*
   for fixed `r`, so the only thing extra carriers buy is a lower `r`. For q=5 %:
   n=20→30 saves ~8 % bandwidth (10 carriers); 80→150 saves ~3 % (70 carriers). The
   knee is ~30–40 carriers, not 150.

Small packets (sent as `c` duplicate copies, delivered if ≥1 arrives): `P(loss)=q^c`,
so `c = ⌈ln ε / ln q⌉` → **c = 2** (q≤3 %), **c = 3** (q=5 %). Independent of carrier
count — the current `small_redundancy ≥ carriers` saturation trigger is the wrong
shape and should be replaced by this.

## 4. Proposed control law

Everything below lives on the **server** (it owns redundancy in `auto_adapt`); the
client keeps performing the actual opens/closes.

**Estimate `q`** (uncensored, converges faster than directly measuring a 0.1 % event):
over a sliding window, `q ≈ (# shards arriving later than first_shard + α·RTT, or
never) / (# shards sent)`, `α ≈ 1.5`. Optionally inflate `q` if observed late-count
variance exceeds the binomial `n·q(1-q)` (loss correlation → independence assumption
optimistic).

**Redundancy** (replaces the heuristic bumps AND the client's `-0.02` nudge): each
adapt cycle set
```
m* = min { m : P(Binomial(n, q) > m) ≤ ε }
r* = m* / (n - m*)          # push via SERVER_CONFIG
```
Because `m*` is computed from the *current* `n`, `r*` automatically falls as carriers
are added — the missing feedback. (This is the user's "nudge on the server" idea, but
exact instead of a fixed 0.02 step.)

**Carrier count** (replaces the unbounded `rs_redundancy > 0.4` trigger): let `r_cap`
be a redundancy ceiling (how much parity bandwidth we'll tolerate before spending
connections instead). Grow carriers (rate-limited as today) only while
`r*(n) > r_cap`, and **stop when `r*(n) ≤ r_cap`** — a real terminating condition.
Equivalent self-tuning form: stop when one more carrier reduces `(1+r)` by less than δ
(diminishing-returns knee). `max_connections` stays a hard safety cap; **throughput**
growth (`backpressure`, real write backlog) is orthogonal and still allowed up to the
cap, since high-RTT bulk transfer legitimately needs many parallel TCP connections.

Worked, q=5 %: `r_cap=0.3 → ~30 carriers (r≈0.25)`; `r_cap=0.2 → ~40–60`;
`r_cap=0.5 → ~15`. Pick `r_cap` to trade parity-bandwidth vs. connection overhead.
Suggested default `r_cap ≈ 0.3`, `ε = 0.001`, both CLI-overridable.

## 5. What changes in code

- `carrier_adapt`: add `min_parity_for_stall_bound(n, q, ε)` (binomial tail; small `n`,
  cheap) and a `target_carriers_for_redundancy(q, ε, r_cap)` helper. Unit-test against
  the table above.
- Server adapt: estimate `q`; set `r* = m*/(n-m*)`; set small-copy count
  `c = ⌈ln ε / ln q⌉`. Stop using the spread/extra-gap bump/decrement heuristics for
  RS (keep them only as the `q` estimator inputs if useful).
- Client carrier-add: gate `redundancy_pressure` on `r*(n) > r_cap` (or the knee test)
  instead of `rs_redundancy > 0.4`; drop the `small_redundancy ≥ carriers` trigger.
- CLI: `--target-stall-prob` (ε), `--max-redundancy` (r_cap). Keep `--connections` as
  the floor and `--max-connections` as the safety cap.

## 6. Caveats

- **Correlated loss** breaks independence (a link-wide blip stalls many carriers at
  once); the variance check inflates `q` to compensate, but a fully correlated outage
  is handled by the reconnect/total-outage path, not by redundancy.
- **High RTT** doesn't enter `P(stall)` (that's loss-driven) but sets the lateness
  deadline (`α·RTT`) and the *cost* of a stall (≈1 RTT), which is the whole reason for
  the 0.1 % target.
- ε is per *block*; with B blocks/sec the stream stalls ~`ε·B` times/sec — tighten ε if
  that's still too frequent for an interactive session.

## 7. Validation

Add `test_carrier_adapt` cases pinning `min_parity_for_stall_bound` to the table.
Add a `test_all.sh` scenario at q≈5 %, RTT≈400 ms, bulk + idle traffic, asserting the
carrier count **plateaus** (e.g. < 2× the `r_cap`-implied target) instead of climbing
to `max_connections`, while stall/stutter stays within bounds.
