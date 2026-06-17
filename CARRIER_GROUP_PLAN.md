# Plan: manage carriers as a synced group

Status: design / not yet implemented. Goal: cut interactive latency on a high-RTT,
lossy, many-carrier link by (a) removing self-inflicted head-of-line delay from routine
control traffic, and (b) detecting dead carriers from the data we already send instead
of from blanket pings.

## The insight that drives this

A PING / keepalive is a small packet on a carrier's TCP stream. On a 1–5 % loss link,
when it is lost TCP retransmits it and **head-of-line-blocks that carrier's next data
shard** — so the shard arrives late, counts toward the loss estimate `q`, the model
raises redundancy and adds carriers, every new carrier gets pinged again, and so on. With
30+ carriers pinged every ~2 s plus per-carrier keepalive every ~3 s, a large fraction of
the measured lateness is **self-inflicted**. Removing routine pings should lower `q`
directly, which lowers redundancy and carrier count on its own.

## Two regimes (the key design split)

- **One / a few carriers dead:** detection can be *slow*. As long as redundancy covers the
  missing shards, a dead carrier does **not** block the logical SSH latency, so there is no
  rush — notice it over many groups, confirm, then close and replace.
- **Many carriers dead at once (or all):** this **does** block latency — groups can no
  longer reach `k`, the stream stalls. This must be detected **fast** and the whole dead
  subset closed and routed around immediately.

The discriminator is simply *are groups still decoding?* If yes → slow path is fine. If
groups are failing to reach `k` → mass-death path, react now.

## Detection from the redundancy structure (no routine pings)

Shards of an RS group are already sent one-per-carrier in rotation. Make the carrier each
shard was sent on **recoverable by the receiver**:

- Each shard carries (or the receiver derives) the group's **carrier assignment**: shards
  go to carriers in increasing order from a per-group start ("first carrier"). Given the
  start + the synced, sorted live-carrier set, the receiver maps every `shard_index →
  carrier_id` — including the ones that **didn't arrive**.
- Per carrier, track *assigned vs delivered* over a sliding window. A carrier that is
  assigned shards but delivers ~none (while peers deliver) is **suspect**.
- Only a suspect gets a **targeted confirm-ping**: deliver → it was transient loss,
  un-suspect it; no PONG within a timeout → confirmed dead → close.

So pings become rare and targeted (confirm only), not a constant fleet-wide load. This is
symmetric: the server does this for c2s (client→server) shards, the client for s2c.

Wire cost note: the "first carrier" can be an explicit ~2-byte index into the sorted set
(robust to set drift) or *derived* from the group id + shard count `n` + the synced set
(zero bytes, but needs both sides' carrier-set views to agree at send time). Start with the
explicit field; optimize to derived later if the overhead matters.

## Load spreading — not "freshness"

Every carrier is an independent TCP connection with roughly equal odds of a loss/retransmit
at any moment, so "which carrier received most recently" is noise, not health. When we need
to send a control packet (CARRIER_STATUS, a confirm-ping), pick the **non-suspect carrier
with the longest time since we last *sent* on it** — spreads control load evenly and rests
the busiest connections. (Replaces any "freshest-recv" selection.)

## Synced carrier identity + out-of-band status

- Client assigns each carrier a stable `carrier_id` and **syncs it in START_CONNECTION**;
  both sides keep `carrier_id → state` and a deterministic sorted order (a generation
  counter bumps on add/close so drift is detectable).
- New **CARRIER_STATUS** packet (either direction, sent over a load-spread carrier): the
  list of `carrier_id`s the sender has concluded are dead. This finally lets the **server
  report a dead carrier over a *healthy* carrier** — today SUGGEST_CLOSE rides the dead
  carrier itself and never arrives.
- **Kill policy (simple):** the client closes a carrier if **either** direction is dead —
  its own s2c detection OR the server's c2s CARRIER_STATUS. No per-direction bookkeeping.

## Mass-death path

When recent groups stop decoding (received shards `< k`), don't wait for per-carrier
windows: take the set of carriers that delivered nothing for the last few groups, close
them as a batch, and open replacements immediately. This reuses the existing
total-outage/reconnect machinery but triggers on "decode is failing" so a large correlated
drop is rerouted in seconds, not after each carrier's slow window elapses.

## Keep `--min-data-per-minute`

Firewalls misbehave when a connection spikes traffic after an idle period, so the steady
per-carrier keepalive stays (it is per-connection NAT upkeep, inherently fleet-wide). It is
not the liveness mechanism anymore — that's the redundancy-attribution above — so its rate
is purely the firewall knob.

## Growth policy (latency-first)

Keep growing carriers while redundancy is above the achievable optimum (more carriers ride
more of the fast pack → lower latency), **but make the rate adaptive**: gentle below the
2.0 redundancy max, **aggressive when redundancy is pinned at 2.0** (carriers are then the
only remaining lever to cut latency). Still bounded by `max_connections`.

## Wire changes

- `START_CONNECTION`: add `carrier_id` (+ set generation).
- RS shard packet: add `first_carrier` index (or derive from id+n).
- New `CARRIER_STATUS` (kind 12): `{ header; uint16 count; carrier_id[]; }` of dead ids.
- Update ssholl.h structs, packet_io append/parse, README wire section. Not
  backward-compatible — both ends rebuilt together.

## Phasing (each step independently testable; watch `q` in the [adapt-model] log)

1. **Sync `carrier_id`** in START_CONNECTION; both sides keep the map + sorted order.
   (No behavior change — plumbing only.)
2. **Per-carrier assigned/delivered tracking** + recover the assignment on the receiver;
   **CARRIER_STATUS reporting** — log only, change nothing. Confirm we correctly fingerprint
   a carrier we kill manually.
3. **Switch reaping** to attribution + targeted confirm-ping; **remove blanket pinging**.
   Expect `q` to drop here.
4. **Mass-death fast path** (decode-failure → batch close + reroute).
5. **Load-spread control-packet selection** (longest-time-since-sent).
6. **Adaptive growth rate** (fast at max).

## Open questions / risks

- **Carrier-set drift** between the two sides' sorted views at send time (affects derived
  attribution; the explicit first-carrier field avoids it). Generation counter to detect.
- **CARRIER_STATUS over a dead-picked carrier** — if the load-spread pick just died, the
  report is lost; retry next interval. Acceptable (statistical).
- **Confirm-ping on a suspect that's merely slow** — a single PONG clears it; tune the
  confirm timeout so transient loss doesn't churn a healthy carrier.
- **Single shared redundancy** still sized for max(c2s_q, s2c_q); separate per-direction
  redundancy remains a later option.
