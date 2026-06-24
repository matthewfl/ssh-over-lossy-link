# CLAUDE.md — ssh-oll developer notes

Working notes for navigating and modifying this codebase. The user-facing README.md
is the authoritative description of behavior and the wire protocol; this file is the
map for *where things live* and *how the pieces fit*, so I don't have to re-derive it.

## What this is

`ssh-oll` ("SSH over lossy link") makes SSH usable over high-loss links where you
can't switch to UDP (e.g. the server is behind a `ProxyJump` / firewall). It tunnels
a single logical SSH byte stream over **N parallel "carrier" SSH connections**. Each
carrier is its own TCP connection subject to its own loss; running many in parallel
means the aggregate path keeps making progress while individual carriers stall.
Reed–Solomon erasure coding + small-packet duplication recover lost data without
waiting for any single TCP retransmit.

It runs as an SSH `ProxyCommand`: the real `ssh` talks to the ssh-oll **client** over
stdin/stdout; the client multiplexes that stream over carriers to the **server**,
which reassembles it and connects to `localhost:22` (the inner SSH).

> Note from README: this project is largely "vibe coded" (Cursor / Sonnet 4.6 /
> Codex). Expect pragmatic, heavily-iterated code rather than a clean-room design.
> Git history is full of incremental "fix the X scenario" commits — read it for the
> *why* behind a particular timeout or heuristic.

## Build & test

```bash
make                        # builds ssh-oll + test_reed_solomon (C++17, -O2)
make install                # installs to /usr/local/bin (DESTDIR-aware)
make clean
```

- **Linux**: native `epoll`. **macOS**: needs `epoll-shim` (`brew install epoll-shim`);
  the Makefile auto-detects via `uname` and adds the include/lib flags.
- Both client and server are **single-threaded, epoll-driven**. No threads, no locks.
- `.o` files and the `ssh-oll` binary are checked into the tree but gitignored going
  forward (`*.o`, `ssh-oll`, `test_reed_solomon` are in `.gitignore`) — rebuild rather
  than trust them.

**Testing without SSH** (`test_ssh_oll.py`): stands up a TCP backend, runs
`ssh-oll --server`, puts a latency/loss-injecting proxy in front of its Unix socket,
and runs the client with `--unix-socket-connection <proxy>`. No real SSH involved.

```bash
./test_ssh_oll.py --ssh-oll-path ./ssh-oll [--latency-ms 5] [--iterations 10]
./test_all.sh                     # full suite with pass/fail latency bounds
./test_all.sh fixed-10ms          # prefix-filter to one test
./test_all.sh --auto-rerun-failed # retry flaky tests once (what CI uses)
```

**Deterministic unit tests** (fast, no sockets — run these first when touching the
wire/reassembly/adapt code):
```bash
make check   # builds + runs test_reed_solomon, test_packet_io, test_carrier_adapt
```
`test_packet_io.cc` drives `packet_io::process_carrier_read` directly to lock in the
reconnect-critical invariants: in-order delivery of out-of-order packets, **a
duplicate of an already-delivered id is dropped (not re-delivered)** — which is what
makes retransmit-after-reconnect safe — gap-blocking, and RS decode + extra-shard
handling. `test_carrier_adapt.cc` pins the pure decision logic: the stall-probability
model (`min_parity_for_stall_bound` etc. against an exact-binomial table) and
`assess_carriers` (dead-idle, rx-dead, no-churn-while-link-up).

**Carrier-count stability** is guarded end-to-end by `--assert-max-carrier-removes N`
(fails a run if too many carriers are closed for a non-benign reason after startup);
it's enabled on the death/blackout-free scenarios in `test_all.sh`. Run those whenever
touching carrier add/reap/adapt logic.

Test scenarios in `test_all.sh` cover: fixed latency, random-spike latency (simulated
loss), connection death in each direction, combined latency+death, high-latency links,
wifi stop/recover + blackout scenarios, no-auto-adapt mode, and a data-integrity
sanity check. CI (`.github/workflows/ci.yml`) builds + tests on Linux and macOS;
macOS test failures are tolerated (timing flakiness).

## File map

| File | Role |
|------|------|
| `main.cc` | Entry point, `getopt_long` arg parsing (`parse_args`/`usage`), `--file-lock` handling, dispatch to `run_server`/`run_client`. `SIGPIPE` ignored. |
| `ssholl.h` | **Wire protocol** (`PacketKind`, packed `Packet*` structs), `Config`, `Args`. Start here for protocol questions. |
| `client.cc` | `run_client` — ~2500 lines. Launches server over SSH, opens carriers, multiplexes stdin/stdout. Master for the link. |
| `server.cc` | `run_server` — daemonizes, creates Unix socket, accepts carriers, bridges to backend `localhost:22`. |
| `packet_io.{h,cc}` | Shared wire (de)serialization: `append_*` builders, `process_carrier_read` parser + reassembly/RS-decode, `flush_carrier_writes`, `CarrierState`, `RsPending`, `ReceiveCallbacks`. |
| `carrier_adapt.{h,cc}` | Pure decision logic shared by both sides. **Redundancy: the probability model** — `min_parity_for_stall_bound` / `redundancy_for_stall_bound` / `small_copies_for_loss` (see REDUNDANCY_MODEL.md). `assess_carriers` (dead-idle / `rx_dead_fds` / `reap_fds` / rtt-outlier). `compute_from_deques` / `merge` / `run_adapt` are the **legacy** struggling-spread heuristic, now bypassed by the server (kept only as the s2c metric path). Thresholds are `constexpr` here. |
| `reed_solomon.{h,cc}` | Vendored systematic RS erasure coding over GF(2^8). `encode(k,m,...)` / `decode(n,k,...)`. First k shards = data, next m = parity; any k of n reconstructs. |
| `net_util.h` | Shared `now_ns()`, `p90_ns`, `scaled_ns(mult,min,max,rtt)`, `UnackedItem`. |
| `REDUNDANCY_MODEL.md` | Derivation of the stall-probability redundancy model (q, ε, latency budget B). |
| `CARRIER_GROUP_PLAN.md` | Design of the synced-carrier-group / data-based dead detection. |
| `test_ssh_oll.py` | Python integration harness (no SSH); `--assert-max-carrier-removes` stability gate. |
| `test_all.sh` | Scenario suite with assertions. |
| `test_reed_solomon.cc` / `test_packet_io.cc` / `test_carrier_adapt.cc` | Unit tests (`make check`). |

## Core mental model

### The packet `id` (sequencing)
SSH is one ordered byte stream. Every logical send gets a monotonically increasing
`id` (`next_send_id`). The receiver buffers out-of-order data keyed by `id`
(`reassembly` map for SMALL, `rs_pending` for RS groups) and only delivers contiguous
data starting at `next_deliver_id`. **A gap blocks delivery** — this is why lost data
must be recovered (RS / retransmit) rather than skipped. Jumping `next_deliver_id`
over a real gap corrupts the inner SSH stream (MAC failure), so the code is careful
*not* to do that except as a last-resort safety net (client) / never (server, per its
comments — it relies on retransmit or the global idle timeout instead).

### Two packet encodings (see `PacketKind` in ssholl.h)
- **SMALL** (`PacketKind::SMALL`): payload `< packet_size`. Sent as N identical copies
  (`small_packet_redundancy`) over different carriers. Recovery = duplication. N comes
  from the model: `ceil(ln ε / ln q)`.
- **REED_SOLOMON** (`PacketKind::REED_SOLOMON`): one packet carries one shard. A group
  of `n` shards (k data + m parity) shares one `id`; any `k` reconstruct the block.
  `k = floor(n_carriers / (1 + rs_redundancy))`, one shard per carrier round-robin, so
  every carrier carries one shard per group. Because the model computes the needed
  redundancy from the *current* carrier count, **adding a carrier lets the redundancy
  fraction drop** (carriers and redundancy trade off) — and a carrier silent while peers
  deliver is the data-based dead signal (no shard arrived for it).

Control packets (PING/PONG/ACK/SET_CONFIG/START_CONNECTION/READY/SUGGEST_CLOSE/
SERVER_METRICS/SERVER_CONFIG/CLIENT_METRICS/**CARRIER_STATUS**) are header-only or small
structs; see ssholl.h and the `append_*` helpers in packet_io. Two carry payload worth
noting: `START_CONNECTION` carries the client-assigned `carrier_id` (synced to both
sides); `CARRIER_STATUS` carries a list of shared carrier ids the sender sees as dead.

### Who is in charge
The **client is the master**: it decides carrier count, opens/closes carriers, and
launches the server. The **server cannot open connections** — it reports carriers it
sees as dead via `CARRIER_STATUS` (sent over a *healthy* carrier, so the news arrives
even though nothing succeeds on the dead one) and the client performs the actual close.
(`SUGGEST_CLOSE` is the legacy version that had to ride the dead carrier itself; still
sent but superseded.) In default `auto_adapt` mode the **server owns the redundancy
value**: it runs the probability model and pushes the value via `SERVER_CONFIG`; the
client applies it and feeds back its s2c loss estimate `q` via `CLIENT_METRICS`. The
client still sends `SET_CONFIG` for non-redundancy settings, but the server **ignores
its redundancy fields in auto mode** (else client and model fight). In `--no-auto` the
client's `SET_CONFIG` fully controls redundancy and the server doesn't adapt.

### RTT and ACKs (bidirectional)
- Server sends `ACK` when it has written client→server data to the backend; client
  measures the c2s RTT from those ACKs.
- Client sends `ACK` when it has written server→client data to stdout; server measures
  s2c RTT.
- Each side keeps recent RTT samples; **all major timeouts are RTT-scaled**
  (`scaled_ns(mult, min, max)`), so the system self-tunes from low-latency LANs to
  multi-second-RTT links. `--rtt-ms` hints the cold-start RTT before any ACK arrives
  (default cold value ~5 s).

### Adaptation: redundancy (probability model — see REDUNDANCY_MODEL.md)
Redundancy is **not** the old struggling-spread heuristic anymore (that lives in
`run_adapt`/`compute_from_deques`, now bypassed). The server runs a stall-probability
model every ~300 ms:
- A block stalls iff **more than `m`** of its `n` shards are *late*. With per-shard late
  probability `q`, that's `P(Binomial(n,q) > m)`. Pick the smallest `m` (smallest
  redundancy `r = m/k`) holding `P(stall) ≤ ε` (ε = 0.01 %), then add a `+0.05` margin;
  clamp to **[0.1, 2.0]**. `m` uses the *current* carrier count, so r falls as carriers grow.
- **"late" = absolute latency budget**, not RTT-relative: a shard is late if it arrives
  more than `B` (= `--max-added-latency-ms`, default 10 ms) after its group's first shard.
- **`q` estimate**: fraction of received shards whose gap-from-first exceeds `B`, sliding
  window. Server measures c2s; client measures s2c and reports it (repurposed
  `fraction_struggling` field in `CLIENT_METRICS`); server uses `max(c2s, s2c)`.
- **Small-packet copies**: `ceil(ln ε / ln q)`, clamped `[2, n]`.

### Adaptation: carrier count (client.cc)
- **Floor** `max(2, --connections)` always maintained; grow up to `--max-connections`.
- **Grow** on write-backlog, rtt-outlier, or **redundancy pressure** (server's redundancy
  > ~0.3). Redundancy-pressure add rate is adaptive: ~25 s normally, ~3 s when redundancy
  is pinned at the 2.0 max.
- **Release excess** when above floor *and* redundancy is low (< 0.2) *and* no backlog:
  one carrier per ~15 s. Hysteresis (grow >0.3 / shrink <0.2) prevents oscillation, so the
  count tracks need (floor on a clean link, higher on a lossy one).
- `assess_carriers` flags: `rx_dead_fds` (silent while a peer is delivering — **threshold
  ~25 s, deliberately > the ~10 s keepalive interval** so a carrier merely between
  keepalives isn't falsely flagged), idle-dead, rtt-outlier (5× median + floor), and the
  total-outage zombie reap. **History note:** rx-dead was once 3 s, which mis-flagged
  healthy carriers between keepalives and churned the count — keep it above the keepalive
  interval.

### Reliability mechanisms
- **Unacked buffer** (`unacked_sends` / `unacked_data`): every SMALL and RS group is
  kept until ACKed. Retransmit paths: (1) on reconnect, replay all unacked onto the new
  carrier; (2) periodic (~500 ms), resend items older than ~4×RTT to a healthy carrier,
  tracked by *logical carrier_id* (not fd) so churn doesn't cause dupes.
- **Dead-connection detection (data-based, no blanket pings)**: immediate (EPOLLHUP /
  read / write EPIPE); **rx-dead** (carrier silent while peers deliver) reported peer→peer
  via `CARRIER_STATUS` over a healthy carrier, with the client confirming its own s2c
  suspects via a single targeted `PING` before closing; and a **mass-death fast path**
  (delivery stalled + a large subset silent → batch-close immediately). Blanket pinging
  was *removed* — a lost ping HoL-blocks that carrier's next data shard and inflates the
  measured loss. **Idle keepalive is `--min-data-per-minute`** (default 100, 10 s windows),
  not pings. epoll_wait timeout is capped (~500 ms) so the periodic checks always run.
- **Stale RS groups**: incomplete groups older than ~4×RTT are dropped to bound memory
  (and on the client, advance past the gap as a last resort).
- **Global idle / reconnect timeout**: if nothing is received for `12×RTT`
  (clamped 60–300 s) the side exits; override with `--reconnect-timeout`. The server
  stays alive across this window so a client that lost all carriers can reconnect.

### Lifecycle & cleanup
- Server: forks, parent prints socket path + exits, child `setsid()` daemonizes and
  closes stdio. Socket path is `/tmp/ssh-oll-server.<random>` (user-only perms); a
  unique suffix per session means multiple clients can share a host. Server exits when
  the inner SSH (backend) closes, and unlinks its socket on exit.
- Client: per-carrier local sockets live under a `/tmp/ssh-oll-client.<random>/`
  directory (one numbered socket per SSH `-L` slot); cleaned up on exit. `--file-lock`
  (main.cc) serializes client startup via `flock` with a 15 s timeout.

## Debugging

- `--debug` writes verbose logs to `/tmp/ssh-oll-{client,server}-<pid>.log`. The server
  is daemonized with closed stdio, so this is the only way to see server-side state.
- Reproduce link conditions locally with `test_ssh_oll.py --latency-ms` /
  `--latency-random` and the named scenarios in `test_all.sh` (e.g. the
  `wifi-stop-then-recover*` and `connection-death-*` tests for reconnection bugs).
- Server `--debug` has an `[adapt-model t=… q=… q_c2s=… q_s2c=… n=… r_model=… copies=…
  B_ms=… gap_ms_p50/p90/p99=…]` line — the live loss estimate and model decision. If
  redundancy is pinned at 2.0 and carriers climb, the link's inter-shard spread exceeds
  `B`; the gap percentiles tell you where to set `--max-added-latency-ms`.
- Client `--debug` has a periodic `[carriers-diag …]` line (per-carrier recv/send-ago,
  dead/pending flags) and `[carrier-remove … reason=…]` lines — use these for carrier
  churn / stability questions.
- When touching timeouts or carrier add/reap/adapt, run the high-latency, wifi-blackout,
  and the stability-asserted (`--assert-max-carrier-removes`) scenarios specifically.

## Conventions / gotchas

- Everything is in `namespace ssholl` (with `packet_io`, `carrier_adapt`,
  `reed_solomon` sub-namespaces). Wire structs are `#pragma pack(push,1)`.
- Two logical ids on `CarrierState`, both distinct from the OS fd (fds get reused):
  `carrier_id` is **each side's own** monotonically-increasing id (retransmit dedup keys
  on it); `shared_carrier_id` is the **client-assigned id synced to both sides** (via
  `START_CONNECTION`) and is what `CARRIER_STATUS` / cross-link naming uses. The client
  sets `shared_carrier_id = carrier_id`; the server gets it from the wire.
- `next_send_id` vs `next_deliver_id`: send-side counter vs receive-side contiguous
  delivery cursor. Don't conflate them.
- When changing the wire format, update **both** the structs in `ssholl.h`, the
  `append_*`/parse code in `packet_io.cc`, *and* the protocol section of `README.md`
  (the README documents the wire format as authoritative).
- Single-threaded by design: there is no concurrency to guard against, but the flip
  side is that any blocking call stalls the whole link — keep everything non-blocking
  and epoll-driven.
