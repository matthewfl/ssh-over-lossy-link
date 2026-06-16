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
wire/reassembly code):
```bash
make && ./test_reed_solomon && ./test_packet_io
```
`test_packet_io.cc` drives `packet_io::process_carrier_read` directly to lock in the
reconnect-critical invariants: in-order delivery of out-of-order packets, **a
duplicate of an already-delivered id is dropped (not re-delivered)** — which is what
makes retransmit-after-reconnect safe — gap-blocking, and RS decode + extra-shard
handling.

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
| `carrier_adapt.{h,cc}` | Pure adaptation logic shared by both sides: `compute_from_deques`, `merge`, `run_adapt` (redundancy), `assess_carriers` (which carriers are dead/slow). Thresholds are `constexpr` here. |
| `reed_solomon.{h,cc}` | Vendored systematic RS erasure coding over GF(2^8). `encode(k,m,...)` / `decode(n,k,...)`. First k shards = data, next m = parity; any k of n reconstructs. |
| `test_ssh_oll.py` | Python integration harness (no SSH). |
| `test_all.sh` | Scenario suite with assertions. |
| `test_reed_solomon.cc` | Unit test for the RS codec. |

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
  (`small_packet_redundancy`) over different carriers. Recovery = duplication.
- **REED_SOLOMON** (`PacketKind::REED_SOLOMON`): one packet carries one shard. A group
  of `n` shards (k data + m parity) shares one `id`; any `k` reconstruct the block.
  `k = floor(n_carriers / (1 + rs_redundancy))`, one shard per carrier round-robin, so
  **adding a carrier raises `k` and thus throughput** — that's why redundancy pressure
  triggers adding carriers.

Control packets (PING/PONG/ACK/SET_CONFIG/START_CONNECTION/READY/SUGGEST_CLOSE/
SERVER_METRICS/SERVER_CONFIG/CLIENT_METRICS) are header-only or small structs;
see ssholl.h and the `append_*` helpers in packet_io.

### Who is in charge
The **client is the master**: it decides carrier count, opens/closes carriers, and
launches the server. The **server cannot open connections** — it can only *suggest*
closing one via `SUGGEST_CLOSE`; the client performs the actual close. Both sides
adapt redundancy, but in default `auto_adapt` mode the **server owns the redundancy
value** and pushes it via `SERVER_CONFIG`; the client feeds it s2c quality via
`CLIENT_METRICS`. In `--no-auto` the client computes redundancy and pushes
`SET_CONFIG`.

### RTT and ACKs (bidirectional)
- Server sends `ACK` when it has written client→server data to the backend; client
  measures the c2s RTT from those ACKs.
- Client sends `ACK` when it has written server→client data to stdout; server measures
  s2c RTT.
- Each side keeps recent RTT samples; **all major timeouts are RTT-scaled**
  (`scaled_ns(mult, min, max)`), so the system self-tunes from low-latency LANs to
  multi-second-RTT links. `--rtt-ms` hints the cold-start RTT before any ACK arrives
  (default cold value ~5 s).

### Adaptation (carrier_adapt.cc — read this for the heuristics)
The signals are designed to be **independent of base RTT** (a uniformly slow link
where shards arrive slow-but-together reads as healthy):
- **Increase RS**: a decoded group is "struggling" if shard spread (1st→k-th) > 2 ms
  *and* the final inter-shard gap is > half the spread (the last needed shard was the
  bottleneck). >5% struggling → big bump; >1% → medium bump.
- **Decrease RS**: p90 of k→(k+1) "extra shard" gaps < 0.5 ms (parity was essentially
  free) *and* <1% struggling → small decrement.
- **Small-packet copies**: decreased via their own p90 first→median copy gap signal.
- RS redundancy clamped to **[0.1, 2.0]**.
- `assess_carriers` decides dead-idle and RTT-outlier carriers (5× median + absolute
  floor). It also catches "send-only zombies" (we keep writing, nothing comes back
  while peers receive). Dead-idle threshold was deliberately lowered to ~5×RTT/min 3 s
  so wifi drops recover fast — see the comment in `assess_carriers`.

### Reliability mechanisms
- **Unacked buffer** (`unacked_sends` / `unacked_data`): every SMALL and RS group is
  kept until ACKed. Retransmit paths: (1) on reconnect, replay all unacked onto the new
  carrier; (2) periodic (~500 ms), resend items older than ~4×RTT to a healthy carrier,
  tracked by *logical carrier_id* (not fd) so churn doesn't cause dupes.
- **Dead-connection detection**: immediate (EPOLLHUP / read / write EPIPE), keepalive
  PING when idle, and inactivity timeout. epoll_wait timeout is capped (~500 ms) so the
  periodic checks always run.
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
- Recent crash/robustness fixes clustered around slow-ping / long-RTT and
  reconnection handling — when touching timeouts or carrier reaping, run the
  high-latency and wifi-blackout scenarios specifically.

## Conventions / gotchas

- Everything is in `namespace ssholl` (with `packet_io`, `carrier_adapt`,
  `reed_solomon` sub-namespaces). Wire structs are `#pragma pack(push,1)`.
- "carrier_id" is a **logical** monotonically increasing id, intentionally distinct
  from the OS fd (fds get reused; retransmit dedup keys on carrier_id).
- `next_send_id` vs `next_deliver_id`: send-side counter vs receive-side contiguous
  delivery cursor. Don't conflate them.
- When changing the wire format, update **both** the structs in `ssholl.h`, the
  `append_*`/parse code in `packet_io.cc`, *and* the protocol section of `README.md`
  (the README documents the wire format as authoritative).
- Single-threaded by design: there is no concurrency to guard against, but the flip
  side is that any blocking call stalls the whole link — keep everything non-blocking
  and epoll-driven.
