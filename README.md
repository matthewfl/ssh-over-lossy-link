# SSH Over Lossy Link (ssh-oll)

This project is for making SSH connections usable when making a connection with a server when there is high packet loss.  In the ideal case where you have full control over a server and its networking interfaces, using a project such as [Mosh](https://mosh.org/), or where instead of using a TCP based connection, a UDP based connection is used, allowing for dropped packet to not delay the connection.  However, when a server is behind a firewall or requires an SSH [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump) to access, using a UDP based connection is not an option.

Ssh-oll solves this problem by layering a single SSH connection over several "carrier SSH connections". Each TCP connection is subject to individual packet loss, and therefore a single TCP connection can become delayed when a packet is lost. By using multiple TCP connections in parallel, the aggregate path can still make progress when some carriers are stalled.

## Architecture (data flow)

```
  Local SSH client
        |
        | (stdin/stdout via ProxyCommand)
        v
  +------------------+                      +------------------+
  |  ssh-oll client  | ---- carrier 1 ----> |                  |
  |                  | ---- carrier 2 ----> |  ssh-oll server  | ----> localhost:22
  |                  | ---- carrier N ----> |  (Unix socket)   |       (inner SSH)
  +------------------+                      +------------------+
        ^                                             ^
        |                                             |
   lossy-ssh-host     (multiple SSH sessions)    lossy-ssh-host
```

The client runs as a ProxyCommand: the real SSH process talks to the client over stdin/stdout. The client multiplexes that single stream over N carrier SSH connections (each with a forwarded Unix socket to the server). The server reassembles the stream and connects to `localhost:22` (or the configured host/port) to complete the SSH hop.

## Setup

Install `ssh-oll` on both the client and the server.

**Linux:**
```bash
git clone https://github.com/matthewfl/ssh-over-lossy-link.git
cd ssh-over-lossy-link
make && make install
```

**macOS:** Requires [epoll-shim](https://github.com/jiixyj/epoll-shim) (provides epoll on top of kqueue).
```bash
brew install epoll-shim
git clone https://github.com/matthewfl/ssh-over-lossy-link.git
cd ssh-over-lossy-link
make && make install
```

Then configure your `~/.ssh/config` file as follows:
```
Host lossy-ssh-connection
    HostName ip/hostname of remote ssh host
    ProxyJump hostname-of-jump-host                # can use ProxyJump or ProxyCommands on lossy host

    # DO NOT have ControlMaster or ServerAliveInterval on the lossy connection

Host good-ssh-connection
    ProxyCommand ssh-oll lossy-ssh-connection     # configure ssh-oll as ProxyCommand
    ConnectTimeout 120                            # initial connection may take longer than normal

    ControlMaster auto                            # optional, reuse the same ssh connection for other sessions
    ControlPath ~/.ssh/ssh-control-%C
    ControlPersist 1m
    ServerAliveInterval 15                        # optional, have ssh send keep alive pings
    ServerAliveCountMax 3
```


Then make sure you can ssh using the lossy connection without having to enter a password:
```bash
$ ssh-add                           # register ssh key with ssh agent
$ ssh lossy-ssh-connection          # check that this works without entering a password

$ ssh good-ssh-connection           # ssh connection now running over ssh-oll
```

## Command line
```
ssh-oll   [command line options]   lossy-ssh-host   [hostname on remote (default localhost)]   [remote port (default 22)]

--auto / --no-auto            Automatically adapt the number of carrier SSH connections and redundancy transmission rates. Default on
--path-on-server              Path to the ssh-oll binary on the server.  Default to "ssh-oll" with the binary installed in the user's PATH.
--connections [N]             How many carrier SSH connections to open initially.  Default 10 (a reasonable default for moderate loss; increase for worse links).
--max-connections [N]         Max number of carrier connections that can be opened.  Default 50
--packet-size [N]             The max bytes of a single "packet" sent across a connection.  Default 400
--small-packet-redundancy [N] For buffered data smaller than packet-size, send N copies without Reed–Solomon. In auto mode this is the cold-start value; the redundancy model then sets it. Default 2
--rs-redundancy [N]           Reed–Solomon parity as a fraction of data (m/k). In auto mode this is the cold-start value; the probability model then sets it. Default 0.1
--max-delay [N]               Max delay in ms for sending data while waiting for buffer to fill for Reed–Solomon.  Default 1ms
--max-added-latency-ms [N]    Latency budget B for the redundancy model: a shard arriving more than N ms after its group's first shard counts as "late". Lower N spends more parity/carriers for tighter latency; raise it on a high-jitter link to avoid over-provisioning. Default 10
--rtt-ms [N]                  Hint RTT (ms) for cold-start timeouts; 0 = auto from observed link latency. Use on high-latency links to avoid premature timeouts before first ACK. Default 0
--connect-timeout [N]         SSH ConnectTimeout in seconds for carrier connections; 0 = no limit. Default 30
--min-data-per-minute [N]     Idle keepalive: each carrier sends ≥N bytes/min in each direction (spread over 10s windows) so a firewall/NAT doesn't close an idle link. This is the only idle keepalive (blanket pinging was removed). Default 100; set 0 to disable
--reconnect-timeout [N]       Global idle timeout in seconds before giving up; 0 = adaptive (12×RTT, min 60 s, max 300 s); else 1–7200. Default 0
--file-lock PATH              Acquire an exclusive lock on PATH (flock, 15 s timeout) before client start, to serialize concurrent client launches.
--debug                       Write verbose debug logs to /tmp/ssh-oll-{client,server}-<pid>.log.
--server                      Start the server instance of ssh-oll.  Default off (client mode).
--unix-socket-connection PATH  Connect directly to Unix socket PATH instead of using SSH -L (for testing).
```


## How it works

When `ssh-oll` is started, it opens a connection to the SSH host to launch the server using `ssh lossy-ssh-host "ssh-oll --server localhost 22"`. The server creates a Unix socket such as `/tmp/ssh-oll-server.abc123def` with permissions so only the current user can access it, prints the socket path, then daemonizes and closes the initial SSH connection. The client then opens multiple carrier connections with commands like `ssh -L /tmp/ssh-oll-client.hgi456789/0:/tmp/ssh-oll-server.abc123def lossy-ssh-host`, and so on for each carrier. The client can open up to `--max-connections` sessions; by default the count is adapted automatically based on observed packet loss. Both sides monitor link latency using ACKs in both directions: the server sends ACK when it has delivered data to the backend (client→server path); the client sends ACK when it has delivered data to stdout (server→client path). Each side measures RTT from the ACKs it receives. The server reports its observed RTT to the client via SERVER_METRICS so the client can use max(client RTT, server RTT) when deciding to add carriers. The client is the master for the link (carrier count, when to add more). Redundancy is managed automatically when auto mode is on (default) or uses the initial config without any changes when auto mode is off. Both client and server are single-threaded, using epoll to manage connections and subprocesses.

**Lifecycle and cleanup:** The server exits when the inner SSH session to localhost:22 (or the configured host/port) ends. On exit it removes its Unix socket. Each session uses a unique random suffix in the socket path (e.g. `abc123def`), so multiple ssh-oll clients can use the same host concurrently.

**Failure and reconnection:** If carrier connections drop, the client can open additional carriers (up to `--max-connections`) to keep the logical stream alive. The client keeps attempting to reconnect as long as its process is alive, and the server stays alive waiting for the client to reconnect. How long each side waits before giving up is the global idle timeout: by default adaptive (12×RTT, clamped to 60 s–300 s), or a fixed value via `--reconnect-timeout`. **To survive a long outage (e.g. a multi-minute VPN/Wi-Fi drop), set `--reconnect-timeout` to comfortably exceed the expected outage** (for example `--reconnect-timeout 900` for up to ~15 minutes) — otherwise, on a low-latency link, both ends reach the 60 s idle floor and exit *before* the link returns, leaving nothing to reconnect to. Once both ends survive the outage, recovery is automatic: dead-but-open carriers are reaped (even when every carrier is down) and unacked data is retransmitted onto the freshly reopened carriers.

### Automatic mode (`--auto`, default on)

Auto mode controls two things: how many carrier connections to maintain, and how much Reed-Solomon redundancy to use.

#### Connection count

A *floor* of `max(2, --connections)` connections is always maintained, in both auto and non-auto mode. The client checks every 50 ms (when zero connections are alive) or 100 ms (otherwise) and opens a new connection if it is below the floor.

In auto mode, extra connections (up to `--max-connections`) are opened when any of the following triggers fires:

| Trigger | Meaning |
|---------|---------|
| **Write backlog** | Total queued outgoing bytes across all carriers exceeds 150 × packet_size — the existing carriers can't keep up. |
| **RTT outlier** | A carrier's measured ACK round-trip time is both above 1 s and more than 5× the median peer RTT — that carrier is stalled while others are fine. |
| **Redundancy pressure** | The model's RS redundancy is above a cap (~0.3). Each RS group uses one shard per carrier, so adding a carrier raises `k` (data shards per group) and lets the model *lower* the redundancy fraction — i.e. carriers and redundancy trade off. The add rate is adaptive: ~25 s apart normally, but ~3 s apart when redundancy is pinned at its 2.0 max (carriers are then the only lever to cut latency). |

**Releasing carriers.** When the count is above the floor and redundancy is low (the link is good: model redundancy < 0.2) and there is no backlog, one excess carrier is released every ~15 s, so the count drifts back toward the floor instead of ratcheting up. The hysteresis (grow when redundancy > 0.3, shrink when < 0.2) keeps it from oscillating. The count therefore tracks actual need: at the floor on a clean link, higher on a lossy one.

**Reaping dead carriers** is driven by the *data*, not by pings (see [Dead-connection detection](#dead-connection-detection)): a carrier that goes silent while its peers keep delivering is identified, confirmed, and closed, and a correlated drop of many carriers is rerouted immediately.

#### Reed-Solomon redundancy (probability model)

Redundancy is set from a stall-probability model rather than ad-hoc bump/decay heuristics. The full derivation is in [`REDUNDANCY_MODEL.md`](REDUNDANCY_MODEL.md); the summary:

An RS group is `n` shards (`k` data + `m` parity, one shard per carrier). It is delivered as soon as any `k` arrive, so it **stalls** (must wait for a retransmit — a head-of-line delay) only if **more than `m`** of its `n` shards are *late*. Treating shard lateness as roughly independent with probability `q`, the number late is `~Binomial(n, q)` and the stall probability is `P(X > m)`. The model picks the smallest `m` (hence the smallest redundancy `r = m/k`) that holds `P(stall) ≤ ε`, with `ε = 0.01 %`, plus a small `+0.05` safety margin. Because `m` is computed from the *current* carrier count `n`, the redundancy **falls as carriers are added** — that is the feedback that lets carriers and redundancy trade off (and stops carriers from ratcheting up forever). Redundancy is clamped to `[0.1, 2.0]`.

**"Late" is an absolute latency budget, not RTT-relative.** A shard counts as late if it arrives more than `B` after its group's first shard, where `B = --max-added-latency-ms` (default 10 ms). This is the acceptable head-of-line delay for the inner SSH stream — far tighter than the link's RTT (which may be hundreds of ms). On a 1–5 % loss link the arrival distribution is bimodal: shards that ride through arrive within a few ms of each other, while a shard hit by loss waits ~one RTT for a TCP retransmit; `B` sits in the gap, so the measured `q` ≈ the real loss/retransmit rate.

**Estimating `q`:** each side counts, over a sliding window, the fraction of received shards whose gap from their group's first shard exceeds `B`. The server measures the client→server direction; the client measures server→client the same way and reports it in `CLIENT_METRICS`. A single redundancy value governs both directions, so it is sized for the worse one: `q = max(c2s, s2c)`. Re-evaluated every ~300 ms.

**Small-packet copies** (duplicate-on-distinct-carriers, used for sub-packet-size sends) come from the same `q`: the smallest `c` with `q^c ≤ ε`, i.e. `c = ⌈ln ε / ln q⌉`, clamped to `[2, carrier count]`.

In `--auto` mode the **server owns** redundancy: it runs the model and pushes the value via `SERVER_CONFIG`; the client applies that and reports its s2c `q` back via `CLIENT_METRICS`. (The client still sends `SET_CONFIG` for non-redundancy settings such as packet size, but the server **ignores its redundancy fields in auto mode** so the model isn't overridden.) In manual mode the client's `SET_CONFIG` fully controls redundancy and no adaptation happens.

> Tuning note: if you see redundancy pinned at 2.0 and the carrier count growing, the link's natural inter-shard spread exceeds `B` (10 ms can't be met). Check the `gap_ms_p50/p90/p99` figures in the server `--debug` log (`[adapt-model ...]` line) and raise `--max-added-latency-ms` toward `p90` to trade some latency for far fewer carriers.

#### RTT-scaled timeouts

Retransmit, inactivity, and reap timeouts are scaled by observed link RTT rather than hardcoded (the idle keepalive is a fixed-cadence exception — see below). On low-latency links this yields tighter timeouts; on high-latency links (e.g. 5–10 s RTT) timeouts lengthen accordingly. Use `--rtt-ms N` to hint the expected RTT for cold-start (before any ACKs arrive); otherwise a conservative 5 s default is used until RTT is measured.

#### Dead-connection detection

Dead carriers are detected from the data already flowing, **not** by pinging every carrier (a blanket ping is itself harmful: a lost ping triggers a TCP retransmit that head-of-line-blocks that carrier's next data shard, inflating the very lateness the redundancy model measures). The mechanisms:

1. **Immediate error**: `EPOLLHUP`, a failed `read()`, or a failed `write()` (returns `EPIPE`) removes the carrier immediately.
2. **Silent-while-peers-deliver (the data signal)**: since each group sends one shard per carrier, a healthy carrier delivers something on roughly every group. A carrier that delivers *nothing* while its peers keep delivering is suspect. The threshold is deliberately longer than the idle-keepalive interval (~25 s) so a carrier that is merely between keepalives or interactive bursts is **not** flagged. Each side reports the carriers it sees as dead, by their shared carrier id, to the peer via `CARRIER_STATUS` — sent over a *healthy* carrier, so the news arrives even though nothing succeeds on the dead one (the old `SUGGEST_CLOSE` had to ride the dead carrier itself). A carrier is closed if **either** direction reports it dead; the client confirms its own (server→client) suspects with a single targeted `PING` first, then closes only if that delivers nothing back. The client is the master and performs all closes/opens.
3. **Mass-death fast path**: if delivery stalls (data pending but the in-order cursor not advancing) *and* a large fraction of carriers go silent at once, the whole silent set is closed and rerouted immediately rather than waiting out the per-carrier confirmation — this is the case that actually blocks latency.

A single dead carrier is therefore detected somewhat slowly (~25 s), which is fine: redundancy covers its absence in the meantime, and a correlated outage takes the fast path. Carriers are kept warm on an idle link by `--min-data-per-minute` (see below), not by these checks. The `epoll_wait` timeout is capped so these periodic checks always run even when no I/O events arrive.

**Idle keepalive.** With blanket pinging removed, an otherwise-idle link still needs to touch every carrier so a firewall/NAT doesn't close it. `--min-data-per-minute N` (default 100) ensures each carrier sends at least `N` bytes/minute, spread over 10-second windows (so the per-carrier gap stays ≤ ~10 s); real traffic counts toward the budget, so it only emits keepalive bytes when a carrier would otherwise be quiet. Set `0` to disable.

#### Retransmission and data recovery

Every RS group and every `SMALL` packet sent is kept in an *unacked buffer* until an `ACK` is received for it. Two retransmit paths exist:

- **On reconnect**: when the last carrier dies and a new one subsequently connects, all unacked data is replayed immediately onto the new carrier.
- **Periodic timeout**: every 500 ms, any unacked item that was sent more than 4×RTT ago is resent to a healthy carrier. This recovers from partial loss where some (but not all) carriers died, leaving the remote side's Reed-Solomon groups incomplete.

Finally, incomplete RS groups (waiting for shards) that are older than 4×RTT are discarded **from memory** to bound buffering. Note that `next_deliver_id` is **not** advanced past the gap: jumping would inject a hole into the SSH byte stream, which SSH detects as a MAC failure and closes the connection. Instead the receiver waits for the retransmit path to refill the gap; if the sender is truly gone, the global idle timeout closes the connection cleanly. Both directions behave identically here.

### Ordering

SSH is a single ordered byte stream. Packets are sent over multiple carriers and may arrive out of order or be lost. The **packet header `id`** groups data that must be delivered in order: all packets sharing the same `id` form a logical group. The receiver must buffer out-of-order packets and only pass data to the inner SSH stream once every packet in that group has been received (or recovered via redundancy). Concretely: each group has a sequence (e.g. per-id sub-ordering or a global stream offset), and the receiver reassembles groups in order before writing to the backend socket. Additional wire details (e.g. group size, sequence within group) can be carried in the packet payload or in a small extension to the header as the design is implemented.

### Backpressure

When outgoing carrier links are full, the client stops reading from stdin (the local SSH client). That naturally back-pressures the SSH client. To avoid stalling indefinitely, the client should also try to open new carrier SSH connections when buffers are persistently full, so more capacity is available to push data through. Thus backpressure both throttles the producer and triggers growth of the carrier set.

### Security

Security is not a primary focus of this layer: the payload is already an SSH session, so traffic is encrypted and authenticated by SSH. The Unix socket is restricted to the current user. The threat model assumes the same as using SSH alone; ssh-oll does not add new cryptographic or authentication mechanisms.

### Platform and dependencies

The implementation uses **epoll** (Linux) or **epoll-shim** (macOS, kqueue-based). Supported platforms: Linux (native epoll), macOS (via [epoll-shim](https://github.com/jiixyj/epoll-shim), install with `brew install epoll-shim`). Dependencies include a Reed–Solomon (erasure coding) library (vendored); epoll-shim required on macOS.

## Packet format (wire protocol)

```
enum packet_kind_e : uint8_t {
    PACKET_PING = 0,              // client -> server; server replies with PONG for health checks
    PACKET_PONG = 1,               // server -> client; response to PING
    PACKET_SMALL = 2,
    PACKET_REED_SOLOMON = 3,
    PACKET_SET_CONFIG = 4,        // client -> server; adjust redundancy / packet size etc.
    PACKET_START_CONNECTION = 5,  // client -> server; first packet on a new carrier, carries its shared carrier_id
    PACKET_ACK = 6,               // both directions; cumulative ack: all data up to and including header.id delivered (for latency measurement)
    PACKET_SERVER_METRICS = 7,    // server -> client; max RTT observed by server (server→client path) for client adapt
    PACKET_SERVER_CONFIG = 8,     // server -> client; server's current redundancy (when server manages it; auto_adapt)
    PACKET_READY = 9,             // server -> client; sent when carrier connects, confirms link is up before client sends
    PACKET_SUGGEST_CLOSE = 10,   // server -> client; legacy "close this carrier" hint (rides the carrier itself); CARRIER_STATUS is now the primary dead-carrier signal
    PACKET_CLIENT_METRICS = 11,  // client -> server; server→client path quality (incl. s2c loss estimate q) so the server can size redundancy for both directions
    PACKET_CARRIER_STATUS = 12,  // either direction; list of shared_carrier_ids the sender sees as dead, sent over a healthy carrier
};
struct __attribute__((__packed__)) packet_header {
    uint64_t id;
    packet_kind_e packet_kind;
};

struct __attribute__((__packed__))  packet_small : packet_header {
    uint16_t size;
    uint8_t data[];
};

struct __attribute__((__packed__)) packet_reed_solomon : packet_header {
    uint16_t size;       // block_size (shard length in bytes)
    uint8_t n, k;        // Reed–Solomon: n = total shards, k = data shards
    uint8_t shard_index;  // which shard 0..n-1 (one packet = one shard)
    uint8_t data[];      // shard payload, exactly size bytes
};
struct __attribute__((__packed__)) packet_config : packet_header {
    // client -> server: configure redundancy and transmission settings
    uint16_t packet_size;
    uint16_t small_packet_redundancy;
    float max_delay_ms;
    float reed_solomon_redundancy;
    uint8_t auto_adapt;  // 1 = server may adapt and send SERVER_CONFIG; 0 = client manages via SET_CONFIG
};

struct __attribute__((__packed__)) packet_start_connection : packet_header {
    uint64_t carrier_id;   // client-assigned shared id for this carrier; the server records
                           // fd -> carrier_id so both sides can name the same carrier
};

struct __attribute__((__packed__)) packet_carrier_status : packet_header {
    uint16_t count;        // followed by `count` little-endian uint64 shared carrier ids
    // uint64_t dead_carrier_ids[count];
};

// PACKET_START_CONNECTION: client -> server. First packet the client writes on a freshly
// connected carrier, carrying that carrier's shared carrier_id (the client is the sole
// carrier authority). Lets health/attribution messages refer to a carrier across the link.

// PACKET_CARRIER_STATUS: either direction. The shared_carrier_ids the sender's receive side
// currently sees as dead (silent while peers keep delivering). Sent over a healthy carrier so
// it arrives even though nothing succeeds on the dead carrier. The client closes a carrier if
// either its own detection or the peer's CARRIER_STATUS flags it.

// PACKET_ACK: header only. header.id = acked_id (all data with id <= acked_id delivered).
// Server sends ACK when it has written to the backend (client measures client→server RTT).
// Client sends ACK when it has written to stdout (server measures server→client RTT).
// Both sides use received ACKs for latency monitoring.

// PACKET_SERVER_METRICS: server -> client. struct { packet_header; uint64_t max_rtt_ns; }
// Server sends periodically so the client can use max(client RTT, server RTT) when adding carriers.

// PACKET_SERVER_CONFIG: server -> client. Same payload as packet_config (no auto_adapt).
// When auto_adapt is on, server adapts redundancy and sends this so the client stays in sync.

// PACKET_SUGGEST_CLOSE: server -> client. Header only. Legacy per-carrier "close this" hint that
// rides the carrier itself; superseded by CARRIER_STATUS (which can name a dead carrier over a
// healthy one). The client performs all closes; the server cannot open connections.

// PACKET_READY: server -> client. Header only. Sent when a carrier connects so the client
// knows the bidirectional path is up before it sends data; avoids premature timeouts.

// PACKET_CLIENT_METRICS: client -> server. struct { packet_header; uint64_t avg_shard_spread_ns;
//   uint64_t avg_extra_shard_gap_ns; float fraction_struggling; uint32_t rs_pending_count;
//   uint8_t can_decrease_rs; uint8_t can_decrease_small; }. Reports server→client path quality
//   so the server (which owns redundancy in auto mode) can adapt using both directions.
//   NOTE: in the probability-bounded redundancy model the `fraction_struggling` field carries
//   the client's s2c per-shard loss estimate q (fraction of received shards arriving later than
//   the latency budget B after their group's first shard); the server uses max(c2s_q, s2c_q).
//   The avg_* and can_decrease_* fields are legacy and currently unused by the server.

```

## Development testing

A Python script `test_ssh_oll.py` exercises the stack without SSH:

1. Starts a TCP server (default port 2222) that `ssh-oll --server` uses as its backend instead of real SSH.
2. Starts `ssh-oll --server localhost <port>` and reads its Unix socket path.
3. Creates a proxy Unix socket (e.g. `/tmp/ssh-oll-test-script.<suffix>`) that forwards to the server socket, with optional `--latency-ms` to simulate delay.
4. Runs the client with `--unix-socket-connection <proxy>` so the client connects via the proxy (no SSH).
5. Measures latency: client stdin → TCP and TCP → client stdout, and validates byte-stream integrity.

The proxy can inject fixed/random latency (`--latency-ms`, `--latency-random*`), per-connection death (`--connection-death-probability`), and Wi-Fi-style blackout scenarios. `--assert-max-carrier-removes N` makes a run also fail if the client closed more than `N` carriers for a non-benign reason after startup — a guard against carrier-count instability/churn (use only on scenarios that don't inject carrier death). `test_all.sh` runs the full scenario suite with pass/fail bounds (and the stability assertion on the death/blackout-free scenarios); `make check` runs the deterministic unit tests (`test_reed_solomon`, `test_packet_io`, `test_carrier_adapt`).

Example:

```bash
./test_ssh_oll.py --ssh-oll-path ./ssh-oll [--latency-ms 5] [--iterations 10]
```

Use `--unix-socket-connection` on the client to point at the proxy socket when driving the client manually.

A collection of several tests can be run using `./test_all.sh`

## License

MIT. See [LICENSE](LICENSE) in this repository.

## Vibe coded warning

This project is mostly vibe coded using Cursor with Composer 1.5, Claude Sonnet 4.6 and GPT Codex 5.3.