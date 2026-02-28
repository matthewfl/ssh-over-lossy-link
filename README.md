# SSH Over Lossy Link (ssh-oll)

This project is for making SSH connections usable when making a connection with a server when there is high packet loss.  In the ideal case where you have full control over a server and its networking interfaces, using a project such as [Mosh](https://mosh.org/), or where instead of using a TCP based connection, a UDP based connection is used, allowing for dropped packet to not delay the connection.  However, when a server is behind a firewall or requires an SSH [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump) to access, using a UDP based connection is not an option.

Ssh-oll solves this problem by layering a single SSH connection over several "carrier SSH connections". Each TCP connection is subject to individual packet loss, and therefore a single TCP connection can become delayed when a packet is lost. By using multiple TCP connections in parallel, the aggregate path can still make progress when some carriers are stalled.

## Architecture (data flow)

```
  Local SSH client
        |
        | (stdin/stdout via ProxyCommand)
        v
  +------------------+                    +------------------+
  |  ssh-oll client  | ---- carrier 1 ---->|                  |
  |                  | ---- carrier 2 ---->|  ssh-oll server  | ----> localhost:22
  |                  | ---- carrier N ---->|  (Unix socket)    |       (inner SSH)
  +------------------+                    +------------------+
        ^                                        ^
        |                                        |
   lossy-ssh-host (multiple SSH sessions)   lossy-ssh-host
```

The client runs as a ProxyCommand: the real SSH process talks to the client over stdin/stdout. The client multiplexes that single stream over N carrier SSH connections (each with a forwarded Unix socket to the server). The server reassembles the stream and connects to `localhost:22` (or the configured host/port) to complete the SSH hop.

## Setup

Install `ssh-oll` on both the client and the server.
```
git clone ...
make && make install
```
Then configure your `~/.ssh/config` as follows:
```
Host lossy-ssh-connection
    HostName ip/hostname of remote ssh host

Host good-ssh-connection
    ProxyCommand ssh-oll lossy-ssh-connection
```


## Command line
```
ssh-oll   [command line options]   lossy-ssh-host   [hostname on remote (default localhost)]   [remote port (default 22)]

--auto / --no-auto            Automatically adapt the number of carrier SSH connections and redundancy transmission rates. Default on
--path-on-server              Path to the ssh-oll binary on the server.  Default to "ssh-oll" with the binary installed in the user's PATH.
--connections [N]             How many carrier SSH connections to open initially.  Default 10 (a reasonable default for moderate loss; increase for worse links).
--max-connections [N]         Max number of carrier connections that can be opened.  Default 200
--packet-size [N]             The max bytes of a single "packet" sent across a connection.  Default 800
--small-packet-redundancy [N] For buffered data smaller than packet-size, send N copies without Reed–Solomon. Default 2
--rs-redundancy [N]           Number of extra packets when using Reed–Solomon, as a fraction.  Default 0.2
--max-delay [N]               Max delay in ms for sending data while waiting for buffer to fill for Reed–Solomon.  Default 1ms
--server                      Start the server instance of ssh-oll.  Default off (client mode).
--carrier-cmd [CMD]           Use CMD for each carrier (env: CARRIER_LOCAL, CARRIER_REMOTE). For local testing without SSH.
--server-socket [PATH]         Use PATH as server socket; do not launch server via SSH (requires --carrier-cmd).
```


## How it works

When `ssh-oll` is started, it opens a connection to the SSH host to launch the server using `ssh lossy-ssh-host "ssh-oll --server localhost 22"`. The server creates a Unix socket such as `/tmp/ssh-oll-server.abc123def` with permissions so only the current user can access it, prints the socket path, then daemonizes and closes the initial SSH connection. The client then opens multiple carrier connections with commands like `ssh -L /tmp/ssh-oll-client.hgi456789/0:/tmp/ssh-oll-server.abc123def lossy-ssh-host`, and so on for each carrier. The client can open up to `--max-connections` sessions; by default the count is adapted automatically based on observed packet loss. The client manages connections and monitors health using PING packets; the server replies with PONG. Both client and server are single-threaded, using epoll to manage connections and subprocesses.

**Lifecycle and cleanup:** The server exits when the inner SSH session to localhost:22 (or the configured host/port) ends. On exit it removes its Unix socket. Each session uses a unique random suffix in the socket path (e.g. `abc123def`), so multiple ssh-oll clients can use the same host concurrently.

**Failure and reconnection:** If carrier connections drop, the client can open additional carriers (up to `--max-connections`) to keep the logical stream alive. If all carriers are lost, the session fails; reconnecting requires a new SSH (and ssh-oll) session.

### Ordering

SSH is a single ordered byte stream. Packets are sent over multiple carriers and may arrive out of order or be lost. The **packet header `id`** groups data that must be delivered in order: all packets sharing the same `id` form a logical group. The receiver must buffer out-of-order packets and only pass data to the inner SSH stream once every packet in that group has been received (or recovered via redundancy). Concretely: each group has a sequence (e.g. per-id sub-ordering or a global stream offset), and the receiver reassembles groups in order before writing to the backend socket. Additional wire details (e.g. group size, sequence within group) can be carried in the packet payload or in a small extension to the header as the design is implemented.

### Backpressure

When outgoing carrier links are full, the client stops reading from stdin (the local SSH client). That naturally back-pressures the SSH client. To avoid stalling indefinitely, the client should also try to open new carrier SSH connections when buffers are persistently full, so more capacity is available to push data through. Thus backpressure both throttles the producer and triggers growth of the carrier set.

### Security

Security is not a primary focus of this layer: the payload is already an SSH session, so traffic is encrypted and authenticated by SSH. The Unix socket is restricted to the current user. The threat model assumes the same as using SSH alone; ssh-oll does not add new cryptographic or authentication mechanisms.

### Platform and dependencies

The implementation uses **epoll** and is aimed at Linux. Dependencies include a Reed–Solomon (erasure coding) library; other build/runtime deps TBD as the codebase is implemented.

## Packet format (wire protocol)

```
enum packet_kind_e : uint8_t {
    PACKET_PING = 0,              // client -> server; server replies with PONG for health checks
    PACKET_PONG = 1,               // server -> client; response to PING
    PACKET_SMALL = 2,
    PACKET_REED_SOLOMON = 3,
    PACKET_SET_CONFIG = 4,        // client -> server; adjust redundancy / packet size etc.
    PACKET_START_CONNECTION = 5,  // sent when a new carrier joins; used to associate the carrier with the logical stream
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
    uint16_t size;
    uint8_t n, k; // Reed–Solomon: n = total symbols, k = data symbols
    uint8_t data[]; // encoded data
};
struct __attribute__((__packed__)) packet_config : packet_header {
    // client -> server: configure redundancy and transmission settings
    uint16_t packet_size;
    uint16_t small_packet_redundancy;
    float max_delay_ms;
    float reed_solomon_redundancy;
    // other fields as needed
};

```

## Testing

### Local testing with the Python proxy (no SSH or tc)

The script `test_latency_proxy.py` sits between the ssh-oll client and server. It does not parse packets: it forwards bytes between the client’s carrier connections and the server’s carrier connections, and can inject latency and drop connections. The server’s “backend” TCP connection goes to the script (so no real SSH/sshd). You can optionally have the script run the client and measure one-way latency.

1. **Start the proxy**: run `./test_latency_proxy.py` (optionally `--latency-ms 50` or `--drop-rate 0.1`). It prints a TCP port and a Unix path (e.g. `/tmp/ssh-oll-test-script`). When prompted, paste the server socket path (you’ll get it in step 2).

2. **Start the server** (in another terminal): run `./ssh-oll --server 127.0.0.1 <TCP port from step 1>`. The server connects to the proxy as its backend and prints its Unix socket path (e.g. `/tmp/ssh-oll-server.abc123def`). Paste that path into the proxy’s prompt if you didn’t use `--server-socket`.

3. **Start the client** (or use `--run-client`): either run the client yourself so its carriers connect to the proxy’s Unix path:
   ```bash
   ./ssh-oll --carrier-cmd 'socat UNIX-LISTEN:$CARRIER_LOCAL,reuseaddr,fork UNIX-CONNECT:$CARRIER_REMOTE' \
     --server-socket /tmp/ssh-oll-test-script --connections 4 localhost
   ```
   or run the proxy with `--run-client` so it spawns the client, sends timestamped random data, and reports one-way latency over the TCP connection.

**Proxy options:** `--server-socket PATH` (or prompt), `--unix-path`, `--connections`, `--latency-ms`, `--drop-rate`, `--run-client`.

### Lossy link with tc

You can simulate packet loss and delay using Linux `tc` and the `netem` qdisc. The script `test.sh` demonstrates one way to set up a lossy environment. See `./test.sh --help` for options.

## License

MIT. See [LICENSE](LICENSE) in this repository.
