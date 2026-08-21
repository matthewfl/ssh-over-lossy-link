#ifndef SSH_OLL_SSHOLL_H
#define SSH_OLL_SSHOLL_H

#include <cstdint>
#include <string>

namespace ssholl {

// -----------------------------------------------------------------------------
// Wire protocol: packet kinds and packet layouts (must match README).
// All multi-byte fields are stored in natural byte order (implementation
// can swap for wire if needed). Structs are packed for wire representation.
// -----------------------------------------------------------------------------

enum class PacketKind : uint8_t {
  PING = 0,               // client -> server; server replies with PONG
  PONG = 1,               // server -> client; response to PING
  SMALL = 2,
  REED_SOLOMON = 3,
  SET_CONFIG = 4,         // client -> server: adjust redundancy / packet size
  START_CONNECTION = 5,   // new carrier joins; associate carrier with stream
  ACK = 6,                // server -> client; cumulative ack: all data up to id delivered
  SERVER_METRICS = 7,     // server -> client; observed link quality (max RTT etc.) for client adapt
  SERVER_CONFIG = 8,      // server -> client; server's current redundancy config (when server manages it)
  READY = 9,              // server -> client; sent when carrier connects, confirms link is up
  SUGGEST_CLOSE = 10,     // server -> client; suggests client close this carrier (dead or slow)
  CLIENT_METRICS = 11,    // client -> server; s2c path quality so server can adapt using both directions
  CARRIER_STATUS = 12,    // either direction; shared_carrier_ids the sender sees as dead (sent over a healthy carrier)
};

#pragma pack(push, 1)

struct PacketHeader {
  uint64_t id;
  PacketKind packet_kind;
};

// Small packet: header + size + payload. Payload length is `size` bytes and
// follows immediately after this struct in the buffer.
struct PacketSmall {
  PacketHeader header;
  uint16_t size;
  uint8_t data[1];  // variable; actual length is `size`
};

// Reed–Solomon shard: one packet carries one shard (same id for whole block).
// Layout: header + size (block_size) + n, k + shard_index + shard data.
struct PacketReedSolomon {
  PacketHeader header;
  uint16_t size;       // block_size (shard length in bytes)
  uint8_t n;
  uint8_t k;
  uint8_t shard_index; // which shard 0..n-1
  uint8_t data[1];     // variable; exactly size bytes
};

// Client -> server: first packet on a newly connected carrier. Tells the server this
// connection's shared carrier id (the client is the sole carrier authority), so both
// sides can name the same carrier when reporting health / attributing RS shards.
struct PacketStartConnection {
  PacketHeader header;
  uint64_t carrier_id;
};

// Client -> server: configure redundancy and transmission.
struct PacketConfig {
  PacketHeader header;
  uint16_t packet_size;
  uint16_t small_packet_redundancy;
  float max_delay_ms;
  float reed_solomon_redundancy;
  uint8_t auto_adapt;  // 1 = server may adapt and send SERVER_CONFIG; 0 = server only applies SET_CONFIG
  // Reconnect/idle timeout in seconds. 0 = use adaptive formula (12×RTT, min 60 s, max 300 s).
  // When non-zero, both sides use this fixed value as their global_idle_ns threshold.
  uint32_t reconnect_timeout_sec;
};

// Server -> client: link quality observed by server so client can adapt.
// avg_shard_spread_ns: rolling average of (time-from-first-shard-to-last-needed-shard) for
//   RS groups received on the client→server path.  Zero means all shards arrived together
//   (healthy); non-zero means the server had to wait for a lagging/lost shard.  Independent
//   of the link's base RTT so the client can tell whether RS is struggling even on a
//   high-latency link where RTTs are uniformly slow.
struct PacketServerMetrics {
  PacketHeader header;
  uint64_t max_rtt_ns;
  uint64_t avg_shard_spread_ns;     // avg spread (1st→k-th shard) for c2s RS groups
  uint64_t avg_extra_shard_gap_ns;  // avg gap (k-th→(k+1)-th shard) for c2s RS groups
  uint32_t rs_pending_count;        // c2s RS groups server is waiting to decode; client may add carriers
  uint32_t flags;                   // SSHOLL_SERVER_METRICS_FLAG_* status bits
};

// SERVER_METRICS flags bit 0: the server's server→client send window is saturated — the
// link is at capacity and the ACK-clocked RateWindow deliberately forbids more bytes in
// flight. The client must not grow carriers on load pressure in that state: spreading the
// same bounded bytes across more carriers cannot raise throughput, yet the stall fraction
// stays high on a capacity-limited queue and would otherwise drive the count to the max.
static constexpr uint32_t SSHOLL_SERVER_METRICS_FLAG_S2C_WINDOW_SATURATED = 1u << 0;

// Server -> client: server's current redundancy config (when auto_adapt; client stays in sync).
struct PacketServerConfig {
  PacketHeader header;
  uint16_t packet_size;
  uint16_t small_packet_redundancy;
  float max_delay_ms;
  float reed_solomon_redundancy;
};

// Client -> server: s2c path quality (server receives, client sends). Server merges with c2s for adapt.
struct PacketClientMetrics {
  PacketHeader header;
  uint64_t avg_shard_spread_ns;
  uint64_t avg_extra_shard_gap_ns;
  float fraction_struggling;
  uint32_t rs_pending_count;
  uint8_t can_decrease_rs;    // p90 extra-shard gap < 0.5ms on s2c
  uint8_t can_decrease_small; // p90 first→median gap < 1.5ms on s2c
  uint8_t c2s_window_saturated; // client's client→server send window deliberately full
  // (link at capacity). The server then clamps rs redundancy: under provable saturation
  // shard lateness is queueing, so extra parity would only re-share the same bytes from
  // data onto overhead (observed: rs pinned at the 2.0 ceiling → 4× goodput collapse on
  // a capacity-limited but lossless simulated link).
};

// Either direction: the shared_carrier_ids the sender currently believes are dead (its
// receive side has gone silent on them while peers keep delivering). Sent over a healthy
// carrier so the news arrives even though nothing succeeds on the dead carrier itself.
// Header followed by `count` little-endian uint64 carrier ids.
struct PacketCarrierStatus {
  PacketHeader header;
  uint16_t count;
  // uint64_t dead_carrier_ids[count];
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Runtime configuration (from CLI and PACKET_SET_CONFIG).
// -----------------------------------------------------------------------------

struct Config {
  bool auto_adapt = true;
  std::string path_on_server = "ssh-oll";
  unsigned connections = 10;
  unsigned max_connections = 50;
  unsigned packet_size = 400;
  unsigned small_packet_redundancy = 2;
  float rs_redundancy = 0.1f;
  float max_delay_ms = 1.0f;
  unsigned rtt_hint_ms = 0;  // 0 = auto from observed latency; else hint for cold-start timeouts
  unsigned connect_timeout_sec = 30;  // SSH ConnectTimeout; 0 = no timeout (wait indefinitely)
  unsigned min_data_per_minute = 100;  // keepalive: each carrier sends >=N bytes/min (spread over
                                       // 10s windows) so an idle link still touches every carrier and
                                       // a firewall/NAT doesn't close it. 0 disables. This is the ONLY
                                       // idle keepalive (blanket pinging was removed); default it on.
  unsigned reconnect_timeout_sec = 0; // global idle timeout; 0 = adaptive (12×RTT, min 60 s, max 300 s)
  unsigned max_added_latency_ms = 10; // RESERVED / currently unused. The redundancy model used to
                                      // count a shard "late" if it arrived >B(=this) after its
                                      // group's first shard, but that saturated on base jitter; the
                                      // stall threshold is now RTT-relative (carrier_adapt::
                                      // stall_threshold_ns). Kept so the flag still parses.
};

// -----------------------------------------------------------------------------
// Parsed command-line arguments.
// -----------------------------------------------------------------------------

struct Args {
  Config config;
  bool server_mode = false;
  bool debug = false;           // write debug logs to /tmp/ssh-oll-{client,server}-<pid>.log
  std::string lossy_ssh_host;   // required in client mode unless unix_socket_connection is set
  std::string remote_hostname = "localhost";
  uint16_t remote_port = 22;
  std::string unix_socket_connection;  // if non-empty, connect directly to this socket (no SSH -L)
  // TEST AID: apply the SSH-spawn-mode dead-carrier POLICY (the conservative dead_idle skip)
  // even though carriers are local sockets. Lets the no-SSH test harness exercise the same
  // code branches that production (real SSH carriers) runs.
  bool force_ssh_carrier_mode = false;
  std::string file_lock;              // if non-empty, acquire exclusive lock on this file before client start
};

// Parse argc/argv into Args. Returns true on success; otherwise prints usage
// to stderr and returns false.
bool parse_args(int argc, char* argv[], Args& out);

// Print usage to stderr.
void usage(const char* program_name);

// Run server: Unix socket, epoll, forward carriers to TCP. Returns exit code.
int run_server(const Args& args);

// Run client: launch server, open N carriers, multiplex stdin/stdout. Returns exit code.
int run_client(const Args& args);

}  // namespace ssholl

#endif /* SSH_OLL_SSHOLL_H */
