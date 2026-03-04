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

// Client -> server: configure redundancy and transmission.
struct PacketConfig {
  PacketHeader header;
  uint16_t packet_size;
  uint16_t small_packet_redundancy;
  float max_delay_ms;
  float reed_solomon_redundancy;
  uint8_t auto_adapt;  // 1 = server may adapt and send SERVER_CONFIG; 0 = server only applies SET_CONFIG
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
};

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
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Runtime configuration (from CLI and PACKET_SET_CONFIG).
// -----------------------------------------------------------------------------

struct Config {
  bool auto_adapt = true;
  std::string path_on_server = "ssh-oll";
  unsigned connections = 10;
  unsigned max_connections = 200;
  unsigned packet_size = 400;
  unsigned small_packet_redundancy = 2;
  float rs_redundancy = 0.1f;
  float max_delay_ms = 1.0f;
  unsigned rtt_hint_ms = 0;  // 0 = auto from observed latency; else hint for cold-start timeouts
  unsigned connect_timeout_sec = 30;  // SSH ConnectTimeout; 0 = no timeout (wait indefinitely)
  unsigned min_data_per_minute = 0;   // when >0, send keepalive data so each carrier sends ≥N bytes/min
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
