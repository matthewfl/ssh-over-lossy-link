#ifndef SSH_OLL_PACKET_IO_H
#define SSH_OLL_PACKET_IO_H

#include "ssholl.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>
#include <sys/epoll.h>

namespace ssholl {

namespace packet_io {

const size_t MAX_PACKET_PAYLOAD = 65536;
const size_t READ_BUF_SIZE = 65536;

// Per-carrier connection state.
struct CarrierState {
  std::vector<uint8_t> read_buf;
  std::vector<uint8_t> write_buf;
  size_t write_pos = 0;
  bool connecting = false;    // client: true until connect() completes
  uint64_t last_rtt_ns = 0;   // last RTT measured via ACK on this carrier
  uint64_t last_recv_ns = 0;  // last time any packet arrived on this carrier
  uint64_t last_send_ns = 0;  // last time bytes were actually written to this carrier fd
  uint64_t connect_ns = 0;    // when this carrier finished connecting (set by caller)
  uint64_t bytes_sent_this_minute = 0;  // for --min-data-per-minute keepalive
  uint64_t last_minute_reset_ns = 0;    // when bytes_sent_this_minute was last reset
};

// Per-id state when collecting Reed-Solomon shards.
struct RsPending {
  unsigned n = 0;
  unsigned k = 0;
  size_t block_size = 0;
  std::map<unsigned, std::vector<uint8_t>> shards;
  std::map<unsigned, uint64_t> shard_recv_ns;  // shard_index -> arrival time (ns)
  uint64_t first_recv_ns = 0;  // when the first shard for this group arrived
};

// Callbacks used when processing received packets. Set only the ones you need.
struct ReceiveCallbacks {
  // Delivered contiguous data. completing_fd is the carrier whose shard triggered delivery (use for ACK).
  // Server writes to backend and queues ACK on completing_fd; client writes to stdout and ACKs on completing_fd.
  std::function<void(int completing_fd, uint64_t id, const uint8_t* data, size_t len)> on_deliver;
  // Client -> server PING; server should send PONG. Server -> client PING; client should send PONG.
  // payload_size: if >0, PING had keepalive payload; responder should send PONG with payload.
  std::function<void(int fd, uint64_t id, size_t payload_size)> on_ping;
  // PONG received (response to our PING). Caller may record RTT (e.g. server measures server→client path).
  std::function<void(int fd, uint64_t id)> on_pong;
  // Server -> client ACK; client may record RTT.
  std::function<void(int fd, uint64_t acked_id)> on_ack;
  // Client -> server SET_CONFIG; server should apply config.
  std::function<void(const PacketConfig&)> on_set_config;
  // Fired each time an RS group is fully decoded.
  //   shards_received: how many shards arrived before decode was possible (>= k)
  //   n:              total shards sent for this group
  //   shard_spread_ns: time from the 1st shard to the k-th (last-needed) shard.
  //                   Independent of link RTT: zero means all arrived together.
  //   gap_final_ns:   time between the (k-1)-th and k-th shard specifically.
  //                   Large gap_final relative to shard_spread means the last needed
  //                   shard was a bottleneck (group was close to failing).
  std::function<void(unsigned shards_received, unsigned n,
                     uint64_t shard_spread_ns, uint64_t gap_final_ns)> on_rs_decode;
  // Fired when the first "extra" shard (beyond the k needed) arrives for a recently
  // decoded group.  gap_ns is the time from when the k-th shard arrived (decode
  // triggered) to when this (k+1)-th shard arrived.  A consistently small gap means
  // the extra shard was essentially free — we could reduce RS redundancy safely.
  std::function<void(uint64_t gap_ns)> on_rs_extra_shard;
  // Server -> client SERVER_METRICS; client uses for adapt.
  std::function<void(uint64_t max_rtt_ns, uint64_t avg_shard_spread_ns,
                     uint64_t avg_extra_shard_gap_ns, uint32_t rs_pending_count)> on_server_metrics;
  // Server -> client SERVER_CONFIG; server's current redundancy (client uses when auto_adapt).
  std::function<void(const PacketServerConfig&)> on_server_config;
  // Server -> client SUGGEST_CLOSE; client should close this carrier (server thinks it's dead or slow).
  std::function<void(int fd)> on_suggest_close;
  // Client -> server CLIENT_METRICS; server uses s2c path quality for dual-direction adapt.
  std::function<void(uint64_t avg_shard_spread_ns, uint64_t avg_extra_shard_gap_ns,
                     float fraction_struggling, uint32_t rs_pending_count,
                     bool can_decrease_rs, bool can_decrease_small)> on_client_metrics;
  // When we have ≥2 copies of a small packet: gap_ns from first to median arrival.
  // We don't know which copy would be dropped when reducing N→N-1; median is representative.
  std::function<void(uint64_t gap_ns)> on_small_extra_copy;
};

// Process bytes from carrier read_buf: parse SMALL/REED_SOLOMON, update reassembly/rs_pending,
// advance next_deliver_id, invoke on_deliver for contiguous data. Invoke on_ping/on_ack/on_set_config
// for control packets. Mutates s.read_buf, reassembly, rs_pending, next_deliver_id.
// recently_decoded_ns: shared map of (id -> decode_time_ns) for recently decoded RS groups;
//   used to detect and time "extra" shards that arrive after a group has already decoded.
// small_copy_arrival_times: (id -> arrival times of all copies) for small packets; used to measure first→median gap.
//   Caller must pass the same maps across all calls for a session.
// Returns false if the connection should be closed (eof or error).
bool process_carrier_read(
  int fd,
  CarrierState& s,
  std::map<uint64_t, std::vector<uint8_t>>& reassembly,
  std::map<uint64_t, RsPending>& rs_pending,
  std::map<uint64_t, uint64_t>& recently_decoded_ns,
  std::map<uint64_t, std::vector<uint64_t>>& small_copy_arrival_times,
  uint64_t& next_deliver_id,
  const ReceiveCallbacks& callbacks);

// Append packet to a carrier's write_buf (or any buffer). Used by both client and server.
void append_small(std::vector<uint8_t>& out, uint64_t id, const uint8_t* data, size_t len);
void append_rs_shard(std::vector<uint8_t>& out, uint64_t id, unsigned n, unsigned k,
                    uint16_t block_size, unsigned shard_index, const uint8_t* shard_data);
void append_config(std::vector<uint8_t>& out, uint16_t packet_size, uint16_t small_packet_redundancy,
                  float max_delay_ms, float reed_solomon_redundancy, uint8_t auto_adapt);
void append_server_config(std::vector<uint8_t>& out, uint16_t packet_size, uint16_t small_packet_redundancy,
                         float max_delay_ms, float reed_solomon_redundancy);
void append_ack(std::vector<uint8_t>& out, uint64_t acked_id);
void append_pong(std::vector<uint8_t>& out, uint64_t id);
void append_pong(std::vector<uint8_t>& out, uint64_t id, const uint8_t* payload, size_t payload_len);
void append_ping(std::vector<uint8_t>& out, uint64_t id);
void append_ping(std::vector<uint8_t>& out, uint64_t id, const uint8_t* payload, size_t payload_len);
void append_ready(std::vector<uint8_t>& out);
void append_suggest_close(std::vector<uint8_t>& out);
void append_server_metrics(std::vector<uint8_t>& out, uint64_t max_rtt_ns,
                           uint64_t avg_shard_spread_ns, uint64_t avg_extra_shard_gap_ns,
                           uint32_t rs_pending_count);
void append_client_metrics(std::vector<uint8_t>& out, uint64_t avg_shard_spread_ns,
                           uint64_t avg_extra_shard_gap_ns, float fraction_struggling,
                           uint32_t rs_pending_count, bool can_decrease_rs, bool can_decrease_small);

// Flush write_buf of all carriers to their fds. Removes and closes fd on write error.
// skip_write: if non-null, skip flushing for carriers where skip_write(fd, state) is true (e.g. client: connecting).
// on_removed: if non-null, called with (fd, reason) before removing due to write error (for logging/cleanup).
void flush_carrier_writes(
  std::map<int, CarrierState>& carriers,
  int epfd,
  struct ::epoll_event& ev,
  std::function<bool(int fd, const CarrierState&)> skip_write = nullptr,
  std::function<void(int fd, const char* reason)> on_removed = nullptr);

}  // namespace packet_io
}  // namespace ssholl

#endif /* SSH_OLL_PACKET_IO_H */
