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

// Per-carrier connection state. Client may set connecting and last_rtt_ns.
struct CarrierState {
  std::vector<uint8_t> read_buf;
  std::vector<uint8_t> write_buf;
  size_t write_pos = 0;
  bool connecting = false;   // client: true until connect() completes
  uint64_t last_rtt_ns = 0;  // client: last RTT from ACK
};

// Per-id state when collecting Reed-Solomon shards.
struct RsPending {
  unsigned n = 0;
  unsigned k = 0;
  size_t block_size = 0;
  std::map<unsigned, std::vector<uint8_t>> shards;
};

// Callbacks used when processing received packets. Set only the ones you need.
struct ReceiveCallbacks {
  // Delivered contiguous data (id, data, len). Server writes to backend and queues ACK; client writes to stdout.
  std::function<void(uint64_t id, const uint8_t* data, size_t len)> on_deliver;
  // Client -> server PING; server should send PONG.
  std::function<void(int fd, uint64_t id)> on_ping;
  // Server -> client ACK; client may record RTT.
  std::function<void(int fd, uint64_t acked_id)> on_ack;
  // Client -> server SET_CONFIG; server should apply config.
  std::function<void(const PacketConfig&)> on_set_config;
};

// Process bytes from carrier read_buf: parse SMALL/REED_SOLOMON, update reassembly/rs_pending,
// advance next_deliver_id, invoke on_deliver for contiguous data. Invoke on_ping/on_ack/on_set_config
// for control packets. Mutates s.read_buf, reassembly, rs_pending, next_deliver_id.
// Returns false if the connection should be closed (eof or error).
bool process_carrier_read(
  int fd,
  CarrierState& s,
  std::map<uint64_t, std::vector<uint8_t>>& reassembly,
  std::map<uint64_t, RsPending>& rs_pending,
  uint64_t& next_deliver_id,
  const ReceiveCallbacks& callbacks);

// Append packet to a carrier's write_buf (or any buffer). Used by both client and server.
void append_small(std::vector<uint8_t>& out, uint64_t id, const uint8_t* data, size_t len);
void append_rs_shard(std::vector<uint8_t>& out, uint64_t id, unsigned n, unsigned k,
                    uint16_t block_size, unsigned shard_index, const uint8_t* shard_data);
void append_config(std::vector<uint8_t>& out, uint16_t packet_size, uint16_t small_packet_redundancy,
                  float max_delay_ms, float reed_solomon_redundancy);
void append_ack(std::vector<uint8_t>& out, uint64_t acked_id);
void append_pong(std::vector<uint8_t>& out, uint64_t id);

// Flush write_buf of all carriers to their fds. Removes and closes fd on write error.
// skip_write: if non-null, skip flushing for carriers where skip_write(fd, state) is true (e.g. client: connecting).
void flush_carrier_writes(
  std::map<int, CarrierState>& carriers,
  int epfd,
  struct ::epoll_event& ev,
  std::function<bool(int fd, const CarrierState&)> skip_write = nullptr);

}  // namespace packet_io
}  // namespace ssholl

#endif /* SSH_OLL_PACKET_IO_H */
