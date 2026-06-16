#ifndef SSH_OLL_NET_UTIL_H
#define SSH_OLL_NET_UTIL_H

// Small shared utilities used by both the client and the server: a monotonic clock,
// RTT percentile / timeout scaling, and the unacked-retransmit buffer entry. These were
// previously duplicated (and at risk of drifting) in client.cc and server.cc.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <vector>

namespace ssholl {

// Monotonic clock in nanoseconds (steady_clock).
inline uint64_t now_ns() {
  return static_cast<uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
}

// 90th-percentile of a set of RTT samples (nanoseconds). Precondition: non-empty.
// Uses the same index convention as the original inline code: sorted[size * 0.9].
inline uint64_t p90_ns(const std::deque<uint64_t>& samples) {
  std::vector<uint64_t> sorted(samples.begin(), samples.end());
  std::sort(sorted.begin(), sorted.end());
  return sorted[static_cast<size_t>(sorted.size() * 0.9)];
}

// RTT-scaled timeout: clamp(mult * effective_rtt_ns, min_ns, max_ns). The caller
// supplies the effective RTT because client and server derive it differently.
inline uint64_t scaled_ns(unsigned mult, uint64_t min_ns, uint64_t max_ns,
                          uint64_t effective_rtt_ns) {
  uint64_t v = static_cast<uint64_t>(mult) * effective_rtt_ns;
  if (v < min_ns) return min_ns;
  if (v > max_ns) return max_ns;
  return v;
}

// Unacked-send retransmit buffer entry: holds the original pre-encoded data for an
// outstanding send_id so it can be re-encoded and resent on another carrier when a
// carrier dies. Used by both directions (client→server and server→client).
struct UnackedItem {
  std::vector<uint8_t> data;   // RS: k*block_size bytes; SMALL: raw bytes
  unsigned n = 0;
  unsigned k = 0;
  uint16_t block_size = 0;
  bool is_small = false;
  uint64_t send_ns = 0;        // when originally sent (for timeout-based retransmit)
  // Which logical carriers have already carried this send, so retransmits avoid
  // reusing the same carrier. SMALL: set of carrier_ids that saw this id. RS: per-shard.
  std::set<uint64_t> small_sent_on;
  std::map<unsigned, std::set<uint64_t>> rs_shard_sent_on;  // shard_index -> carrier_ids
};

}  // namespace ssholl

#endif  // SSH_OLL_NET_UTIL_H
