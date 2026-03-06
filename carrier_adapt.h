// Shared logic for carrier quality monitoring and redundancy adaptation.
// Server and client use the same logic; server suggests close, client performs close/add.
#ifndef SSH_OLL_CARRIER_ADAPT_H
#define SSH_OLL_CARRIER_ADAPT_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <vector>

namespace ssholl {

namespace carrier_adapt {

// Thresholds for adapt (shared between client and server).
constexpr float kFractionSlowIncreaseFast = 0.05f;    // >5% struggling → big increase
constexpr float kFractionSlowIncreaseMedium = 0.01f;  // >1% struggling → medium increase
constexpr float kFractionSlowDecrease = 0.01f;       // <1% struggling → decrease
constexpr size_t kMinSamplesForAdapt = 20;
constexpr uint64_t kSpreadIncreaseThresholdNs = 2000000ULL;       // 2 ms
constexpr uint64_t kExtraGapDecreaseThresholdNs = 500000ULL;     // 0.5 ms
constexpr uint64_t kSmallPacketGapDecreaseThresholdNs = 1500000ULL;  // 1.5 ms

// Path metrics computed from one direction (c2s or s2c).
struct PathMetrics {
  float fraction_struggling = 0.0f;
  bool can_decrease_rs = false;
  bool can_decrease_small = false;
  uint64_t avg_shard_spread_ns = 0;
  uint64_t avg_extra_shard_gap_ns = 0;
};

// Compute metrics from raw deque samples (for the path we measure locally).
PathMetrics compute_from_deques(
    const std::deque<uint64_t>& shard_spread_ns,
    const std::deque<uint64_t>& gap_final_ns,
    const std::deque<uint64_t>& extra_shard_gap_ns,
    const std::deque<uint64_t>& small_extra_copy_gap_ns);

// Approximate c2s fraction_struggling from avg_shard_spread (when we only have aggregates).
float approximate_fraction_struggling_from_avg_spread(uint64_t avg_shard_spread_ns);

// Merge c2s + s2c for dual-path adapt. When s2c_fresh, require both to allow decrease.
PathMetrics merge(const PathMetrics& c2s, const PathMetrics& s2c, bool s2c_fresh);

// Adapt result: new redundancy values. clear_spread tells caller to clear c2s deques on increase.
struct AdaptResult {
  float rs_redundancy;
  unsigned small_packet_redundancy;
  bool clear_spread;
};

// Run redundancy adapt from merged path metrics.
AdaptResult run_adapt(const PathMetrics& merged,
                     float current_rs, unsigned current_small,
                     unsigned n_carriers);

// Carrier quality: which carriers should be closed or suggested for close?
struct CarrierInfo {
  int fd;
  uint64_t last_rtt_ns;
  uint64_t last_recv_ns;
  uint64_t connect_ns;
  uint64_t last_send_ns = 0;
};

struct CarrierQualityResult {
  std::vector<int> dead_idle_fds;  // no activity for too long
  int rtt_outlier_fd = -1;         // worst carrier when 5× median; -1 if none
};

// scaled_ns(mult, min_ns, max_ns) -> ns, typically RTT-scaled.
using ScaledNsFn = std::function<uint64_t(unsigned, uint64_t, uint64_t)>;

CarrierQualityResult assess_carriers(
    const std::vector<CarrierInfo>& carriers,
    uint64_t now_ns,
    ScaledNsFn scaled_ns);

}  // namespace carrier_adapt

}  // namespace ssholl

#endif  // SSH_OLL_CARRIER_ADAPT_H
