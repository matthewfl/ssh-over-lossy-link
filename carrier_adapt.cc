#include "carrier_adapt.h"
#include <algorithm>

namespace ssholl {

namespace carrier_adapt {

PathMetrics compute_from_deques(
    const std::deque<uint64_t>& shard_spread_ns,
    const std::deque<uint64_t>& gap_final_ns,
    const std::deque<uint64_t>& extra_shard_gap_ns,
    const std::deque<uint64_t>& small_extra_copy_gap_ns) {
  PathMetrics m;
  if (shard_spread_ns.empty()) return m;

  auto deque_avg = [](const std::deque<uint64_t>& d) -> uint64_t {
    if (d.empty()) return 0;
    uint64_t sum = 0;
    for (uint64_t v : d) sum += v;
    return sum / d.size();
  };
  m.avg_shard_spread_ns = deque_avg(shard_spread_ns);
  m.avg_extra_shard_gap_ns = deque_avg(extra_shard_gap_ns);

  size_t n_struggling = 0;
  for (size_t i = 0; i < shard_spread_ns.size(); ++i) {
    uint64_t spread = shard_spread_ns[i];
    uint64_t gfinal = (i < gap_final_ns.size()) ? gap_final_ns[i] : 0;
    if (spread > kSpreadIncreaseThresholdNs && gfinal > spread / 2)
      n_struggling++;
  }
  m.fraction_struggling = static_cast<float>(n_struggling) /
      static_cast<float>(shard_spread_ns.size());

  if (extra_shard_gap_ns.size() >= 10) {
    std::vector<uint64_t> sg(extra_shard_gap_ns.begin(), extra_shard_gap_ns.end());
    std::sort(sg.begin(), sg.end());
    m.can_decrease_rs = sg[(sg.size() * 9) / 10] < kExtraGapDecreaseThresholdNs;
  }
  if (small_extra_copy_gap_ns.size() >= 5) {
    std::vector<uint64_t> sg(small_extra_copy_gap_ns.begin(), small_extra_copy_gap_ns.end());
    std::sort(sg.begin(), sg.end());
    m.can_decrease_small = sg[(sg.size() * 9) / 10] < kSmallPacketGapDecreaseThresholdNs;
  }
  return m;
}

float approximate_fraction_struggling_from_avg_spread(uint64_t avg_shard_spread_ns) {
  return (avg_shard_spread_ns > kSpreadIncreaseThresholdNs)
      ? kFractionSlowIncreaseFast * 2.0f : 0.0f;
}

PathMetrics merge(const PathMetrics& c2s, const PathMetrics& s2c, bool s2c_fresh) {
  PathMetrics m = c2s;
  if (s2c_fresh) {
    m.fraction_struggling = std::max(m.fraction_struggling, s2c.fraction_struggling);
    m.can_decrease_rs = m.can_decrease_rs && s2c.can_decrease_rs;
    m.can_decrease_small = m.can_decrease_small && s2c.can_decrease_small;
  }
  return m;
}

AdaptResult run_adapt(const PathMetrics& merged,
                     float current_rs, unsigned current_small,
                     unsigned n_carriers) {
  AdaptResult r;
  r.rs_redundancy = current_rs;
  r.small_packet_redundancy = current_small;
  r.clear_spread = false;

  if (merged.fraction_struggling > kFractionSlowIncreaseFast) {
    r.rs_redundancy = std::min(2.0f, r.rs_redundancy + 0.10f);
    r.small_packet_redundancy = std::min(20u, r.small_packet_redundancy + 1u);
    r.clear_spread = true;
  } else if (merged.fraction_struggling > kFractionSlowIncreaseMedium) {
    r.rs_redundancy = std::min(2.0f, r.rs_redundancy + 0.05f);
    r.clear_spread = true;
  } else {
    if (merged.can_decrease_rs && merged.fraction_struggling < kFractionSlowDecrease)
      r.rs_redundancy = std::max(0.1f, r.rs_redundancy - 0.02f);
  }
  if (merged.can_decrease_small) {
    unsigned decr = (r.small_packet_redundancy > 10u) ? 2u : 1u;
    r.small_packet_redundancy = std::max(2u, r.small_packet_redundancy - decr);
  }
  r.small_packet_redundancy = std::min(r.small_packet_redundancy,
                                       std::max(1u, n_carriers));
  return r;
}

CarrierQualityResult assess_carriers(
    const std::vector<CarrierInfo>& carriers,
    uint64_t now_ns,
    ScaledNsFn scaled_ns) {
  CarrierQualityResult res;
  if (carriers.empty()) return res;

  uint64_t dead_idle_ns = scaled_ns(5, 15000000000ULL, 120000000000ULL);
  uint64_t grace_ns = scaled_ns(2, 5000000000ULL, 30000000000ULL);
  uint64_t very_high_ns = scaled_ns(3, 5000000000ULL, 30000000000ULL);

  for (const auto& c : carriers) {
    if (now_ns - c.connect_ns < grace_ns) continue;
    // Use the most recent of connect, last recv, or last send.
    // Including last_send prevents falsely closing a carrier that is actively
    // pushing data outward but hasn't received a response yet (e.g. full write
    // buffer suppressing PINGs on both sides under heavy bidirectional load).
    uint64_t last_activity = std::max({c.connect_ns, c.last_recv_ns, c.last_send_ns});
    if (now_ns - last_activity > dead_idle_ns)
      res.dead_idle_fds.push_back(c.fd);
  }

  if (carriers.size() > 1) {
    std::vector<uint64_t> rtts;
    for (const auto& c : carriers)
      if (c.last_rtt_ns > 0) rtts.push_back(c.last_rtt_ns);
    if (rtts.size() >= 2) {
      std::vector<uint64_t> sorted = rtts;
      std::sort(sorted.begin(), sorted.end());
      uint64_t median_rtt = sorted[sorted.size() / 2];
      int worst_fd = -1;
      uint64_t worst_rtt = 0;
      for (const auto& c : carriers)
        if (c.last_rtt_ns > worst_rtt) {
          worst_rtt = c.last_rtt_ns;
          worst_fd = c.fd;
        }
      if (worst_fd >= 0 && worst_rtt > 5 * median_rtt && worst_rtt > very_high_ns)
        res.rtt_outlier_fd = worst_fd;
    }
  }
  return res;
}

}  // namespace carrier_adapt

}  // namespace ssholl
