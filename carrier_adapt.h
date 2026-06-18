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

// Carrier-health predicate thresholds, shared by client and server so the two sides
// cannot silently diverge (the kind of drift that produced the B1 reaper bug).
constexpr uint64_t kHeavyBacklogBytes = 256 * 1024ULL;
constexpr size_t   kHeavyBacklogCount = 128;

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
  // Subset of dead_idle_fds that are *confidently* dead: a peer carrier received data far
  // more recently than this one, so there is active traffic this carrier is missing (not
  // merely a quiet period). The server may close these itself — it can only SUGGEST_CLOSE
  // to the client, which a dead-but-open carrier (e.g. after a WiFi/VPN drop) never
  // receives, so without this the server would retain stale carriers forever and waste
  // retransmits on them instead of reaching the client's live carriers.
  std::vector<int> reap_fds;
  // Carriers silent on our receive side while a peer carrier received much more recently
  // ("rx-dead": delivering nothing while the link is clearly up). Distinct from idle_dead
  // (everyone quiet) — used for group dead-carrier detection without blanket pings.
  std::vector<int> rx_dead_fds;
  int rtt_outlier_fd = -1;         // worst carrier when 5× median; -1 if none
};

// scaled_ns(mult, min_ns, max_ns) -> ns, typically RTT-scaled.
using ScaledNsFn = std::function<uint64_t(unsigned, uint64_t, uint64_t)>;

CarrierQualityResult assess_carriers(
    const std::vector<CarrierInfo>& carriers,
    uint64_t now_ns,
    ScaledNsFn scaled_ns);

// Base "heavy backlog" test from the unacked-retransmit buffer (bytes or item count
// over threshold). The server additionally OR's in its pending-buffer conditions
// (backend_pending / reassembly / rs_pending non-empty) at the call site.
bool is_heavy_backlog(uint64_t unacked_bytes, size_t unacked_count);

// Should a keepalive PING be sent on an idle carrier? True when its write buffer is
// empty and it has had no send *and* no receive activity for ping_idle_ns.
bool should_send_idle_ping(bool write_buf_empty, uint64_t now_ns,
                           uint64_t last_send_ns, uint64_t last_recv_ns,
                           uint64_t ping_idle_ns);

// ── Probability-bounded redundancy model ──────────────────────────────────────
// An RS group of n shards (k data + m parity, one shard per carrier) stalls — needs a
// retransmit, ~1 RTT of head-of-line block — when MORE than m of the n shards are late
// (lost, or stuck behind a per-carrier TCP retransmit). Treating shard lateness as ~iid
// with probability q, the number late ~ Binomial(n, q) and P(stall) = P(X > m). These
// pick the redundancy / copies that hold P(stall) <= eps. See REDUNDANCY_MODEL.md.

// Smallest m (parity shards) with P(Binomial(n,q) > m) <= eps. 0 when q<=0; capped so
// k = n-m >= 1 (a returned m == n-1 with r still too high means "add carriers").
unsigned min_parity_for_stall_bound(unsigned n, double q, double eps);

// Redundancy fraction r = m/(n-m) for that minimal m. n<2 -> a large value (RS needs
// >=2 carriers); caller clamps and/or falls back to small-packet duplication.
float redundancy_for_stall_bound(unsigned n, double q, double eps);

// Smallest number of duplicate copies c for a SMALL packet so P(all lost)=q^c <= eps.
unsigned small_copies_for_loss(double q, double eps);

}  // namespace carrier_adapt

}  // namespace ssholl

#endif  // SSH_OLL_CARRIER_ADAPT_H
