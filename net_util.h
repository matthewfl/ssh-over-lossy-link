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
  bool retransmitted = false;  // set once this item has been resent; its ACK's RTT is then
                               // ambiguous (Karn's algorithm) and must not be timed.
  // Which logical carriers have already carried this send, so retransmits avoid
  // reusing the same carrier. SMALL: set of carrier_ids that saw this id. RS: per-shard.
  std::set<uint64_t> small_sent_on;
  std::map<unsigned, std::set<uint64_t>> rs_shard_sent_on;  // shard_index -> carrier_ids
};

// ACK-clocked send window shared by both sides: bounds the number of DATA bytes sent
// but not yet ACKed, so a producer faster than the link (a download peer outrunning
// the path) can NOT build an unbounded queue — with no bound, the queuing delay itself
// inflates every RTT-derived timeout/estimator and the tunnel folds into a retransmit
// storm (observed: 23 MB buffered, ~13 KB/s goodput on a 256 KB/s link; users saw
// multi-second lag spikes on a 500 ms link).
//
// The cap = delivered rate x kBudgetSec, clamped [floor, ceil]:
//   • the RATE comes from ACK clocking, so it is self-limiting at the real link speed;
//   • the BUDGET is a CONSTANT time — deliberately NOT derived from the measured RTT.
//     The controller must not size its pipe from a delay its own standing queue
//     maintains: under a persistently-greedy producer every RTT sample includes some
//     queue, so even a min-RTT-derived budget ratchets the cap upward until the clamp
//     (the degraded state this fixes). With a constant budget >= path RTT, a greedy
//     producer equilibrates at a ~budget-deep queue and the max added latency IS the
//     budget — bounded by design, at full link utilization while RTT <= budget.
//   • the time budget is max(kBudgetSec, base_rtt): the cap must cover the path's
//     bandwidth×delay product or the window itself becomes the bottleneck (a 128 KB
//     floor window on a ~0.75 s RTT link topples to ~150 KB/s far below capacity).
//     base_rtt must be the SESSION-MINIMUM RTT: any queueing can only raise an RTT
//     sample, so a monotone session min cannot ratchet the cap upward the way a
//     recent-window estimator would (recent-window min inflates with the very queue
//     the cap maintains; a session min provably converges from above to the true
//     base RTT — measured once, at the cold-start warmup which has no load yet).
//   • a window "opens" when it is empty or below the cap, so at least one RS group is
//     always in flight (no deadlock even when one group exceeds the cap).
//
// Interactive SMALL packets are counted in the outstanding bytes but never gated —
// they are tiny, and jumping the (now-bounded) queue is exactly what keeps typing
// responsive behind a bulk transfer.
//   • the estimator must measure CAPACITY, not throughput: delivered bytes divided by
//     the fold interval confounds the window's own throttling (a window closed mid-fold
//     reports its own clamp, shrinking the cap into a low fixpoint — observed ~35% of a
//     256 KB/s link on a 500 ms pipe), while first→last ACK burst spacing explodes upward
//     with coalesced cumulative ACKs (packing a whole fold's bytes into ~ms "active" time
//     blew the cap to the 4 MB ceiling and admitted 845 groups at once — observed). So
//     track the fold's time with the window OPEN: while open AND full, deliveries run at
//     bottleneck speed; rate = fold_bytes / open-time.
struct RateWindow {
  double rate_bps = 0.0;        // EWMA of capacity (open-time delivered rate), bytes/s
  uint64_t fold_bytes = 0;      // ACKed bytes accumulated in the current fold interval
  uint64_t last_fold_ns = 0;    // start of the current fold interval

  static constexpr uint64_t kFoldIntervalNs = 500 * 1000000ULL;   // 500 ms
  static constexpr double kBudgetSec = 1.0;                       // queue budget on top of base-RTT
  static constexpr double kHeadroomMult = 1.25;                   // probe shift: lifts the stall point toward capacity
  static constexpr uint64_t kFloorBytes = 128 * 1024;             // cold-start / min cap (scales with base_s)
  static constexpr uint64_t kCeilBytes = 4 * 1024 * 1024;         // sanity ceiling
};

inline void rate_window_on_ack(RateWindow& w, uint64_t acked_bytes, uint64_t now_ns) {
  w.fold_bytes += acked_bytes;
  if (w.last_fold_ns == 0) w.last_fold_ns = now_ns;
  uint64_t dt = now_ns - w.last_fold_ns;
  if (dt >= RateWindow::kFoldIntervalNs) {
    double inst = static_cast<double>(w.fold_bytes) / (static_cast<double>(dt) / 1e9);
    w.rate_bps = (w.rate_bps > 0.0) ? (0.5 * w.rate_bps + 0.5 * inst) : inst;
    w.fold_bytes = 0;
    w.last_fold_ns = now_ns;
  }
}

inline uint64_t rate_window_cap(const RateWindow& w, uint64_t base_rtt_ns) {
  // Budget = base-RTT PLUS the queue budget: the cap must cover the bandwidth×delay
  // product (or the window itself becomes the bottleneck and locks at a low-rate
  // fixpoint below the floor: cap(T+1) = cap(T) × budget/RTT_eff shrinks whenever
  // budget < RTT_eff). base is a session min, which queueing can never inflate.
  double budget_s = (static_cast<double>(base_rtt_ns) / 1e9 + RateWindow::kBudgetSec) * RateWindow::kHeadroomMult;
  uint64_t cap = static_cast<uint64_t>(w.rate_bps * budget_s);
  // The floor scales with base RTT so a slow path's BDP is covered before the estimate
  // learns the capacity (otherwise a satellite link would crawl at 128 KB/RTT).
  uint64_t floor = static_cast<uint64_t>(RateWindow::kFloorBytes *
                                         std::max(1.0, static_cast<double>(base_rtt_ns) / 1e9));
  if (w.rate_bps <= 0.0) return floor;
  return std::min(RateWindow::kCeilBytes, std::max(floor, cap));
}

inline bool rate_window_open(uint64_t outstanding_bytes, const RateWindow& w,
                             uint64_t base_rtt_ns) {
  return outstanding_bytes == 0 || outstanding_bytes < rate_window_cap(w, base_rtt_ns);
}

}  // namespace ssholl

#endif  // SSH_OLL_NET_UTIL_H
