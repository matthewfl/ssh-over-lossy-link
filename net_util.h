#ifndef SSH_OLL_NET_UTIL_H
#define SSH_OLL_NET_UTIL_H

// Small shared utilities used by both the client and the server: a monotonic clock,
// RTT percentile / timeout scaling, and the unacked-retransmit buffer entry. These were
// previously duplicated (and at risk of drifting) in client.cc and server.cc.

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <set>
#include <vector>

namespace ssholl {

// ---------------------------------------------------------------------------
// Bounded debug logging
// ---------------------------------------------------------------------------
// Production incident (2026-08-21): a spam path printed on every event-loop pass
// and the server debug log reached 29 GB in ~2 h. Every debug write now goes through
inline bool dbg_rate_allow(uint64_t& last_ns, uint64_t now_ns_v, uint64_t min_interval_ns) {
  if (last_ns != 0 && now_ns_v - last_ns < min_interval_ns) return false;
  last_ns = now_ns_v;
  return true;
}

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
  // Estimated WIRE bytes for this send once in flight (RS: n*block_size, i.e. the
  // data inflated by the redundancy factor; SMALL: payload x copies sent).  The
  // send window compares against these: unacked data otherwise counts one logical
  // copy while Nx bytes queue on carriers, and a duplicated small-packet flood then
  // grows carrier queues ~copies-fold past the cap (measured: ~15x wire overhead,
  // multi-MB queue in 60 s on a 256 KB/s link).  0 = fall back to data.size().
  uint64_t wire_bytes = 0;
  uint64_t wire_cost() const { return wire_bytes ? wire_bytes : data.size(); }
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
struct RateWindow {
  double rate_bps = 0.0;        // EWMA of the ACK-clocked delivered rate, bytes/s
  double prev_fold_rate = 0.0;  // previous fold's instantaneous delivered rate, bytes/s
  uint64_t fold_bytes = 0;      // ACKed bytes accumulated in the current fold interval
  uint64_t last_fold_ns = 0;    // start of the current fold interval

  static constexpr uint64_t kFoldIntervalNs = 500 * 1000000ULL;   // 500 ms
  static constexpr double kBudgetSec = 1.0;                       // queue budget on top of base-RTT
  static constexpr double kHeadroomMult = 1.25;                   // probe shift: lifts the stall point toward capacity
  static constexpr double kProbeMult = 1.6;                         // supply-limited growth probe per fold
  static constexpr double kProbeResponseMult = 1.15;                // grow again only if the rate RESPONDED
  static constexpr uint64_t kFloorBytes = 128 * 1024;             // cold-start / min cap (scales with base_s)
  static constexpr uint64_t kCeilBytes = 4 * 1024 * 1024;         // sanity ceiling
};

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
inline void rate_window_on_ack(RateWindow& w, uint64_t acked_bytes, uint64_t now_ns,
                               uint64_t outstanding_after, uint64_t base_rtt_ns) {
  w.fold_bytes += acked_bytes;
  if (w.last_fold_ns == 0) w.last_fold_ns = now_ns;
  uint64_t dt = now_ns - w.last_fold_ns;
  if (dt >= RateWindow::kFoldIntervalNs) {
    double inst = static_cast<double>(w.fold_bytes) / (static_cast<double>(dt) / 1e9);
    // Supply-limited probe: the plain EWMA locks in at ANY self-confirming equilibrium
    // (measured: ~1/3 of link capacity on ~30% of runs) because the fold-clock is window-driven:
    // few ACKs come while the window is closed, so the measured delivered rate reports its own
    // clamp. If the fold ends with the window still full the link's capacity may exceed what we
    // offered, so probe-grow multiplicatively like a TCP window — but ONLY while each growth
    // actually LIFTS the delivered rate (rate_response): when the bottleneck is the link, growth
    // stops lifting inst and the probe stops. (The bare supply_limited condition is a tautology
    // on an overloaded link — it was always true, and the estimate ran away to the 4 MB ceiling.)
    bool supply_limited = (outstanding_after + w.fold_bytes) >= rate_window_cap(w, base_rtt_ns);
    // The probe via rate-response alone NEVER converges to a saturated-link stop: when the
    // backlog sits in the proxy/kernel and delivery runs at the wire rate, an oversized window
    // still delivers "fold-bytes" at that rate — rate-responsive keeps growing because bytes
    // keep moving, while the QUEUE grows. A saturate-stop: once the backlog is the full queue
    // budget of the rate MEASURED while delivery was running FAST (inst, not the EWMA), the
    // probe freezes and the link's queueing settles at the budget.
    uint64_t budget_cap = static_cast<uint64_t>(
        inst * (static_cast<double>(base_rtt_ns) / 1e9 + RateWindow::kBudgetSec) * RateWindow::kHeadroomMult);
    // …but the saturate-stop must not bind while the cap sits at its FLOOR: the floor
    // cap (128 KB × base_s) exceeds the natural target of ANY depressed-rate estimate
    // (e.g. a lossy link whose decode-stall-stretched ACK clock reads ~30 KB/s), which
    // would freeze the probe forever — exactly the locked-low equilibrium the probe
    // exists to escape.  At the floor we are already admitting the minimum, so letting
    // the probe grow there costs at most one probe cycle of overshooting above the
    // floor; above the floor (rate-derived caps) the stop binds as designed.
    uint64_t floor_bytes = static_cast<uint64_t>(RateWindow::kFloorBytes *
                           std::max(1.0, static_cast<double>(base_rtt_ns) / 1e9));
    bool cap_at_floor = rate_window_cap(w, base_rtt_ns) <= floor_bytes;
    bool queue_saturated = !cap_at_floor && outstanding_after >= budget_cap;
    bool rate_responsive = w.prev_fold_rate == 0.0 ||
                           inst >= w.prev_fold_rate * RateWindow::kProbeResponseMult;
    w.prev_fold_rate = inst;
    // Empty-fold corruption guard: when the window was supply-limited all fold but
    // produced (nearly) no ACKed bytes, the fold carries NO capacity information —
    // delivery was decode-/return-path-stalled behind the saturated link (measured:
    // k-of-n groups complete in ~5 s clumps under sustained loss, so most 500 ms
    // folds read inst=0 and the 0.5/0.5 EWMA locked the estimate around ~40 KB/s
    // on a link capable of 256 KB/s). HOLD the estimate instead of decaying it.
    double floor_rate = static_cast<double>(floor_bytes) /
                        std::max(1.0, static_cast<double>(base_rtt_ns) / 1e9);
    bool silent_saturated = supply_limited && inst < floor_rate * 0.25 && w.rate_bps > 0.0;
    if (supply_limited && rate_responsive && !queue_saturated && w.rate_bps > 0.0)
      inst = std::max(inst, w.rate_bps * RateWindow::kProbeMult);
    if (!silent_saturated)
      w.rate_bps = (w.rate_bps > 0.0) ? (0.5 * w.rate_bps + 0.5 * inst) : inst;
    w.fold_bytes = 0;
    w.last_fold_ns = now_ns;
  }
}



}  // namespace ssholl

#endif  // SSH_OLL_NET_UTIL_H
