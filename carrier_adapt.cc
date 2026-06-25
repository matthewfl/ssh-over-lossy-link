#include "carrier_adapt.h"
#include <algorithm>
#include <cmath>

namespace ssholl {

namespace carrier_adapt {

unsigned min_parity_for_stall_bound(unsigned n, double q, double eps) {
  if (n == 0) return 0;
  if (q <= 0.0) return 0;          // no loss -> no parity needed
  if (q >= 1.0) return n;          // total loss -> impossible at this n
  if (eps <= 0.0) eps = 1e-12;
  // Walk the Binomial(n,q) PMF iteratively (stable for n up to a few hundred) and stop at
  // the smallest m whose CDF P(X<=m) >= 1-eps, i.e. P(X>m) <= eps.
  const double need = 1.0 - eps;
  double pmf = std::pow(1.0 - q, static_cast<double>(n));  // P(X=0)
  double cdf = pmf;
  if (cdf >= need) return 0;
  const double ratio = q / (1.0 - q);
  for (unsigned i = 1; i <= n; ++i) {
    pmf *= (static_cast<double>(n - i + 1) / static_cast<double>(i)) * ratio;
    cdf += pmf;
    if (cdf >= need) return i;
  }
  return n;
}

float redundancy_for_stall_bound(unsigned n, double q, double eps) {
  if (n < 2) return 2.0f;          // RS needs >=2 carriers
  unsigned m = min_parity_for_stall_bound(n, q, eps);
  if (m >= n) m = n - 1;           // keep k = n-m >= 1
  unsigned k = n - m;
  return static_cast<float>(m) / static_cast<float>(k);
}

unsigned small_copies_for_loss(double q, double eps) {
  if (q <= 0.0) return 1;
  if (q >= 1.0) return 20;
  if (eps <= 0.0) eps = 1e-12;
  // smallest c with q^c <= eps  ->  c >= ln(eps)/ln(q)  (ln q < 0)
  double c = std::log(eps) / std::log(q);
  unsigned ci = static_cast<unsigned>(std::ceil(c - 1e-9));
  return ci < 1 ? 1u : ci;
}

uint64_t stall_threshold_ns(uint64_t rtt_ns) {
  // A "stall" is a block waiting for a TCP retransmit, which costs ~max(RTT, RTO_min). Linux's
  // RTO floor is ~200 ms, so on a LOW-RTT link a stall costs ~200 ms — NOT the RTT. The
  // threshold must therefore be a fraction of the *retransmit cost*, not of the RTT: tying it
  // to RTT would, on a fast link, push it down into the host's scheduling-jitter band (tens of
  // ms) and mistake jitter for stalls (inflating q -> spurious redundancy). A quarter of the
  // retransmit cost lands safely between jitter and a retransmit in BOTH regimes — ~50 ms on a
  // fast link, RTT/4 on a high-RTT link. This is what makes q robust to the RTT regime (and to
  // this constant) instead of needing a hand-tuned absolute floor that we have to keep above
  // whatever the link's jitter happens to be.
  constexpr uint64_t kRtoFloorNs = 200000000ULL;  // ~Linux TCP RTO_min
  uint64_t retransmit_cost = rtt_ns > kRtoFloorNs ? rtt_ns : kRtoFloorNs;
  return retransmit_cost / 4;
}

unsigned carrier_target_for_load(double packets_per_s, uint64_t recovery_window_ns,
                                 double tau, double rho_bar, double rho_gate,
                                 unsigned floor, unsigned cap) {
  if (rho_bar < rho_gate) return floor;      // essentially no stalls -> floor regardless of load
  if (tau <= 0.0) tau = 1.0;
  double w_s = static_cast<double>(recovery_window_ns) / 1e9;
  double in_flight = packets_per_s * w_s;    // packets resident on the fleet per window
  double want = std::ceil(in_flight / tau);
  if (!(want >= 0.0)) want = static_cast<double>(floor);   // guard NaN
  unsigned n = (want > static_cast<double>(cap)) ? cap : static_cast<unsigned>(want);
  if (n < floor) n = floor;
  if (n > cap) n = cap;
  return n;
}

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

bool is_heavy_backlog(uint64_t unacked_bytes, size_t unacked_count) {
  return unacked_bytes > kHeavyBacklogBytes || unacked_count > kHeavyBacklogCount;
}

bool should_send_idle_ping(bool write_buf_empty, uint64_t now_ns,
                           uint64_t last_send_ns, uint64_t last_recv_ns,
                           uint64_t ping_idle_ns) {
  return write_buf_empty
      && now_ns - last_send_ns > ping_idle_ns
      && now_ns - last_recv_ns > ping_idle_ns;
}

CarrierQualityResult assess_carriers(
    const std::vector<CarrierInfo>& carriers,
    uint64_t now_ns,
    ScaledNsFn scaled_ns) {
  CarrierQualityResult res;
  if (carriers.empty()) return res;

  // 5×RTT, min 3 s (was 15 s): when WiFi/link drops we need to declare carriers dead
  // quickly so floor maintenance can open new connections; 15 s caused very slow recovery.
  uint64_t dead_idle_ns = scaled_ns(5, 3000000000ULL, 120000000000ULL);
  uint64_t grace_ns = scaled_ns(2, 5000000000ULL, 30000000000ULL);
  uint64_t very_high_ns = scaled_ns(3, 5000000000ULL, 30000000000ULL);
  // Send-only zombie threshold: a carrier we keep writing to but that has delivered
  // nothing back for this long is dead. Unlike the rx-dead test below, this needs no
  // healthy peer, so it works during a *total* outage where every carrier is dead.
  uint64_t zombie_ns = scaled_ns(8, 20000000000ULL, 120000000000ULL);

  // Track the freshest receive time across all carriers so we can detect
  // "send-only zombies": carriers we keep writing to but that never deliver
  // anything back while peers are still receiving.
  uint64_t latest_recv_ns = 0;
  for (const auto& c : carriers)
    if (c.last_recv_ns > latest_recv_ns) latest_recv_ns = c.last_recv_ns;

  // Total outage: the link was up (we received before) but NO carrier has received
  // anything for dead_idle. This is the *only* condition under which we close carriers
  // ourselves (reap_fds): when the whole link is down, a carrier we keep writing to but
  // that is silent is genuinely dead. When the link is up (some carrier received recently)
  // a silent carrier may simply be one the peer's return traffic isn't currently routed
  // over — closing it would cause constant carrier churn — so we never reap in that case,
  // only flag it (the client/server then SUGGEST_CLOSE and rely on a real socket error).
  const bool total_outage = (latest_recv_ns > 0) && (now_ns - latest_recv_ns > dead_idle_ns);

  for (const auto& c : carriers) {
    if (now_ns - c.connect_ns < grace_ns) continue;
    // Default idle test: no recent send/recv activity.
    uint64_t last_activity = std::max({c.connect_ns, c.last_recv_ns, c.last_send_ns});
    bool idle_dead = (now_ns - last_activity > dead_idle_ns);
    // Special case for carriers that have NEVER received anything:
    // only reap them aggressively when all three are true:
    // 1) they've been connected long enough,
    // 2) we have sent on them recently (active retransmit pressure),
    // 3) another carrier has received data since this one connected.
    //
    // This preserves the blackout recovery fix without culling healthy-but-idle
    // carriers during normal low/one-way traffic.
    if (!idle_dead && c.last_recv_ns == 0) {
      bool connected_long_enough = (now_ns - c.connect_ns > dead_idle_ns);
      bool actively_sending = (c.last_send_ns > 0) && (now_ns - c.last_send_ns < dead_idle_ns);
      bool peers_receiving = (latest_recv_ns > c.connect_ns + dead_idle_ns);
      if (connected_long_enough && actively_sending && peers_receiving)
        idle_dead = true;
    }

    // Additional RX-dead test: this carrier has not received anything for a long
    // time while at least one peer *has* recently received data. This catches
    // "zombie" carriers that we can still write to (so last_send_ns keeps
    // advancing) but that never deliver shards back.
    //
    // The threshold MUST exceed the idle-keepalive interval (--min-data, ~10s windows):
    // an alive carrier receives a keepalive PONG / data at least every ~10s, so its gap
    // behind the freshest carrier stays well under this. Using the short dead_idle (3s)
    // here mis-flagged healthy carriers that were merely *between* keepalives (or between
    // interactive bursts) while another carrier had just received — reaping live carriers
    // and churning the count. A genuinely dead carrier gets no keepalive and blows past
    // this bound; single-carrier detection is intentionally slow (redundancy covers it,
    // and a correlated mass drop is caught fast by the stall path).
    uint64_t rx_dead_ns = scaled_ns(8, 25000000000ULL, 120000000000ULL);  // >> ~10s keepalive
    bool rx_dead = false;
    if (!idle_dead && latest_recv_ns > 0 && c.last_recv_ns > 0) {
      uint64_t recv_gap = latest_recv_ns - c.last_recv_ns;
      if (recv_gap > rx_dead_ns)
        rx_dead = true;
    }
    if (rx_dead) res.rx_dead_fds.push_back(c.fd);

    // Send-only zombie: we are actively writing to this carrier (so the idle test above
    // is defeated by an advancing last_send_ns) but it has delivered nothing back for a
    // long time. This needs no healthy peer, so it detects dead-but-open carriers even
    // when EVERY carrier is dead (a long total outage) — the case that otherwise stalls
    // recovery forever, because nothing drops the carrier count below the floor so fresh
    // carriers are never opened, and the server never sheds corpses to accept new ones.
    // Send-only zombie: during a TOTAL outage, a carrier we keep writing to (so the idle
    // test is defeated by an advancing last_send_ns) but that has delivered nothing back
    // for a long time is dead. Gated on total_outage so it never fires while the link is
    // up — when some carrier is receiving, a silent carrier may just be out of the peer's
    // return-traffic rotation, and reaping it would cause endless carrier churn.
    bool zombie_dead = false;
    if (!idle_dead && !rx_dead && total_outage) {
      bool actively_sending = (c.last_send_ns > 0) && (now_ns - c.last_send_ns < dead_idle_ns);
      uint64_t silent_since = std::max(c.last_recv_ns, c.connect_ns);
      if (actively_sending && now_ns - silent_since > zombie_ns)
        zombie_dead = true;
    }

    if (idle_dead || rx_dead || zombie_dead) {
      res.dead_idle_fds.push_back(c.fd);
      // Only confidently-dead total-outage zombies are reaped by us directly; everything
      // else (rx-dead / never-received while the link is up) is left to SUGGEST_CLOSE +
      // real socket errors, to avoid closing live-but-quiet carriers.
      if (zombie_dead)
        res.reap_fds.push_back(c.fd);
    }
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
