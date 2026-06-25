// Unit tests for carrier_adapt — the pure redundancy/carrier-health decision logic
// shared (and soon to be more shared) between client and server. Deterministic, no I/O.
//
// These lock in the behavior before the refactor relocates/uses this logic more widely.

#include "carrier_adapt.h"
#include <algorithm>
#include <cstdio>
#include <deque>
#include <vector>

using namespace ssholl::carrier_adapt;

namespace {

int g_failures = 0;
void check(bool cond, const char* msg) {
  if (!cond) { std::fprintf(stderr, "FAIL: %s\n", msg); ++g_failures; }
}
bool approx(float a, float b) { float d = a - b; return d < 0.0005f && d > -0.0005f; }

const uint64_t MS = 1000000ULL;
const uint64_t S  = 1000000000ULL;

// ── run_adapt ───────────────────────────────────────────────────────────────
void test_run_adapt() {
  // Heavy struggling (> 5%): big RS bump (+0.10) and +1 small copy.
  {
    PathMetrics m; m.fraction_struggling = 0.06f;
    AdaptResult r = run_adapt(m, /*rs=*/0.10f, /*small=*/2, /*n=*/10);
    check(approx(r.rs_redundancy, 0.20f), "run_adapt: heavy → rs +0.10");
    check(r.small_packet_redundancy == 3, "run_adapt: heavy → small +1");
    check(r.clear_spread, "run_adapt: heavy → clear_spread");
  }
  // Medium struggling (1%..5%): smaller RS bump (+0.05), no small change.
  {
    PathMetrics m; m.fraction_struggling = 0.02f;
    AdaptResult r = run_adapt(m, 0.10f, 2, 10);
    check(approx(r.rs_redundancy, 0.15f), "run_adapt: medium → rs +0.05");
    check(r.small_packet_redundancy == 2, "run_adapt: medium → small unchanged");
    check(r.clear_spread, "run_adapt: medium → clear_spread");
  }
  // Calm + can_decrease_rs: gentle RS decrease (-0.02), floored at 0.1.
  {
    PathMetrics m; m.fraction_struggling = 0.0f; m.can_decrease_rs = true;
    AdaptResult r = run_adapt(m, 0.20f, 2, 10);
    check(approx(r.rs_redundancy, 0.18f), "run_adapt: calm+can_decrease → rs -0.02");
    AdaptResult r2 = run_adapt(m, 0.10f, 2, 10);
    check(approx(r2.rs_redundancy, 0.10f), "run_adapt: rs decrease floored at 0.1");
    check(!r.clear_spread, "run_adapt: calm → no clear_spread");
  }
  // can_decrease_small: -1 when <=10, -2 when >10, floored at 2.
  {
    PathMetrics m; m.can_decrease_small = true;
    check(run_adapt(m, 0.10f, 5, 10).small_packet_redundancy == 4, "run_adapt: small 5→4");
    check(run_adapt(m, 0.10f, 12, 20).small_packet_redundancy == 10, "run_adapt: small 12→10 (-2)");
    check(run_adapt(m, 0.10f, 2, 10).small_packet_redundancy == 2, "run_adapt: small floored at 2");
  }
  // small_packet_redundancy is clamped to n_carriers.
  {
    PathMetrics m;
    check(run_adapt(m, 0.10f, 8, /*n=*/3).small_packet_redundancy == 3, "run_adapt: small clamped to n_carriers");
  }
}

// ── compute_from_deques ───────────────────────────────────────────────────────
void test_compute_from_deques() {
  // Empty input → neutral metrics.
  {
    std::deque<uint64_t> empty;
    PathMetrics m = compute_from_deques(empty, empty, empty, empty);
    check(m.fraction_struggling == 0.0f && !m.can_decrease_rs && !m.can_decrease_small,
          "compute: empty → neutral");
  }
  // "Struggling" = spread > 2ms AND final gap > half the spread.
  {
    std::deque<uint64_t> spread = {3*MS, 3*MS, 1*MS, 3*MS};
    std::deque<uint64_t> gapf   = {2*MS, 1*MS, 1*MS, 2*MS};  // idx0,3 struggle; idx1 gap too small; idx2 spread too small
    std::deque<uint64_t> empty;
    PathMetrics m = compute_from_deques(spread, gapf, empty, empty);
    check(approx(m.fraction_struggling, 0.5f), "compute: 2 of 4 groups struggling");
  }
  // can_decrease_rs: needs >=10 extra-shard samples with p90 < 0.5ms.
  {
    std::deque<uint64_t> spread(10, 1*MS), gapf(10, 0);
    std::deque<uint64_t> extra_small(10, 400000ULL);  // 0.4ms, all under 0.5ms
    std::deque<uint64_t> empty;
    check(compute_from_deques(spread, gapf, extra_small, empty).can_decrease_rs,
          "compute: tight extra-shard gaps → can_decrease_rs");
    std::deque<uint64_t> extra_big(10, 1*MS);  // 1ms, over threshold
    check(!compute_from_deques(spread, gapf, extra_big, empty).can_decrease_rs,
          "compute: wide extra-shard gaps → !can_decrease_rs");
    std::deque<uint64_t> few(5, 400000ULL);  // fewer than 10 samples → no decision
    check(!compute_from_deques(spread, gapf, few, empty).can_decrease_rs,
          "compute: <10 extra-shard samples → !can_decrease_rs");
  }
  // can_decrease_small: needs >=5 samples with p90 < 1.5ms.
  {
    std::deque<uint64_t> spread(5, 1*MS), gapf(5, 0), empty;
    std::deque<uint64_t> small_tight(5, 1*MS);  // 1ms < 1.5ms
    check(compute_from_deques(spread, gapf, empty, small_tight).can_decrease_small,
          "compute: tight small-copy gaps → can_decrease_small");
  }
}

// ── merge ─────────────────────────────────────────────────────────────────────
void test_merge() {
  PathMetrics c2s; c2s.fraction_struggling = 0.02f; c2s.can_decrease_rs = true; c2s.can_decrease_small = true;
  PathMetrics s2c; s2c.fraction_struggling = 0.10f; s2c.can_decrease_rs = false; s2c.can_decrease_small = true;
  // s2c not fresh → c2s passes through unchanged.
  {
    PathMetrics m = merge(c2s, s2c, /*s2c_fresh=*/false);
    check(approx(m.fraction_struggling, 0.02f) && m.can_decrease_rs && m.can_decrease_small,
          "merge: stale s2c → c2s unchanged");
  }
  // s2c fresh → struggling is the max, decrease flags are ANDed (both must agree).
  {
    PathMetrics m = merge(c2s, s2c, /*s2c_fresh=*/true);
    check(approx(m.fraction_struggling, 0.10f), "merge: fresh → max struggling");
    check(!m.can_decrease_rs, "merge: fresh → can_decrease_rs ANDed (s2c says no)");
    check(m.can_decrease_small, "merge: fresh → can_decrease_small ANDed (both yes)");
  }
}

// ── assess_carriers ─────────────────────────────────────────────────────────
void test_assess_carriers() {
  // Emulate scaled_ns with an effective RTT of 1 s: dead_idle=5s, grace=5s, very_high=5s.
  auto scaled = [](unsigned mult, uint64_t mn, uint64_t mx) -> uint64_t {
    uint64_t v = static_cast<uint64_t>(mult) * 1 * S;
    return v < mn ? mn : (v > mx ? mx : v);
  };
  const uint64_t now = 1000 * S;

  // A carrier idle (no recv/send) well past dead_idle, connected long ago → dead.
  {
    std::vector<CarrierInfo> cs = {
      {/*fd=*/7, /*last_rtt=*/1*S, /*last_recv=*/now - 100*S, /*connect=*/now - 100*S, /*last_send=*/now - 100*S}
    };
    auto r = assess_carriers(cs, now, scaled);
    check(r.dead_idle_fds.size() == 1 && r.dead_idle_fds[0] == 7, "assess: long-idle carrier is dead");
  }
  // A carrier with recent activity is healthy.
  {
    std::vector<CarrierInfo> cs = {
      {7, 1*S, now - 1*S, now - 100*S, now - 1*S}
    };
    auto r = assess_carriers(cs, now, scaled);
    check(r.dead_idle_fds.empty(), "assess: recently-active carrier is healthy");
  }
  // A just-connected carrier (within grace) is never flagged, even with no activity.
  {
    std::vector<CarrierInfo> cs = {
      {7, 0, now - 1*S, now - 1*S, now - 1*S}   // connected 1s ago < 5s grace
    };
    auto r = assess_carriers(cs, now, scaled);
    check(r.dead_idle_fds.empty() && r.rtt_outlier_fd == -1, "assess: carrier within grace is untouched");
  }
  // RTT outlier: one carrier 5×+ the median and above the absolute floor.
  {
    std::vector<CarrierInfo> cs = {
      {1, 1*S,  now - 1*S, now - 100*S, now - 1*S},
      {2, 1*S,  now - 1*S, now - 100*S, now - 1*S},
      {3, 10*S, now - 1*S, now - 100*S, now - 1*S},  // outlier
    };
    auto r = assess_carriers(cs, now, scaled);
    check(r.rtt_outlier_fd == 3, "assess: identifies the RTT outlier");
    check(r.dead_idle_fds.empty(), "assess: outlier set is independent of dead-idle");
  }
}

// ── is_heavy_backlog / should_send_idle_ping ─────────────────────────────────
void test_health_predicates() {
  check(!is_heavy_backlog(0, 0), "heavy_backlog: empty → false");
  check(is_heavy_backlog(kHeavyBacklogBytes + 1, 0), "heavy_backlog: over byte threshold → true");
  check(is_heavy_backlog(0, kHeavyBacklogCount + 1), "heavy_backlog: over count threshold → true");
  check(!is_heavy_backlog(kHeavyBacklogBytes, kHeavyBacklogCount), "heavy_backlog: exactly at threshold → false");

  const uint64_t now = 100 * S, idle = 5 * S;
  // Idle long enough in both directions, buffer empty → ping.
  check(should_send_idle_ping(true, now, now - 6*S, now - 6*S, idle), "idle_ping: idle both ways → true");
  // Non-empty write buffer → never ping (we're already sending).
  check(!should_send_idle_ping(false, now, now - 6*S, now - 6*S, idle), "idle_ping: write pending → false");
  // Recent send → not idle enough.
  check(!should_send_idle_ping(true, now, now - 1*S, now - 6*S, idle), "idle_ping: recent send → false");
  // Recent recv → not idle enough.
  check(!should_send_idle_ping(true, now, now - 6*S, now - 1*S, idle), "idle_ping: recent recv → false");
}

// ── reap_fds is anti-churn: never reap while the link is up ──────────────────
// Critical safety property. When SOME carrier is receiving (the link is up), a carrier
// that is silent is INDISTINGUISHABLE from a dead one by passive signals — it may simply
// be one the peer's return traffic (ACKs) isn't currently routed over. Reaping it caused
// constant carrier churn (the server closed live carriers, the client reopened them, ad
// infinitum). So reap_fds must be EMPTY whenever any peer received recently; such carriers
// are still flagged dead_idle (for SUGGEST_CLOSE) but are only really removed by a genuine
// socket error.
void test_reap_no_churn_while_link_up() {
  auto scaled = [](unsigned mult, uint64_t mn, uint64_t mx) -> uint64_t {
    uint64_t v = static_cast<uint64_t>(mult) * 1 * S;  // effective RTT = 1 s -> dead_idle 5s
    return v < mn ? mn : (v > mx ? mx : v);
  };
  const uint64_t now = 1000 * S;
  auto has = [](const std::vector<int>& v, int fd) {
    return std::find(v.begin(), v.end(), fd) != v.end();
  };

  // Two long-silent carriers we keep writing to, plus a healthy carrier receiving now.
  // The link is up (fd=3 just received), so NOTHING is reaped — even the silent ones.
  std::vector<CarrierInfo> cs = {
    {/*fd=*/1, /*rtt=*/1*S, /*last_recv=*/now - 100*S, /*connect=*/now - 100*S, /*last_send=*/now - 1*S},
    {/*fd=*/2, 1*S,         now - 100*S,               now - 100*S,             now - 1*S},
    {/*fd=*/3, 1*S,         now - 1*S,                 now - 10*S,              now - 1*S},  // healthy
  };
  auto r = assess_carriers(cs, now, scaled);
  check(r.reap_fds.empty(), "reap: link is up (a peer is receiving) -> reap nothing (no churn)");
  // The silent ones are still flagged dead_idle so SUGGEST_CLOSE can be sent.
  check(has(r.dead_idle_fds, 1) && has(r.dead_idle_fds, 2), "reap: silent carriers still flagged dead_idle");
  check(!has(r.dead_idle_fds, 3), "reap: the receiving carrier is not flagged");

  // Global quiet period (no carrier ever received recently, and we are not sending):
  // still nothing reaped.
  std::vector<CarrierInfo> quiet = {
    {1, 1*S, now - 100*S, now - 200*S, now - 100*S},
    {2, 1*S, now - 100*S, now - 200*S, now - 100*S},
  };
  check(assess_carriers(quiet, now, scaled).reap_fds.empty(), "reap: quiet period reaps nothing");
}

// ── send-only zombie: reap-able with NO healthy peer (total-outage recovery) ──
// The case that stalls recovery after a long *total* outage: every carrier is dead, so
// there is no healthy peer for the rx-dead/reap comparison, yet we keep writing
// retransmits onto each (last_send advances, defeating the idle test). Such carriers
// must still be reaped (peer-independently) or the count never drops below the floor,
// fresh post-outage carriers are never opened, and the link never recovers.
void test_reap_send_only_zombie() {
  auto scaled = [](unsigned mult, uint64_t mn, uint64_t mx) -> uint64_t {
    uint64_t v = static_cast<uint64_t>(mult) * 1 * S;  // RTT = 1 s -> dead_idle 5s, zombie 20s
    return v < mn ? mn : (v > mx ? mx : v);
  };
  const uint64_t now = 1000 * S;
  auto has = [](const std::vector<int>& v, int fd) {
    return std::find(v.begin(), v.end(), fd) != v.end();
  };

  // Two carriers, BOTH dead-but-open: silent ~50 s but we are still actively writing to
  // them (last_send recent). No healthy peer exists.
  std::vector<CarrierInfo> cs = {
    {/*fd=*/1, /*rtt=*/1*S, /*last_recv=*/now - 50*S, /*connect=*/now - 100*S, /*last_send=*/now - 1*S},
    {/*fd=*/2, 1*S,         now - 50*S,               now - 100*S,             now - 1*S},
  };
  auto r = assess_carriers(cs, now, scaled);
  check(has(r.reap_fds, 1) && has(r.reap_fds, 2), "zombie: send-only zombies are reaped with no healthy peer");

  // Not a zombie yet: silent only 10 s (< 20 s zombie window) while sending.
  std::vector<CarrierInfo> young = {
    {1, 1*S, now - 10*S, now - 100*S, now - 1*S},
    {2, 1*S, now - 10*S, now - 100*S, now - 1*S},
  };
  check(assess_carriers(young, now, scaled).reap_fds.empty(),
        "zombie: brief silence (< zombie window) is not reaped");

  // Not a zombie: we are NOT writing to it (last_send old) — a quiet period, must not be
  // reaped just for being idle. Pins the actively-sending requirement.
  std::vector<CarrierInfo> idle = {
    {1, 1*S, now - 50*S, now - 100*S, now - 50*S},
    {2, 1*S, now - 50*S, now - 100*S, now - 50*S},
  };
  check(assess_carriers(idle, now, scaled).reap_fds.empty(),
        "zombie: idle (not actively sending) is not reaped peer-independently");
}

// ── probability-bounded redundancy model ─────────────────────────────────────
// Values pinned against an independent exact-binomial computation (REDUNDANCY_MODEL.md).
void test_stall_bound_model() {
  const double eps = 0.0001;  // 0.01%

  // min_parity_for_stall_bound matches the table.
  check(min_parity_for_stall_bound(10, 0.01, eps) == 3, "model: q1% n10 -> m=3");
  check(min_parity_for_stall_bound(20, 0.01, eps) == 3, "model: q1% n20 -> m=3");
  check(min_parity_for_stall_bound(20, 0.03, eps) == 5, "model: q3% n20 -> m=5");
  check(min_parity_for_stall_bound(30, 0.03, eps) == 6, "model: q3% n30 -> m=6");
  check(min_parity_for_stall_bound(20, 0.05, eps) == 6, "model: q5% n20 -> m=6");
  check(min_parity_for_stall_bound(30, 0.05, eps) == 7, "model: q5% n30 -> m=7");
  check(min_parity_for_stall_bound(40, 0.05, eps) == 9, "model: q5% n40 -> m=9");

  // No loss -> no parity needed.
  check(min_parity_for_stall_bound(30, 0.0, eps) == 0, "model: q=0 -> m=0");

  // Redundancy fraction falls as carriers grow at fixed loss (the key feedback).
  float r20 = redundancy_for_stall_bound(20, 0.05, eps);
  float r40 = redundancy_for_stall_bound(40, 0.05, eps);
  float r80 = redundancy_for_stall_bound(80, 0.05, eps);
  check(approx(r20, 6.0f/14.0f), "model: q5% n20 -> r=6/14");
  check(r40 < r20 && r80 < r40, "model: redundancy decreases as carriers grow");

  // Small-packet copies: smallest c with q^c <= eps.
  check(small_copies_for_loss(0.01, eps) == 2, "model: q1% -> 2 copies");
  check(small_copies_for_loss(0.03, eps) == 3, "model: q3% -> 3 copies");
  check(small_copies_for_loss(0.05, eps) == 4, "model: q5% -> 4 copies");
  check(small_copies_for_loss(0.0,  eps) == 1, "model: q=0 -> 1 copy");
}

// ── retransmit-scale stall threshold ─────────────────────────────────────────
void test_stall_threshold() {
  // A quarter of the retransmit cost = max(RTT, RTO_min~200ms)/4. High-RTT -> RTT/4; low-RTT
  // -> RTO_min/4 (= 50ms), NOT RTT/4 (which would dip into the jitter band).
  check(stall_threshold_ns(300000000ULL) == 75000000ULL, "stall: 300ms RTT -> 75ms (RTT/4)");
  check(stall_threshold_ns(800000000ULL) == 200000000ULL, "stall: 800ms RTT -> 200ms (RTT/4)");
  check(stall_threshold_ns(40000000ULL)  == 50000000ULL, "stall: 40ms RTT -> 50ms (RTO/4)");
  check(stall_threshold_ns(0ULL)         == 50000000ULL, "stall: 0 RTT -> 50ms (RTO/4)");
  check(stall_threshold_ns(200000000ULL) == 50000000ULL, "stall: 200ms RTT -> 50ms (RTO/4)");
  // base jitter is BELOW the threshold; a retransmit (>= ~1 RTT, or >= RTO on a fast link) is
  // ABOVE it — so the late-fraction reads real stalls, not jitter, in both regimes.
  check(15000000ULL  < stall_threshold_ns(300000000ULL), "stall: 15ms jitter below 300ms-RTT thr");
  check(300000000ULL > stall_threshold_ns(300000000ULL), "stall: retransmit above 300ms-RTT thr");
  check(200000000ULL > stall_threshold_ns(20000000ULL),  "stall: 200ms RTO above fast-link thr");
  check(40000000ULL  < stall_threshold_ns(20000000ULL),  "stall: 40ms jitter below fast-link thr (50ms)");
}

// ── carrier target = load × loss (gated R·W/tau) ─────────────────────────────
void test_carrier_target() {
  const double tau = 1.5, gate = 0.01;
  // CLEAN link (stall fraction below the gate) -> floor, regardless of throughput. This is
  // the key property: a fast flood with no loss is not over-provisioned.
  check(carrier_target_for_load(4000.0, 20000000ULL, tau, 0.0, gate, 5, 50) == 5,
        "load: clean 4000pps @20ms -> floor (no over-provision)");
  check(carrier_target_for_load(4000.0, 20000000ULL, tau, 0.005, gate, 5, 50) == 5,
        "load: near-clean high rate -> floor");
  // LOSSY flood -> grow, capping per-carrier load at tau (4000*0.02/1.5 = 53 -> cap 50).
  check(carrier_target_for_load(4000.0, 20000000ULL, tau, 0.05, gate, 5, 50) == 50,
        "load: lossy 4000pps @20ms -> cap");
  // LOSSY but LOW-RATE (interactive) -> floor: carriers aren't overloaded, redundancy covers
  // the loss (20pps * 0.3s / 1.5 = 4 -> floor 8).
  check(carrier_target_for_load(20.0, 300000000ULL, tau, 0.05, gate, 8, 60) == 8,
        "load: lossy 20pps @300ms -> floor (not overloaded)");
  // LOSSY bulk @ high RTT -> scales up (290 * 0.3 / 1.5 = 58).
  check(carrier_target_for_load(290.0, 300000000ULL, tau, 0.05, gate, 8, 60) == 58,
        "load: lossy 290pps @300ms -> 58");
  // Idle -> floor.
  check(carrier_target_for_load(0.0, 300000000ULL, tau, 0.05, gate, 8, 60) == 8,
        "load: idle -> floor");
}

}  // namespace

int main() {
  test_run_adapt();
  test_compute_from_deques();
  test_merge();
  test_assess_carriers();
  test_health_predicates();
  test_reap_no_churn_while_link_up();
  test_reap_send_only_zombie();
  test_stall_bound_model();
  test_stall_threshold();
  test_carrier_target();
  if (g_failures) {
    std::fprintf(stderr, "carrier_adapt tests: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("carrier_adapt tests OK\n");
  return 0;
}
