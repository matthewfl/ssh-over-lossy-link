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

// ── reap_fds: confidently-dead carriers the server may close itself ──────────
// Reproduces the reported WiFi/VPN-drop bug: the server keeps streaming s2c data, the
// link drops for ~2 min, the client tears down its carriers and opens fresh ones, but the
// server's OLD carriers are dead-but-open (their sockets haven't errored). The server
// keeps writing retransmits to them (last_send advances) while only the NEW carriers
// actually receive — so the stale carriers must be reaped or retransmits never reach the
// client and the logical SSH stream never recovers.
void test_reap_dead_but_open() {
  auto scaled = [](unsigned mult, uint64_t mn, uint64_t mx) -> uint64_t {
    uint64_t v = static_cast<uint64_t>(mult) * 1 * S;  // effective RTT = 1 s
    return v < mn ? mn : (v > mx ? mx : v);
  };
  const uint64_t now = 1000 * S;  // dead_idle = 5 s, grace = 5 s

  // Two stale carriers (received only long ago, but we keep retransmitting → last_send
  // recent) plus a healthy new carrier that is actively receiving.
  std::vector<CarrierInfo> cs = {
    {/*fd=*/1, /*rtt=*/1*S, /*last_recv=*/now - 100*S, /*connect=*/now - 100*S, /*last_send=*/now - 1*S},
    {/*fd=*/2, 1*S,         now - 100*S,               now - 100*S,             now - 1*S},
    {/*fd=*/3, 1*S,         now - 1*S,                 now - 10*S,              now - 1*S},  // healthy, receiving
  };
  auto r = assess_carriers(cs, now, scaled);
  // Both stale carriers are flagged dead AND confidently reap-able; the healthy one isn't.
  auto has = [](const std::vector<int>& v, int fd) {
    return std::find(v.begin(), v.end(), fd) != v.end();
  };
  check(has(r.reap_fds, 1) && has(r.reap_fds, 2), "reap: stale dead-but-open carriers are reap-able");
  check(!has(r.reap_fds, 3), "reap: the actively-receiving carrier is NOT reaped");
  check(has(r.dead_idle_fds, 1) && has(r.dead_idle_fds, 2), "reap: stale carriers are also flagged dead_idle");

  // Safety: during a *global* quiet period (every carrier equally idle, no peer receiving
  // more recently), nothing is reaped — the server must not churn live-but-idle carriers.
  std::vector<CarrierInfo> quiet = {
    {1, 1*S, now - 100*S, now - 200*S, now - 100*S},
    {2, 1*S, now - 100*S, now - 200*S, now - 100*S},
    {3, 1*S, now - 100*S, now - 200*S, now - 100*S},
  };
  auto q = assess_carriers(quiet, now, scaled);
  check(q.reap_fds.empty(), "reap: a global quiet period reaps nothing (no churn)");
  check(!q.dead_idle_fds.empty(), "reap: quiet carriers are still flagged dead_idle (idle)");
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

}  // namespace

int main() {
  test_run_adapt();
  test_compute_from_deques();
  test_merge();
  test_assess_carriers();
  test_health_predicates();
  test_reap_dead_but_open();
  test_reap_send_only_zombie();
  if (g_failures) {
    std::fprintf(stderr, "carrier_adapt tests: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("carrier_adapt tests OK\n");
  return 0;
}
