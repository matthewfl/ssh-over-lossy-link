#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
#include "carrier_adapt.h"
#include "net_util.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

namespace ssholl {

namespace {

using packet_io::CarrierState;
using packet_io::RsPending;
using packet_io::MAX_PACKET_PAYLOAD;
using packet_io::MAX_ID_AHEAD;
using packet_io::READ_BUF_SIZE;
const int LISTEN_BACKLOG = 64;

void set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return;
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::string make_socket_path() {
  std::random_device rd;
  uint32_t r = rd();
  char suffix[16];
  snprintf(suffix, sizeof suffix, "%08x", r);
  return std::string("/tmp/ssh-oll-server.") + suffix;
}

// Create, bind, listen on Unix socket. Returns fd or -1.
int create_listen_socket(const std::string& path, mode_t mode) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof addr.sun_path) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  unlink(addr.sun_path);
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) < 0) {
    close(fd);
    return -1;
  }
  if (chmod(addr.sun_path, mode) < 0) {
    close(fd);
    unlink(addr.sun_path);
    return -1;
  }
  if (listen(fd, LISTEN_BACKLOG) < 0) {
    close(fd);
    unlink(addr.sun_path);
    return -1;
  }
  return fd;
}

// Connect to host:port. Returns fd (non-blocking) or -1. Caller checks EINPROGRESS.
int connect_tcp(const std::string& host, uint16_t port) {
  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char port_str[8];
  snprintf(port_str, sizeof port_str, "%u", port);
  int gai = getaddrinfo(host.c_str(), port_str, &hints, &res);
  if (gai != 0 || !res) return -1;
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  set_nonblocking(fd);
  int r = connect(fd, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if (r == 0) return fd;
  if (errno != EINPROGRESS) {
    close(fd);
    return -1;
  }
  return fd;
}

// Check socket error (for connect completion).
int get_so_error(int fd) {
  int err = 0;
  socklen_t len = sizeof err;
  return getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 ? err : -1;
}

}  // namespace

int run_server(const Args& args) {
  const std::string socket_path = make_socket_path();
  const mode_t socket_mode = 0700;

  int listen_fd = create_listen_socket(socket_path, socket_mode);
  if (listen_fd < 0) {
    std::perror("ssh-oll server: socket");
    return 1;
  }
  set_nonblocking(listen_fd);

  // Print path so client can parse it; then daemonize.
  std::printf("%s\n", socket_path.c_str());
  std::fflush(stdout);

  pid_t pid = fork();
  if (pid < 0) {
    std::perror("ssh-oll server: fork");
    close(listen_fd);
    unlink(socket_path.c_str());
    return 1;
  }
  if (pid != 0) {
    close(listen_fd);
    return 0;  // parent exits; client's SSH session sees exit and closes
  }

  // Child: become session leader, detach from terminal.
  setsid();
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  // Open per-process debug log if --debug was passed.
  DebugLog dbg;
  if (args.debug) {
    char dbg_path[128];
    snprintf(dbg_path, sizeof dbg_path, "/tmp/ssh-oll-server-%d.log", (int)getpid());
    dbg.f = fopen(dbg_path, "w");
    dbg.cap_bytes = 1024ull * (uint64_t)args.config.debug_log_cap_kb;
  }

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    unlink(socket_path.c_str());
    return 1;
  }

  struct epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = listen_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
    close(epfd);
    close(listen_fd);
    unlink(socket_path.c_str());
    return 1;
  }

  int backend_fd = -1;
  bool backend_connected = false;
  std::map<int, CarrierState> carriers;
  std::map<uint64_t, std::vector<uint8_t>> reassembly;
  std::map<uint64_t, RsPending> rs_pending;
  uint64_t next_deliver_id = 0;
  uint64_t next_send_id = 0;
  std::vector<uint8_t> backend_read_buf;
  size_t max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));
  // Cold-start redundancy until the probability model has enough samples to take over.
  // In auto mode the client's SET_CONFIG no longer seeds these (the server owns them), so
  // start moderately protected rather than at the bare 0.1 floor.
  // Cold-start at the configured redundancy (with only the system minimum). In auto mode this
  // is the "initial" value the link runs at until the probability model has enough samples to
  // take over; the client propagates --rs-redundancy / --small-packet-redundancy on the
  // server launch command so this matches what the user set.
  float runtime_rs_redundancy = std::max(0.1f, args.config.rs_redundancy);
  unsigned runtime_small_packet_redundancy = std::max(2u, args.config.small_packet_redundancy);
  uint64_t last_copies_decrease_ns = 0;   // rate-limit small-packet copy DECREASES (fast up, slow down)
  bool runtime_auto_adapt = false;  // set from SET_CONFIG; when true, server adapts and sends SERVER_CONFIG
  uint32_t runtime_reconnect_timeout_sec = (uint32_t)args.config.reconnect_timeout_sec;
  // --max-delay (client-provided via SET_CONFIG): hold a backend→client sub-block remainder
  // up to this long so it can coalesce into a full RS block. 0 = send immediately.
  uint64_t runtime_max_delay_ns = static_cast<uint64_t>(args.config.max_delay_ms * 1000000.0f);
  uint64_t backend_partial_since_ns = 0;
  float last_sent_rs_redundancy = -1.0f;
  unsigned last_sent_small_packet_redundancy = 0;
  uint64_t last_adapt_ns = 0;
  const uint64_t adapt_interval_ns = 300 * 1000000ULL;
  // Round-robin index shared by both SMALL packets and RS shards (server→client).
  unsigned next_rr = 0;


  // Server-side link monitoring: record when we send each id; when client sends ACK, measure RTT.
  std::map<uint64_t, uint64_t> ack_send_time_ns;  // id -> when we sent it (for server→client RTT)
  std::deque<uint64_t> server_recent_rtt_ns;
  const size_t max_server_recent_rtt = 50;
  const uint64_t metrics_interval_ns = 400 * 1000000ULL;  // 400ms
  uint64_t last_metrics_ns = 0;
  uint64_t last_carrier_status_ns = 0;
  // Rolling shard spread samples for the client→server direction.
  std::deque<uint64_t> c2s_shard_spread_ns;
  // gap_final: time between (k-1)-th and k-th shard per group (how close to the edge).
  std::deque<uint64_t> c2s_gap_final_ns;
  // extra_shard_gap: time from k-th shard to (k+1)-th shard (how much headroom we have).
  std::deque<uint64_t> c2s_extra_shard_gap_ns;
  std::deque<uint64_t> c2s_small_extra_copy_gap_ns;  // copy 1->2 gap for small packets (c2s)
  static constexpr size_t kMaxSpreadSamples = 100;
  // Per-shard loss (q) estimation for the probability-bounded redundancy model.
  // A shard counts as "late" if it arrives more than the latency budget B after its
  // group's first shard (it would have added > B of head-of-line delay). Over each adapt
  // window: total shard-gaps seen and how many exceeded B. q = late/total. This is the
  // Per-shard stall probability is measured against a retransmit-scale threshold
  // (carrier_adapt::stall_threshold_ns, ~RTT/2), computed live from the RTT estimate — not a
  // fixed latency budget. See REDUNDANCY_MODEL.md.
  uint64_t qest_total_gaps = 0;
  uint64_t qest_late_gaps = 0;
  double   est_loss_q = 0.05;   // start pessimistic until we have a measurement
  bool     have_loss_q = false;
  std::deque<uint64_t> qest_recent_gaps;  // recent shard gaps (for percentile diagnostics / B tuning)
  // s2c metrics from CLIENT_METRICS (client measures server→client path).
  float s2c_loss_q = 0.0f;   // client-reported s2c per-shard late fraction (latency-budget method)
  bool client_c2s_window_saturated = false;  // client-reported (CLIENT_METRICS) c2s send-window sat
  uint64_t s2c_last_received_ns = 0;
  // Shared map for tracking when RS groups decoded so extra shards can be timed.
  std::map<uint64_t, uint64_t> recently_decoded_ns;
  std::map<uint64_t, std::vector<uint64_t>> small_copy_arrival_times;

  // Unacked retransmit buffer (shared UnackedItem from net_util.h): holds original bytes
  // for each outstanding send_id so we can re-encode and resend on a new carrier when all
  // existing ones die.
  std::map<uint64_t, UnackedItem> unacked_data;
  bool retransmit_needed = false;  // set when last carrier dies with unacked data
  // ACK-clocked send window for the s2c direction: caps outstanding (sent-but-unACKed)
  // data bytes — see RateWindow in net_util.h. When closed we stop encoding new RS groups
  // AND stop reading the backend, so the producer (sshd) gets real backpressure instead
  // of an ever-deepening queue.
  RateWindow s2c_window;
  bool backend_read_wanted = true;   // recomputed each loop pass from the window; gates EPOLLIN
  uint32_t backend_events_state = 0xFFFFFFFF;  // last epoll MOD for backend (for arm_backend dedup)
  uint64_t unacked_bytes_cache = 0;  // outstanding bytes for the current event-loop pass
  std::set<int> pending_peer_suggest_close;
  uint64_t next_carrier_id_global = 1;
  // When the carrier set last went from empty -> non-empty (recovery from total loss).
  // ACKs for data sent before this instant span the outage and must not be timed as RTT.
  uint64_t last_recovery_ns = 0;

  uint64_t last_ping_check_ns       = 0;
  uint64_t last_rs_drain_ns                = 0;
  uint64_t next_deliver_id_stuck_since_ns  = 0;
  uint64_t last_retransmit_check_ns = 0;
  uint64_t last_global_recv_ns      = now_ns();  // last time any data arrived from any carrier
  uint64_t last_suggest_close_ns = 0;  // rate-limit SUGGEST_CLOSE to at most 1 per 10s
  static constexpr uint64_t suggest_close_min_interval_ns = 10 * 1000000000ULL;
  std::map<int, uint64_t> outstanding_ping_ns;  // fd -> ping sent time
  int last_read_errno = 0;
  bool last_read_eof = false;

  // RTT-scaled timeouts: server observes server→client RTT from ACKs. Before enough
  // samples exist, use the client-provided --rtt-ms cold-start hint (propagated on the
  // server launch command) so high-latency links aren't scaled from the 5 s default,
  // which is too aggressive — see README "RTT-scaled timeouts".
  const uint64_t rtt_hint_ns = static_cast<uint64_t>(args.config.rtt_hint_ms) * 1000000ULL;
  auto get_effective_rtt_ns = [&]() -> uint64_t {
    if (server_recent_rtt_ns.size() >= 3)
      return p90_ns(server_recent_rtt_ns);
    return rtt_hint_ns ? rtt_hint_ns : 5000000000ULL;  // hint, else 5 s conservative
  };
  // Base RTT = the MINIMUM of recent samples: the path RTT without standing-queue delay.
  // Used for thresholds that must NOT move with load (the per-shard stall/jitter cutoffs),
  // where the usual p90 would chase the queue depth our own window maintains.
  auto get_base_rtt_ns = [&]() -> uint64_t {
    if (!server_recent_rtt_ns.empty())
      return *std::min_element(server_recent_rtt_ns.begin(), server_recent_rtt_ns.end());
    return rtt_hint_ns ? rtt_hint_ns : 5000000000ULL;
  };
  // Session-minimum RTT, for the send-window budget (net_util.h): queueing can only raise
  // an RTT sample, so a monotone session min cannot ratchet the window cap upward.
  uint64_t base_rtt_min_session_ns = 0;  // 0 = no sample yet
  auto get_window_base_rtt_ns = [&]() -> uint64_t {
    return base_rtt_min_session_ns ? base_rtt_min_session_ns : get_base_rtt_ns();
  };
  auto scaled_ns = [&](unsigned mult, uint64_t min_ns, uint64_t max_ns) -> uint64_t {
    return ssholl::scaled_ns(mult, min_ns, max_ns, get_effective_rtt_ns());
  };

  // Delivered data is queued here; we write to backend and ACK when a chunk is fully written.
  // completing_fd is the carrier that triggered delivery — ACK goes back there for per-carrier RTT measurement.
  struct BackendItem { uint64_t id; std::vector<uint8_t> data; int completing_fd; };
  std::deque<BackendItem> backend_pending;

  // Single place that computes the backend fd's epoll interest: EPOLLOUT while there is
  // backend_pending to write, EPOLLIN only while the send window allows more reading. When
  // the window is closed the fd is left armed for nothing (events=0) so a perpetually-ready
  // readable backend cannot busy-spin the loop. Sites that used to set EPOLLIN unconditionally
  // call this; the periodic pump block re-arms every pass as the window opens/closes.
  auto arm_backend = [&]() {
    if (backend_fd < 0 || !backend_connected) return;
    uint32_t want = (backend_read_wanted ? (uint32_t)EPOLLIN : 0u) |
                    (!backend_pending.empty() ? (uint32_t)EPOLLOUT : 0u);
    if (want == backend_events_state) return;
    backend_events_state = want;
    ev.events = want;
    ev.data.fd = backend_fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
  };

  auto connect_backend = [&]() {
    if (backend_fd >= 0) return;
    backend_fd = connect_tcp(args.remote_hostname, args.remote_port);
    if (backend_fd < 0) return;
    ev.events = EPOLLIN | EPOLLOUT;  // EPOLLOUT for connect completion
    ev.data.fd = backend_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, backend_fd, &ev);
  };

  auto ensure_backend_connected = [&]() {
    if (backend_connected) return;
    if (backend_fd < 0) return;
    int err = get_so_error(backend_fd);
    if (err == 0) {
      backend_connected = true;
      if (dbg.f) dbglogf(dbg, "[backend-connected t=%llu]\n",
                       (unsigned long long)(now_ns()/1000000ULL));
      int one = 1;
      setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      ev.events = EPOLLIN;  // EPOLLOUT only when we have backend_pending data to write
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
      backend_events_state = EPOLLIN;
    } else if (err != EINPROGRESS && err != 0) {
      if (dbg.f) dbglogf(dbg, "[backend-connect-failed t=%llu errno=%d]\n",
                       (unsigned long long)(now_ns()/1000000ULL), err);
      close(backend_fd);
      backend_fd = -1;
    }
  };

  std::mt19937 keepalive_gen(std::random_device{}());
  auto send_pong = [&](int fd, uint64_t id, size_t payload_size = 0) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    if (payload_size > 0) {
      size_t pkt_max = std::min(max_packet, static_cast<size_t>(MAX_PACKET_PAYLOAD));
      size_t len = std::min(payload_size, std::max(size_t(50), pkt_max));
      std::vector<uint8_t> payload(len);
      std::uniform_int_distribution<int> dist(0, 255);
      for (size_t i = 0; i < len; ++i) payload[i] = static_cast<uint8_t>(dist(keepalive_gen));
      packet_io::append_pong(it->second.write_buf, id, payload.data(), len);
    } else {
      packet_io::append_pong(it->second.write_buf, id);
    }
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
  };

  // Send small chunk (< block_size) to n_copies carriers using round-robin across the
  // carrier set. With redundancy N and C carriers, copies for successive packets walk
  // across the carrier indices:
  //   packet 1: rr, rr+1, ..., rr+N-1
  //   packet 2: rr+N, rr+N+1, ...
  // (indices wrap mod C). This matches the client's SMALL/RS round-robin.
  auto queue_small_to_carriers = [&](const uint8_t* data, size_t len) {
    if (len == 0 || carriers.empty()) return;
    ack_send_time_ns[next_send_id] = now_ns();
    const unsigned n_copies = std::max(1u, std::min(runtime_small_packet_redundancy,
                                                     static_cast<unsigned>(carriers.size())));
    size_t n_carriers = carriers.size();
    for (unsigned i = 0; i < n_copies && n_carriers > 0; ++i) {
      unsigned idx = (next_rr + i) % static_cast<unsigned>(n_carriers);
      auto it = carriers.begin();
      std::advance(it, idx);
      int fd = it->first;
      packet_io::append_small(it->second.write_buf, next_send_id, data, len);
      // Record that this SMALL packet id has been carried on this logical carrier.
      unacked_data[next_send_id].small_sent_on.insert(it->second.carrier_id);
      ev.events = EPOLLIN | EPOLLOUT;
      ev.data.fd = fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    }
    if (!carriers.empty())
      next_rr = (next_rr + n_copies) % static_cast<unsigned>(carriers.size());
    next_send_id++;
  };

  auto queue_rs_shard_to_carrier = [&](int fd, unsigned n, unsigned k, uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_rs_shard(it->second.write_buf, next_send_id, n, k, block_size, shard_index, shard_data);
  };

  auto flush_carrier_writes = [&]() {
    bool any_removed = false;
    packet_io::flush_carrier_writes(carriers, epfd, ev, nullptr,
      [&](int fd, const char* reason) {
        any_removed = true;
        if (dbg.f) dbglogf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=%s]\n",
                         (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1, reason);
      });
    if (carriers.empty() && !unacked_data.empty()) {
      retransmit_needed = true;
      { static uint64_t last_spam_ns = 0;
        if (dbg.f && dbg_rate_allow(last_spam_ns, now_ns(), 1000000000ull))
          dbglogf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=write_error_all_dead]\n",
                  (unsigned long long)(now_ns()/1000000ULL), unacked_data.size());
      }
    }
    // If survivors remain after a write-error removal, force the retransmit check
    // to run on the next iteration so we retransmit onto survivors immediately.
    if (any_removed && !carriers.empty() && !unacked_data.empty()) {
      last_retransmit_check_ns = 0;
      if (dbg.f) dbglogf(dbg, "[retransmit-check-reset t=%llu unacked=%zu survivors=%zu reason=write_error]\n",
                       (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), carriers.size());
    }
    for (auto it = outstanding_ping_ns.begin(); it != outstanding_ping_ns.end(); ) {
      if (!carriers.count(it->first)) it = outstanding_ping_ns.erase(it);
      else ++it;
    }
  };

  auto queue_ack_to_carrier = [&](int fd, uint64_t acked_id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_ack(it->second.write_buf, acked_id);
  };

  // Coalesced (cumulative) ACK. An ACK means "every id <= acked_id delivered", so rather than
  // emitting one ACK per delivered group we track only the HIGHEST id written to the backend
  // (and the carrier that completed it, for per-carrier RTT) and emit a single cumulative ACK
  // per flush. Flushes happen within the same epoll iteration as delivery, so no extra latency
  // is added and RTT sampling stays accurate; on a bulk c2s transfer this collapses the
  // return-path ACK stream from one-per-group to one-per-flush.
  uint64_t pending_ack_id = 0;
  int pending_ack_fd = -1;
  bool have_pending_ack = false;
  auto flush_pending_ack = [&]() {
    if (!have_pending_ack || carriers.empty()) return;
    int cfd = pending_ack_fd;
    if (!carriers.count(cfd)) cfd = carriers.begin()->first;
    queue_ack_to_carrier(cfd, pending_ack_id);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = cfd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
    have_pending_ack = false;
  };

  auto queue_server_metrics_to_carrier = [&](int fd, uint64_t max_rtt_ns) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    auto deque_avg = [](const std::deque<uint64_t>& d) -> uint64_t {
      if (d.empty()) return 0;
      uint64_t sum = 0; for (uint64_t v : d) sum += v;
      return sum / d.size();
    };
    // Report whether the s2c send window is saturated (link at capacity, window
    // deliberately closed) so the client suppresses load-pressure carrier growth in
    // that state — extra carriers cannot raise bounded-throughput, only spread it.
    const uint32_t mflags = (unacked_bytes_cache != 0
                             && unacked_bytes_cache >= rate_window_cap(s2c_window, get_window_base_rtt_ns()))
                                ? SSHOLL_SERVER_METRICS_FLAG_S2C_WINDOW_SATURATED : 0u;
    packet_io::append_server_metrics(it->second.write_buf, max_rtt_ns,
                                     deque_avg(c2s_shard_spread_ns),
                                     deque_avg(c2s_extra_shard_gap_ns),
                                     static_cast<uint32_t>(rs_pending.size()), mflags);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
  };

  auto queue_server_config_to_carrier = [&](int fd) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_server_config(it->second.write_buf,
                                   static_cast<uint16_t>(max_packet),
                                   static_cast<uint16_t>(runtime_small_packet_redundancy),
                                   args.config.max_delay_ms,
                                   runtime_rs_redundancy);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
  };

  auto flush_backend_pending = [&]() {
    // Drain as many items as possible in one call. This matters when many RS groups
    // decode simultaneously (e.g. 40 carriers all delivering at once): queuing each
    // item and returning after only one write would leave the backlog growing unboundedly
    // and delay ACKs by O(backlog) epoll iterations.
    while (backend_fd >= 0 && backend_connected && !backend_pending.empty()) {
      auto& front = backend_pending.front();
      ssize_t n = write(backend_fd, front.data.data(), front.data.size());
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Kernel buffer full: re-arm EPOLLOUT so we resume when space is available.
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = backend_fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
        } else {
          // Real write error (EPIPE, ECONNRESET, etc.): backend connection is broken.
          // Close it now so we stop trying to write on every iteration. The server
          // will detect no usable backend on the next iteration and stop running.
          if (dbg.f) dbglogf(dbg, "[backend-write-err t=%llu errno=%d]\n",
                           (unsigned long long)(now_ns()/1000000ULL), errno);
          epoll_ctl(epfd, EPOLL_CTL_DEL, backend_fd, nullptr);
          close(backend_fd);
          backend_fd = -1;
          backend_connected = false;
        }
        return;
      }
      front.data.erase(front.data.begin(), front.data.begin() + n);
      if (!front.data.empty()) {
        // Partial write: kernel buffer accepted some bytes but not all. Re-arm EPOLLOUT
        // so we resume writing the remainder when space is available.
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = backend_fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
        return;
      }
      // Record the highest id written to the backend for a single coalesced cumulative ACK
      // (emitted below / at the loop tail). completing_fd is where the ACK rides so the client
      // still gets an accurate per-carrier RTT sample, with no extra packets.
      pending_ack_id = front.id;
      pending_ack_fd = front.completing_fd;
      have_pending_ack = true;
      backend_pending.pop_front();
    }
    if (backend_fd >= 0 && backend_pending.empty()) {
      ev.events = EPOLLIN;
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
    }
    // Emit the one coalesced ACK covering everything just written to the backend.
    flush_pending_ack();
  };

  packet_io::ReceiveCallbacks recv_cb;
  recv_cb.on_deliver = [&](int cfd, uint64_t id, const uint8_t* data, size_t len) {
    backend_pending.push_back({id, std::vector<uint8_t>(data, data + len), cfd});
    connect_backend();
    if (backend_fd >= 0 && backend_connected) {
      ev.events = EPOLLIN | EPOLLOUT;
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
    }
  };
  recv_cb.on_rs_decode = [&](unsigned /*shards_received*/, unsigned /*n*/,
                              uint64_t spread_ns, uint64_t gap_final_ns) {
    c2s_shard_spread_ns.push_back(spread_ns);
    while (c2s_shard_spread_ns.size() > kMaxSpreadSamples) c2s_shard_spread_ns.pop_front();
    c2s_gap_final_ns.push_back(gap_final_ns);
    while (c2s_gap_final_ns.size() > kMaxSpreadSamples) c2s_gap_final_ns.pop_front();
  };
  // Per-shard stall estimate: every shard's gap from its group's first shard. A gap beyond
  // the retransmit-scale stall threshold (~RTT/2) means its carrier stalled (TCP retransmit)
  // rather than merely jittered, so this counts genuine loss/overload — NOT the link's base
  // jitter. The late fraction is rho-bar, which drives redundancy (see stall_threshold_ns).
  recv_cb.on_rs_shard_gap = [&](uint64_t gap_ns) {
    qest_total_gaps += 1;
    if (gap_ns > carrier_adapt::stall_threshold_ns(get_base_rtt_ns())) qest_late_gaps += 1;
    qest_recent_gaps.push_back(gap_ns);
    if (qest_recent_gaps.size() > 2000) qest_recent_gaps.pop_front();
  };
  recv_cb.on_rs_extra_shard = [&](uint64_t gap_ns) {
    c2s_extra_shard_gap_ns.push_back(gap_ns);
    while (c2s_extra_shard_gap_ns.size() > kMaxSpreadSamples) c2s_extra_shard_gap_ns.pop_front();
  };
  recv_cb.on_small_extra_copy = [&](uint64_t gap_ns) {
    c2s_small_extra_copy_gap_ns.push_back(gap_ns);
    while (c2s_small_extra_copy_gap_ns.size() > kMaxSpreadSamples) c2s_small_extra_copy_gap_ns.pop_front();
  };
  recv_cb.on_start_connection = [&](int fd, uint64_t carrier_id) {
    auto it = carriers.find(fd);
    if (it != carriers.end()) it->second.shared_carrier_id = carrier_id;
    if (dbg.f) dbglogf(dbg, "[carrier-hello fd=%d shared_carrier_id=%llu]\n",
                     fd, (unsigned long long)carrier_id);
  };
  recv_cb.on_ping = [&](int fd, uint64_t id, size_t payload_size) { send_pong(fd, id, payload_size); };
  // Client may send SUGGEST_CLOSE when it has decided a carrier is dead or being
  // replaced. Mark it and close in the event loop after packet parsing returns.
  // This avoids erasing the carrier while process_carrier_read is using CarrierState&.
  recv_cb.on_suggest_close = [&](int fd) {
    if (!carriers.count(fd)) return;
    pending_peer_suggest_close.insert(fd);
    if (dbg.f) dbglogf(dbg, "[carrier-mark-close t=%llu fd=%d reason=peer_suggest_close pending=%zu]\n",
                     (unsigned long long)(now_ns()/1000000ULL), fd, pending_peer_suggest_close.size());
  };
  recv_cb.on_ack = [&](int fd, uint64_t acked_id) {
    auto it = ack_send_time_ns.find(acked_id);
    if (it != ack_send_time_ns.end()) {
      uint64_t rtt = now_ns() - it->second;
      // Skip measurements that span a recovery from total carrier loss: the data was
      // sent before we reconnected, so `rtt` would be ~the outage duration rather than
      // link latency. Recording it would inflate every RTT-scaled timeout (retransmit,
      // rs-stale, ping, idle) for up to max_server_recent_rtt samples and stall recovery.
      bool spans_outage = (it->second < last_recovery_ns);
      // Sanity check: discard clearly-bogus values (> 60s); wrap-around produces ~1.8e19 ns.
      if (!spans_outage && rtt < 60000000000ULL) {
        if (dbg.f && rtt > 5000000000ULL)
          dbglogf(dbg, "[ack-rtt-high t=%llu acked_id=%llu rtt_ms=%llu]\n",
                  (unsigned long long)(now_ns()/1000000ULL), (unsigned long long)acked_id,
                  (unsigned long long)(rtt/1000000ULL));
        server_recent_rtt_ns.push_back(rtt);
        while (server_recent_rtt_ns.size() > max_server_recent_rtt) server_recent_rtt_ns.pop_front();
        if (base_rtt_min_session_ns == 0 || rtt < base_rtt_min_session_ns)
          base_rtt_min_session_ns = rtt;
        auto cs = carriers.find(fd);
        if (cs != carriers.end()) cs->second.last_rtt_ns = rtt;
      }
    }
    for (auto it_m = ack_send_time_ns.begin(); it_m != ack_send_time_ns.end(); )
      if (it_m->first <= acked_id) it_m = ack_send_time_ns.erase(it_m);
      else ++it_m;
    // Data confirmed received: remove from retransmit buffer.
    uint64_t acked_bytes = 0;
    for (auto it_u = unacked_data.begin(); it_u != unacked_data.end() && it_u->first <= acked_id; ) {
      acked_bytes += it_u->second.wire_cost();
      it_u = unacked_data.erase(it_u);
    }
    // ACK-clocked rate estimate for the s2c send window (this also has a nice property: when
    // the window has closed the pump and deliveries pause at the cap, so there is nothing new
    // to ACK and the rate simply holds — it cannot spiral down to zero).
    uint64_t outstanding_after = 0;
    for (const auto& [uid2, ui2] : unacked_data) outstanding_after += ui2.wire_cost();
    rate_window_on_ack(s2c_window, acked_bytes, now_ns(), outstanding_after, get_window_base_rtt_ns());
  };
  recv_cb.on_pong = [&](int fd, uint64_t) {
    outstanding_ping_ns.erase(fd);
  };
  recv_cb.on_client_metrics = [&](uint64_t avg_shard_spread_ns, uint64_t avg_extra_shard_gap_ns,
                                  float fraction_struggling, uint32_t rs_pending_count,
                                  bool can_decrease_rs, bool can_decrease_small,
                                  bool client_c2s_window_saturated_arg) {
    (void)avg_shard_spread_ns;
    (void)avg_extra_shard_gap_ns;
    (void)rs_pending_count;
    (void)can_decrease_rs;
    (void)can_decrease_small;
    // fraction_struggling now carries the client's latency-budget s2c loss estimate q.
    s2c_loss_q = fraction_struggling;
    s2c_last_received_ns = now_ns();
    client_c2s_window_saturated = client_c2s_window_saturated_arg;
  };
  recv_cb.on_set_config = [&](const PacketConfig& pc) {
    runtime_auto_adapt = (pc.auto_adapt != 0);
    max_packet = std::min(static_cast<size_t>(pc.packet_size), MAX_PACKET_PAYLOAD);
    if (max_packet == 0) max_packet = 800;
    // In auto_adapt the SERVER owns redundancy (the probability model) and pushes it via
    // SERVER_CONFIG; do NOT let the client's SET_CONFIG clobber the model's rs/small here,
    // or the two fight and produce inconsistent (rs, copies) snapshots. Only honor the
    // client's redundancy values in manual mode.
    if (!runtime_auto_adapt) {
      runtime_small_packet_redundancy = pc.small_packet_redundancy;
      if (runtime_small_packet_redundancy < 2u) runtime_small_packet_redundancy = 2u;
      runtime_small_packet_redundancy = std::min(runtime_small_packet_redundancy, std::max(2u, static_cast<unsigned>(carriers.size())));
      runtime_rs_redundancy = pc.reed_solomon_redundancy;
      if (runtime_rs_redundancy < 0.1f) runtime_rs_redundancy = 0.1f;
    }
    runtime_reconnect_timeout_sec = pc.reconnect_timeout_sec;
    runtime_max_delay_ns = static_cast<uint64_t>(pc.max_delay_ms * 1000000.0f);
    if (dbg.f) dbglogf(dbg, "[set-config-applied t=%llu pkt_size=%zu rs_red=%.2f small_copies=%u auto_adapt=%d reconnect_timeout_sec=%u]\n",
                     (unsigned long long)(now_ns()/1000000ULL), max_packet,
                     (double)runtime_rs_redundancy, (unsigned)runtime_small_packet_redundancy,
                     (int)runtime_auto_adapt, (unsigned)runtime_reconnect_timeout_sec);
    // When auto_adapt, send current config so client has initial sync; server will send again when it adapts.
    if (runtime_auto_adapt && !carriers.empty()) {
      last_sent_rs_redundancy = runtime_rs_redundancy;
      last_sent_small_packet_redundancy = runtime_small_packet_redundancy;
      queue_server_config_to_carrier(carriers.begin()->first);
    }
  };

  auto process_carrier_read = [&](int fd, CarrierState& s) {
    last_read_errno = 0;
    last_read_eof = false;
    uint8_t buf[READ_BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n <= 0) {
      if (n == 0) {
        last_read_eof = true;
        return false;
      }
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        last_read_errno = errno;
        return false;
      }
      return true;
    }
    s.read_buf.insert(s.read_buf.end(), buf, buf + n);
    return packet_io::process_carrier_read(fd, s, reassembly, rs_pending, recently_decoded_ns, small_copy_arrival_times, next_deliver_id, recv_cb);
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    // 500ms bound ensures retransmit/ping checks run promptly even when carriers are idle.
    // When a backend remainder is being held for coalescing (--max-delay), wake sooner so
    // it flushes on time instead of waiting a full poll cycle.
    int poll_timeout_ms = 500;
    if (backend_partial_since_ns != 0 && runtime_max_delay_ns > 0) {
      uint64_t elapsed = now_ns() - backend_partial_since_ns;
      uint64_t remaining_ms = (runtime_max_delay_ns > elapsed) ? ((runtime_max_delay_ns - elapsed) / 1000000ULL + 1) : 0;
      if (static_cast<int>(remaining_ms) < poll_timeout_ms) poll_timeout_ms = static_cast<int>(remaining_ms);
    }
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), poll_timeout_ms);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;
      uint32_t e = events[i].events;

      if (fd == listen_fd) {
        while (true) {
          int client = accept(listen_fd, nullptr, nullptr);
          if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
          }
          set_nonblocking(client);
          ev.events = EPOLLIN;
          ev.data.fd = client;
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, client, &ev) == 0) {
            const bool recovered_from_empty = carriers.empty();
            CarrierState& cs = carriers[client];
            if (cs.carrier_id == 0) cs.carrier_id = next_carrier_id_global++;
            cs.connect_ns = now_ns();
            if (recovered_from_empty) last_recovery_ns = cs.connect_ns;
            if (dbg.f) { dbglogf(dbg, "[carrier-open t=%llu fd=%d total=%zu]\n",
                               (unsigned long long)(now_ns()/1000000ULL), client, carriers.size());
                        dbg_flush(dbg); }
            // Send READY so client knows the link is up before it sends data.
            packet_io::append_ready(carriers[client].write_buf);
            // Catch-up cumulative ACK: tell the client how much c2s data we've already
            // delivered to the backend, in case its ACKs were lost while carriers were
            // down. Without this the client can keep retransmitting already-delivered
            // data indefinitely on a quiet stream.
            if (next_deliver_id > 0)
              packet_io::append_ack(carriers[client].write_buf, next_deliver_id - 1);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = client;
            epoll_ctl(epfd, EPOLL_CTL_MOD, client, &ev);
            if (backend_fd < 0)
              connect_backend();
            // Re-send any data that was in-flight when all previous carriers died,
            // using the same send_ids so the client can complete partial RS groups.
            if (retransmit_needed && !unacked_data.empty()) {
              retransmit_needed = false;
              auto& cs = carriers[client];
              const uint64_t retransmit_now = now_ns();
              if (dbg.f) dbglogf(dbg, "[retransmit-on-reconnect t=%llu fd=%d items=%zu]\n",
                               (unsigned long long)(retransmit_now/1000000ULL), client, unacked_data.size());
              for (auto& [uid, ui] : unacked_data) {
                if (ui.is_small) {
                  packet_io::append_small(cs.write_buf, uid, ui.data.data(), ui.data.size());
                  // Track by logical carrier_id, not raw fd, so the
                  // retransmit logic can correctly avoid resending on
                  // the same logical carrier even when fds are reused.
                  ui.small_sent_on.insert(cs.carrier_id);
                } else {
                  // Re-encode with the original (n, k, block_size) so these shards combine
                  // with any partials the client retained.
                  auto shards = packet_io::rs_reencode_shards(ui);
                  for (unsigned si = 0; si < ui.n; ++si) {
                    packet_io::append_rs_shard(cs.write_buf, uid, ui.n, ui.k, ui.block_size,
                                               si, shards[si].data());
                    // Track by logical carrier_id, not raw fd, so the retransmit
                    // logic can correctly avoid resending the same shard on the
                    // same logical carrier even when fds are reused.
                    ui.rs_shard_sent_on[si].insert(cs.carrier_id);
                  }
                }
                // Reset timer so the periodic 3 s retransmit doesn't immediately
                // fire a redundant duplicate of what we just queued.
                ui.send_ns = retransmit_now;
                // Re-stamp the RTT send-time so the eventual ACK measures latency from
                // this retransmission, not the original pre-outage send (which would
                // record an RTT ~= the outage duration and inflate every timeout).
                ack_send_time_ns[uid] = retransmit_now;
              }
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = client;
              epoll_ctl(epfd, EPOLL_CTL_MOD, client, &ev);
            }
            // If there is buffered backend data that couldn't be encoded earlier
            // because all carriers were dead, encode and send it now.
            if (!backend_read_buf.empty()) {
              flush_backend_pending();
              flush_carrier_writes();
            }
          } else {
            close(client);
          }
        }
        continue;
      }

      if (fd == backend_fd) {
        ensure_backend_connected();
        if (!backend_connected) continue;
        if ((e & EPOLLIN) && !backend_read_wanted) {
          // Send window is saturated: do NOT read more. Converting the epoll interest now
          // stops a perpetually-ready readable backend from busy-spinning the event loop;
          // the producer gets real TCP backpressure instead (the whole point of the window).
          arm_backend();
          e &= ~(uint32_t)EPOLLIN;
        }
        if (e & EPOLLIN) {
          uint8_t buf[READ_BUF_SIZE];
          ssize_t nr = read(backend_fd, buf, sizeof buf);
          if (nr <= 0) {
            if (nr == 0) {
              running = false;
              if (dbg.f) dbglogf(dbg, "[backend-eof t=%llu]\n", (unsigned long long)(now_ns()/1000000ULL));
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
              if (dbg.f) dbglogf(dbg, "[backend-read-err t=%llu errno=%d]\n",
                               (unsigned long long)(now_ns()/1000000ULL), errno);
            }
            break;
          }
          backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
        }
        if (e & EPOLLOUT) {
          flush_backend_pending();
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          if (dbg.f) dbglogf(dbg, "[backend-err t=%llu]\n", (unsigned long long)(now_ns()/1000000ULL));
          running = false;
          break;
        }
        continue;
      }

      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        bool carrier_removed = false;
        if (e & EPOLLIN) {
          if (!process_carrier_read(fd, it->second)) {
            if (dbg.f) dbglogf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=read_error eof=%d err=%d errstr=%s events=0x%x rbuf=%zu wbuf=%zu]\n",
                             (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1,
                             last_read_eof ? 1 : 0, last_read_errno,
                             last_read_errno ? strerror(last_read_errno) : "none",
                             (unsigned)e, it->second.read_buf.size(), it->second.write_buf.size());
            close(fd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            carriers.erase(it);
            pending_peer_suggest_close.erase(fd);
            if (carriers.empty() && !unacked_data.empty()) {
              retransmit_needed = true;
              if (dbg.f) dbglogf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=all_dead fd=%d]\n",
                               (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), fd);
            }
            if (!carriers.empty() && !unacked_data.empty()) {
              last_retransmit_check_ns = 0;
              if (dbg.f) dbglogf(dbg, "[retransmit-check-reset t=%llu unacked=%zu fd=%d survivors=%zu]\n",
                               (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), fd, carriers.size());
            }
            carrier_removed = true;
          }
        }
        if (!carrier_removed && pending_peer_suggest_close.count(fd)) {
          if (dbg.f) dbglogf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=peer_suggest_close]\n",
                           (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1);
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
          pending_peer_suggest_close.erase(fd);
          if (carriers.empty() && !unacked_data.empty()) {
            retransmit_needed = true;
            if (dbg.f) dbglogf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=peer_closed_last]\n",
                             (unsigned long long)(now_ns()/1000000ULL), unacked_data.size());
          }
          if (!carriers.empty() && !unacked_data.empty()) {
            last_retransmit_check_ns = 0;
            if (dbg.f) dbglogf(dbg, "[retransmit-check-reset t=%llu unacked=%zu fd=%d survivors=%zu reason=peer_suggest_close]\n",
                             (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), fd, carriers.size());
          }
          carrier_removed = true;
        }
        if (!carrier_removed && (e & (EPOLLERR | EPOLLHUP))) {
          if (dbg.f) dbglogf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=epoll_err_hup]\n",
                           (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1);
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
          pending_peer_suggest_close.erase(fd);
          if (carriers.empty() && !unacked_data.empty()) {
            retransmit_needed = true;
            if (dbg.f) dbglogf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=all_dead fd=%d]\n",
                             (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), fd);
          }
          if (!carriers.empty() && !unacked_data.empty()) {
            last_retransmit_check_ns = 0;
            if (dbg.f) dbglogf(dbg, "[retransmit-check-reset t=%llu unacked=%zu fd=%d survivors=%zu]\n",
                             (unsigned long long)(now_ns()/1000000ULL), unacked_data.size(), fd, carriers.size());
          }
        }
      }
    }

    const uint64_t now_ns_val = now_ns();

    // ── Debug: periodic state dump (mirrors client format) ────────────────────
    if (dbg.f) {
      static uint64_t last_dbg_ns = 0;
      if (now_ns_val - last_dbg_ns >= 1000000000ULL) {
        last_dbg_ns = now_ns_val;
        size_t unacked_bytes = 0;
        for (const auto& [_, ui] : unacked_data) unacked_bytes += ui.data.size();
        if (rs_pending.empty()) {
          dbglogf(dbg, "[srv] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=0 next_deliver_id=%llu backend_buf=%zu rs_redundancy=%.2f small_packet_copies=%u wcap_kb=%zu rate_kbps=%.0f base_rtt_ms=%llu\n",
                  carriers.size(), unacked_data.size(), unacked_bytes, reassembly.size(),
                  (unsigned long long)next_deliver_id, backend_read_buf.size(),
                  (double)runtime_rs_redundancy, (unsigned)runtime_small_packet_redundancy,
                  rate_window_cap(s2c_window, get_window_base_rtt_ns())/1024,
                  s2c_window.rate_bps/1024.0,
                  (unsigned long long)(get_window_base_rtt_ns()/1000000ULL));
        } else {
          auto it = rs_pending.begin();
          dbglogf(dbg, "[srv] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=%zu next_deliver_id=%llu backend_buf=%zu rs_redundancy=%.2f small_packet_copies=%u first_rs_id=%llu shards=%zu k=%u n=%u wcap_kb=%zu rate_kbps=%.0f base_rtt_ms=%llu\n",
                  carriers.size(), unacked_data.size(), unacked_bytes, reassembly.size(), rs_pending.size(),
                  (unsigned long long)next_deliver_id, backend_read_buf.size(),
                  (double)runtime_rs_redundancy, (unsigned)runtime_small_packet_redundancy,
                  (unsigned long long)it->first, it->second.shards.size(), it->second.k, it->second.n,
                  rate_window_cap(s2c_window, get_window_base_rtt_ns())/1024,
                  s2c_window.rate_bps/1024.0,
                  (unsigned long long)(get_window_base_rtt_ns()/1000000ULL));
        }
        dbg_flush(dbg);
      }
    }

    // ── Ping / inactivity-check / carrier quality (suggest close) ───────────
    // 500 ms: detect dead carriers promptly so we send SUGGEST_CLOSE and client can recover quickly.
    if (now_ns_val - last_ping_check_ns >= 500000000ULL) {
      last_ping_check_ns = now_ns_val;

      std::vector<carrier_adapt::CarrierInfo> carrier_infos;
      for (auto& [cfd, cs] : carriers) {
        carrier_infos.push_back({cfd, cs.last_rtt_ns, cs.last_recv_ns, cs.connect_ns, cs.last_send_ns});
      }
      auto quality = carrier_adapt::assess_carriers(carrier_infos, now_ns_val, scaled_ns);

      // CARRIER_STATUS: tell the client which carriers look dead from OUR (c2s) receive
      // side, named by shared_carrier_id, sent over a healthy load-spread carrier (the one
      // we've sent on least recently, excluding the dead ones). This reaches the client
      // even though nothing succeeds on the dead carrier itself. (Phase 2: report only;
      // the client logs it and does not yet act.)
      if (now_ns_val - last_carrier_status_ns >= 1000000000ULL) {
        last_carrier_status_ns = now_ns_val;
        // Only rx-dead carriers (silent while a peer is actively delivering) — NOT plain
        // idle_dead, which during a quiet period would flag every carrier and tell the
        // client to reap the whole fleet.
        std::set<int> dead_set(quality.rx_dead_fds.begin(), quality.rx_dead_fds.end());
        std::vector<uint64_t> dead_ids;
        for (int dfd : quality.rx_dead_fds) {
          auto di = carriers.find(dfd);
          if (di != carriers.end() && di->second.shared_carrier_id != 0)
            dead_ids.push_back(di->second.shared_carrier_id);
        }
        if (!dead_ids.empty()) {
          // Pick the non-dead carrier we've sent on least recently (spread control load;
          // every carrier is an equal TCP connection, so "freshness" is noise).
          int best = -1; uint64_t oldest_send = 0;
          for (auto& [cfd, cstate] : carriers) {
            if (dead_set.count(cfd)) continue;
            uint64_t age = now_ns_val - cstate.last_send_ns;
            if (best < 0 || age > oldest_send) { best = cfd; oldest_send = age; }
          }
          if (best >= 0) {
            packet_io::append_carrier_status(carriers[best].write_buf, dead_ids);
            ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = best;
            epoll_ctl(epfd, EPOLL_CTL_MOD, best, &ev);
            if (dbg.f) dbglogf(dbg, "[carrier-status-sent t=%llu over_fd=%d dead_count=%zu]\n",
                             (unsigned long long)(now_ns_val/1000000ULL), best, dead_ids.size());
          }
        }
      }

      // Reap confidently-dead carriers ourselves. The server can normally only
      // SUGGEST_CLOSE (the client is the master that opens/closes carriers), but a
      // dead-but-open carrier — e.g. after a WiFi/VPN drop, where the old socket hasn't
      // errored yet — never receives that suggestion. If we keep it, retransmits get
      // round-robined onto it and never reach the client's fresh carriers, so the logical
      // stream never recovers. reap_fds is the safe subset (a peer is actively receiving
      // while this carrier is not), so closing it here is cleanup, not carrier management.
      for (int cfd : quality.reap_fds) {
        auto it = carriers.find(cfd);
        if (it == carriers.end()) continue;
        if (dbg.f) dbglogf(dbg, "[carrier-reap t=%llu fd=%d total=%zu reason=dead_but_open]\n",
                         (unsigned long long)(now_ns_val/1000000ULL), cfd, carriers.size()-1);
        close(cfd);
        epoll_ctl(epfd, EPOLL_CTL_DEL, cfd, nullptr);
        carriers.erase(it);
        pending_peer_suggest_close.erase(cfd);
        outstanding_ping_ns.erase(cfd);
      }
      if (!quality.reap_fds.empty()) {
        if (carriers.empty() && !unacked_data.empty()) {
          retransmit_needed = true;  // recover by replaying once a fresh carrier connects
        } else if (!unacked_data.empty()) {
          last_retransmit_check_ns = 0;  // retransmit onto the survivors immediately
        }
      }

      size_t backlog_bytes = 0;
      for (const auto& [_, ud] : unacked_data) backlog_bytes += ud.data.size();
      // Base predicate is shared with the client; the server additionally treats any
      // non-empty pending buffer (backend / reassembly / rs) as backlog.
      const bool heavy_backlog =
          carrier_adapt::is_heavy_backlog(backlog_bytes, unacked_data.size()) ||
          !backend_pending.empty() ||
          !reassembly.empty() ||
          !rs_pending.empty();
      // (Blanket idle-pinging removed: a lost PING head-of-line-blocks that carrier's next
      // s2c data shard. Dead carriers are now detected from data — our c2s rx_dead feeds
      // CARRIER_STATUS to the client, and the client detects s2c-dead itself — and s2c RTT
      // comes from client ACKs. min-data keepalive below still covers firewall/NAT.)

      // --min-data-per-minute: the link's idle keepalive (on by default). Keep each carrier
      // sending at a slow, steady rate so a firewall/NAT never sees a long idle gap. The
      // per-minute budget is spread over 10-second windows (6 windows/min): each carries
      // min_bpm/6 bytes, topped up with a small keepalive when real traffic falls short. A
      // 10s window keeps the default packet rate low (~6/min/carrier) while bounding the idle
      // gap to ~10s. Runs every ping-check tick (~500 ms). (See the matching block in client.cc.)
      const unsigned min_bpm = args.config.min_data_per_minute;
      if (min_bpm > 0) {
        const uint64_t window_ns = 10000000000ULL;                    // 10 s
        const uint64_t target = std::max<uint64_t>(1, min_bpm / 6);   // bytes per 10s window
        const size_t pkt_max = std::max<size_t>(1, std::min(max_packet, static_cast<size_t>(MAX_PACKET_PAYLOAD)));
        for (auto& [cfd, cs] : carriers) {
          if (now_ns_val - cs.last_window_reset_ns >= window_ns) {
            cs.bytes_sent_this_window = 0;
            cs.last_window_reset_ns = now_ns_val;
          }
          if (cs.bytes_sent_this_window < target && cs.write_buf.empty()) {
            size_t len = std::min<size_t>(target - cs.bytes_sent_this_window, pkt_max);
            std::vector<uint8_t> payload(len);
            std::uniform_int_distribution<int> byte_dist(0, 255);
            for (size_t i = 0; i < len; ++i) payload[i] = static_cast<uint8_t>(byte_dist(keepalive_gen));
            packet_io::append_ping(cs.write_buf, 0, payload.data(), len);
            outstanding_ping_ns[cfd] = now_ns_val;
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
        }
      }

      // SUGGEST_CLOSE: avoid self-induced churn when traffic is light/idle.
      // Only suggest-close aggressively under meaningful backlog pressure.
      if (heavy_backlog) {
        // Server cannot close directly; client performs actual close.
        // Keep rate limiting (1 per 10s) to avoid mass-close bursts.
        for (int cfd : quality.dead_idle_fds) {
          // Skip any we already reaped above (don't re-insert via operator[]).
          auto itc = carriers.find(cfd);
          if (itc == carriers.end()) continue;
          if (now_ns_val - last_suggest_close_ns < suggest_close_min_interval_ns) break;
          last_suggest_close_ns = now_ns_val;
          packet_io::append_suggest_close(itc->second.write_buf);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = cfd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          if (dbg.f) dbglogf(dbg, "[suggest-close t=%llu fd=%d reason=dead_idle]\n",
                           (unsigned long long)(now_ns_val/1000000ULL), cfd);
        }
        if (quality.rtt_outlier_fd >= 0 && carriers.count(quality.rtt_outlier_fd)
            && now_ns_val - last_suggest_close_ns >= suggest_close_min_interval_ns) {
          last_suggest_close_ns = now_ns_val;
          packet_io::append_suggest_close(carriers[quality.rtt_outlier_fd].write_buf);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = quality.rtt_outlier_fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, quality.rtt_outlier_fd, &ev);
          if (dbg.f) dbglogf(dbg, "[suggest-close t=%llu fd=%d reason=rtt_outlier]\n",
                           (unsigned long long)(now_ns_val/1000000ULL), quality.rtt_outlier_fd);
        }
      }

      // Update global receive timestamp from all live carriers.
      for (auto& [cfd, cs] : carriers)
        if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

      // Global idle timeout: if nothing from any carrier for this long, the client is gone.
      // Adaptive default 12×RTT clamped [60 s, 300 s]; set --reconnect-timeout (client
      // propagates it here via SET_CONFIG) to stay alive across a longer outage so the
      // client can still reconnect when the link returns.
      uint64_t global_idle_ns = (runtime_reconnect_timeout_sec > 0)
          ? (uint64_t)runtime_reconnect_timeout_sec * 1000000000ULL
          : scaled_ns(12, 60000000000ULL, 300000000000ULL);
      if (now_ns_val - last_global_recv_ns > global_idle_ns) {
        if (dbg.f) dbglogf(dbg, "[global-idle-timeout t=%llu]\n", (unsigned long long)(now_ns_val/1000000ULL));
        running = false;
      }
    }

    // Timeout-based retransmit: re-send any group unACK'd for 4×RTT (or 2.5 s when no RTT) to carriers.
    if (!unacked_data.empty() && !carriers.empty()
        && now_ns_val - last_retransmit_check_ns >= 500000000ULL) {
      last_retransmit_check_ns = now_ns_val;
      // 4×RTT, floored at 500 ms. Mirrors the client change: the old 2 s floor caused
      // multi-second stalls after carrier death on low-latency test links.
      // Before ≥2 samples exist, honor the --rtt-ms cold-start hint (scaled_ns falls back
      // to it) so high-latency links aren't retransmitted every 2.5 s before the first ACKs.
      uint64_t retransmit_timeout_ns = (server_recent_rtt_ns.size() >= 2 || rtt_hint_ns > 0)
          ? scaled_ns(4, 500000000ULL, 60000000000ULL)
          : 2500000000ULL;  // 2.5 s when no RTT samples and no hint (cold start)
      std::vector<int> rt_carriers;
      for (auto& [cfd, cs] : carriers)
        if (!cs.connecting) rt_carriers.push_back(cfd);
      if (!rt_carriers.empty()) {
        unsigned rt_idx = 0;
        const unsigned small_rt_copies = std::max(1u, std::min(3u, static_cast<unsigned>(rt_carriers.size())));
        // Bound the work per cycle. unacked_data is ordered by id, and the receiver delivers
        // in order, so it is blocked only on the LOWEST unacked id — anything above the gap is
        // buffered there already. Re-encoding/resending the whole backlog every cycle (seen at
        // 689 items × an RS group each after a long outage) starves the single-threaded loop and
        // the gap data never gets through. Cap to the lowest N due items so the gap is always
        // covered; higher ids are reached on later cycles once they come due again.
        const size_t kMaxRetransmitItemsPerCycle = 64;
        size_t rt_items = 0;
        for (auto& [uid, ui] : unacked_data) {
          if (ui.send_ns == 0 || now_ns_val - ui.send_ns < retransmit_timeout_ns) continue;
          if (rt_items >= kMaxRetransmitItemsPerCycle) break;
          ++rt_items;
          if (ui.is_small) {
            // Only retransmit SMALL on carriers that have not yet carried this uid.
            std::vector<int> candidates;
            for (int cfd : rt_carriers) {
              auto itc = carriers.find(cfd);
              if (itc == carriers.end()) continue;
              uint64_t cid = itc->second.carrier_id;
              if (!ui.small_sent_on.count(cid)) candidates.push_back(cfd);
            }
            // If every carrier has already carried this uid, allow a new round of
            // retransmits on all live carriers rather than stalling forever.
            if (candidates.empty()) {
              candidates = rt_carriers;
              ui.small_sent_on.clear();
            }
            if (!candidates.empty()) {
              unsigned copies = std::min(small_rt_copies, static_cast<unsigned>(candidates.size()));
              if (dbg.f) dbglogf(dbg, "[retransmit-small t=%llu uid=%llu age_ms=%llu copies=%u]\n",
                               (unsigned long long)(now_ns_val/1000000ULL), (unsigned long long)uid,
                               (unsigned long long)((now_ns_val - ui.send_ns)/1000000ULL), copies);
              for (unsigned c = 0; c < copies; ++c) {
                int cfd = candidates[(rt_idx + c) % candidates.size()];
                auto itc = carriers.find(cfd);
                if (itc == carriers.end()) continue;
                ui.small_sent_on.insert(itc->second.carrier_id);
                packet_io::append_small(carriers[cfd].write_buf, uid, ui.data.data(), ui.data.size());
                ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
              }
              rt_idx += copies;
            }
          } else {
            auto shards = packet_io::rs_reencode_shards(ui);
            std::set<int> touched;
            for (unsigned si = 0; si < ui.n; ++si) {
              auto& sent_set = ui.rs_shard_sent_on[si];
              std::vector<int> shard_candidates;
              for (int cfd : rt_carriers) {
                auto itc = carriers.find(cfd);
                if (itc == carriers.end()) continue;
                uint64_t cid = itc->second.carrier_id;
                if (!sent_set.count(cid)) shard_candidates.push_back(cfd);
              }
              // If every live carrier has already carried this shard at least once,
              // reset the per-shard history and allow another full round of
              // retransmits on all carriers so RS groups do not stall forever.
              if (shard_candidates.empty()) {
                shard_candidates = rt_carriers;
                sent_set.clear();
              }
              if (shard_candidates.empty())
                continue;
              int cfd = shard_candidates[(rt_idx + si) % shard_candidates.size()];
              auto itc = carriers.find(cfd);
              if (itc == carriers.end()) continue;
              packet_io::append_rs_shard(carriers[cfd].write_buf, uid,
                                         ui.n, ui.k, ui.block_size, si, shards[si].data());
              sent_set.insert(itc->second.carrier_id);
              touched.insert(cfd);
            }
            if (dbg.f && !touched.empty()) dbglogf(dbg, "[retransmit-rs t=%llu uid=%llu age_ms=%llu n=%u k=%u carriers=%zu unique_cfds=%zu]\n",
                             (unsigned long long)(now_ns_val/1000000ULL), (unsigned long long)uid,
                             (unsigned long long)((now_ns_val - ui.send_ns)/1000000ULL),
                             ui.n, ui.k, rt_carriers.size(), touched.size());
            for (int cfd : touched) {
              ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
            }
            rt_idx += ui.n;
          }
          ui.send_ns = now_ns_val;  // throttle: don't retransmit again for 3 s
          // Re-stamp RTT send-time so the eventual ACK measures from this retransmission,
          // not the original send (which would record an outage-sized RTT and inflate
          // every RTT-scaled timeout). See the reconnect-retransmit path for the same fix.
          ack_send_time_ns[uid] = now_ns_val;
        }
      }
    }

    // RS stale-group drain: evict incomplete groups from memory after 4×RTT (min 10 s).
    // We do NOT jump next_deliver_id. Jumping introduces a hole in the SSH byte stream,
    // which SSH detects as a MAC failure and closes the connection. Instead we wait for
    // the retransmit path to fill the gap; if the sender is truly gone, global_idle_ns
    // will close the connection cleanly.
    if (now_ns_val - last_rs_drain_ns >= 1000000000ULL) {
      last_rs_drain_ns = now_ns_val;
      uint64_t rs_stale_ns = scaled_ns(4, 10000000000ULL, 60000000000ULL);
      // Evict stale incomplete RS groups (memory management only — no gap-jump).
      for (auto it = rs_pending.begin(); it != rs_pending.end(); ) {
        if (it->second.first_recv_ns > 0 && now_ns_val - it->second.first_recv_ns > rs_stale_ns) {
          if (dbg.f) dbglogf(dbg, "[rs-stale-evict t=%llu id=%llu age_ms=%llu shards_had=%zu k=%u n=%u]\n",
                           (unsigned long long)(now_ns_val/1000000ULL), (unsigned long long)it->first,
                           (unsigned long long)((now_ns_val - it->second.first_recv_ns)/1000000ULL),
                           it->second.shards.size(), it->second.k, it->second.n);
          it = rs_pending.erase(it);
        } else
          ++it;
      }
      // Deliver any reassembly entries that are now contiguous from next_deliver_id.
      while (true) {
        auto ra = reassembly.find(next_deliver_id);
        if (ra != reassembly.end()) {
          recv_cb.on_deliver(-1, next_deliver_id, ra->second.data(), ra->second.size());
          reassembly.erase(ra);
          next_deliver_id++;
          next_deliver_id_stuck_since_ns = 0;
        } else if (rs_pending.count(next_deliver_id)) {
          next_deliver_id_stuck_since_ns = 0;  // decoding in progress, not stuck
          break;
        } else {
          // Gap: ID absent from both reassembly and rs_pending. Do NOT jump — wait
          // for the retransmit to fill it.
          bool has_higher = !reassembly.empty() || !rs_pending.empty();
          if (!has_higher) { next_deliver_id_stuck_since_ns = 0; break; }
          if (next_deliver_id_stuck_since_ns == 0) {
            next_deliver_id_stuck_since_ns = now_ns_val;
            if (dbg.f) dbglogf(dbg, "[gap-detected t=%llu next_deliver_id=%llu reassembly=%zu rs_pending=%zu]\n",
                             (unsigned long long)(now_ns_val/1000000ULL), (unsigned long long)next_deliver_id,
                             reassembly.size(), rs_pending.size());
          }
          break;
        }
      }
    }

    // When auto_adapt, server manages its own redundancy and informs the client. Run the model
    // when EITHER self-measured c2s spread samples are available OR the client reports a fresh
    // s2c loss estimate: a download-only session (client sends only SMALL pings) never feeds
    // c2s_shard_spread_ns, and without this the redundancy stayed frozen at the startup value
    // for the whole session even as the s2c direction lost shards (AUD-1).
    const uint64_t s2c_stale_ns = 2 * metrics_interval_ns;
    const bool s2c_fresh_for_adapt = (s2c_last_received_ns != 0) &&
        (now_ns_val - s2c_last_received_ns < s2c_stale_ns);
    if (runtime_auto_adapt && !carriers.empty() && now_ns_val - last_adapt_ns >= adapt_interval_ns
        && (c2s_shard_spread_ns.size() >= carrier_adapt::kMinSamplesForAdapt || s2c_fresh_for_adapt)) {
      const uint64_t adapt_dt = now_ns_val - last_adapt_ns;  // elapsed since last adapt (rate-limiting)
      last_adapt_ns = now_ns_val;
      // Asymmetric adaptation — fast UP, slow DOWN. Redundancy rises immediately to restore
      // protection the moment the link degrades, but only falls at a bounded rate: a single
      // quiet measurement window must not crash redundancy and trigger the oscillation
      // (rs 1.5->0.5, copies 10->6 then climbing right back) seen in the logs. We shed
      // protection only when the link stays good for a while.
      static constexpr double kRsDecreasePerSec = 0.10;            // rs units/sec downward cap
      static constexpr uint64_t kCopiesDecreaseIntervalNs = 2000000000ULL;  // >=2s per -1 copy

      // Probability-bounded redundancy model (see REDUNDANCY_MODEL.md): estimate the
      // per-shard loss q from this window, then set redundancy to the minimum that holds
      // the per-block stall probability at <= kTargetStallProb, plus a fixed safety margin.
      // Because the redundancy is computed from the CURRENT carrier count, it falls as
      // carriers are added — which is the feedback the old heuristic lacked (it kept
      // redundancy high regardless of n, so carriers grew to the cap).
      static constexpr double kTargetStallProb = 0.0001;   // 0.01%
      static constexpr float  kRedundancyMargin = 0.05f;   // headroom over the formula
      if (qest_total_gaps >= 100) {
        // q is now the per-shard STALL probability (gap > retransmit-scale threshold), not a
        // jitter-vs-budget fraction, so it reflects real loss/overload and does not saturate
        // on base jitter. No 0.5 clamp: a genuinely high stall rate should drive real parity.
        double q = static_cast<double>(qest_late_gaps) / static_cast<double>(qest_total_gaps);
        // Light smoothing so a single noisy window doesn't swing the config.
        est_loss_q = have_loss_q ? (0.5 * est_loss_q + 0.5 * q) : q;
        have_loss_q = true;
        qest_total_gaps = qest_late_gaps = 0;
      }
      // A single redundancy value governs BOTH directions, so size it for the worse one:
      // take the max of our c2s loss estimate and the client's reported s2c loss estimate
      // (both measured the same latency-budget way). This protects a lopsided link.
      bool s2c_fresh = (now_ns_val - s2c_last_received_ns < s2c_stale_ns);
      double q_used = est_loss_q;
      if (s2c_fresh) q_used = std::max(q_used, static_cast<double>(s2c_loss_q));

      const unsigned n_now = static_cast<unsigned>(carriers.size());
      float r_model = carrier_adapt::redundancy_for_stall_bound(n_now, q_used, kTargetStallProb)
                      + kRedundancyMargin;
      // Saturation clamp: when EITHER direction's send window is saturated (deliberately
      // full — the producer out-runs the link), shard lateness is queueing on the shared
      // bottleneck, not independent loss: extra parity only re-shares the same fixed
      // bytes from data onto overhead (observed: rs pinned at 2.0 → k=2-of-8 at n=8,
      // ~4× wire amplification, ~21 KB/s delivered where the bucket allows 256 KB/s).
      // Cap at 0.5; genuine loss then rides the retransmit path.
      const bool send_saturated =
          (unacked_bytes_cache != 0
           && unacked_bytes_cache >= rate_window_cap(s2c_window, get_window_base_rtt_ns()))
          || client_c2s_window_saturated;
      const float rs_hi = send_saturated ? 0.5f : 2.0f;
      float rs_target = std::min(rs_hi, std::max(0.1f, r_model));
      if (rs_target >= runtime_rs_redundancy) {
        runtime_rs_redundancy = rs_target;                 // up: immediate
      } else {                                             // down: bounded rate
        float max_drop = static_cast<float>(kRsDecreasePerSec * (static_cast<double>(adapt_dt) / 1e9));
        runtime_rs_redundancy = std::max(rs_target, runtime_rs_redundancy - max_drop);
      }

      // Small-packet copies are sized for interactive SMOOTHNESS, not the retransmit bound. A
      // small (sub-block, interactive) packet is delivered at the MIN over its copies, so we
      // want at least one copy to land within a TIGHT interactive budget of the fastest carrier
      // — i.e. near the min RTT, not merely "before a retransmit". So we measure q_jitter = the
      // fraction of recent shard/copy arrival gaps that exceed B_interactive (a tight,
      // RTT-relative budget, far below the retransmit-scale stall threshold the RS model uses),
      // and pick the smallest copy count holding P(ALL copies miss the budget) = q_jitter^c <=
      // kInteractiveEps. That eps is much tighter than the RS stall bound because EVERY interactive
      // packet's tail is felt by the user: a per-packet 0.01% still hiccups every few seconds at
      // interactive rates, so we target a far rarer per-packet miss. Small packets are tiny, so
      // the extra copies cost almost no bandwidth. q_jitter draws on BOTH the RS shard gaps and
      // the small-packet copy gaps so it has samples whether traffic is bulk or interactive.
      const uint64_t b_interactive = std::max<uint64_t>(20000000ULL, get_base_rtt_ns() / 8);
      size_t jit_total = 0, jit_late = 0;
      for (uint64_t g : qest_recent_gaps) { jit_total++; if (g > b_interactive) jit_late++; }
      for (uint64_t g : c2s_small_extra_copy_gap_ns) { jit_total++; if (g > b_interactive) jit_late++; }
      double q_jitter = (jit_total >= 30) ? static_cast<double>(jit_late) / static_cast<double>(jit_total)
                                          : q_used;
      // Cap at kMaxSmallCopies: beyond it q_jitter reflects aggregate congestion (all carriers
      // backed up), which copies can't fix and only worsen — see kMaxSmallCopies. This is what
      // stops the runaway to ~carrier-count on a busy link. (The carrier-count cap below still
      // applies when there are fewer than kMaxSmallCopies carriers.)
      unsigned copies = std::min(carrier_adapt::small_copies_for_loss(q_jitter, carrier_adapt::kInteractiveEps),
                                 carrier_adapt::kMaxSmallCopies);
      // Saturation clamp for duplication (the rs-side analog is the 0.5f ceiling above):
      // when a send window is pinned at its cap, the "lateness" the model sees is
      // predominantly queueing at the saturated link — and every wasted copy STEALS
      // wire share from payload at the very moment the link is scarce (measured in the
      // 60 Hz small-packet storm: copies pinned at 8, wire overhead ~6x, app goodput
      // stuck ~8 KB/s at ~22 s interactive lag on a 256 KB/s link).  Under saturation
      // hold duplication at the useful minimum; true loss stalls are still repaired by
      // retransmits and RS parity (which is itself clamped under saturation).
      if (send_saturated) copies = std::min(copies, 3u);
      unsigned copies_target = std::min(std::max(2u, n_now), std::max(2u, copies));
      if (copies_target >= runtime_small_packet_redundancy) {
        runtime_small_packet_redundancy = copies_target;  // up: immediate
      } else if (now_ns_val - last_copies_decrease_ns >= kCopiesDecreaseIntervalNs) {
        runtime_small_packet_redundancy -= 1;              // down: at most one copy per interval
        last_copies_decrease_ns = now_ns_val;
      }
      // Hard cap: a copy needs a distinct carrier, so never exceed the live carrier count
      // (this can force an immediate drop when carriers die — protection, not relaxation).
      runtime_small_packet_redundancy =
          std::min(runtime_small_packet_redundancy, std::max(2u, n_now));
      if (dbg.f) {
        // Shard-gap percentiles (ms) so the latency budget B can be tuned: set B above the
        // "normal" spread (around p50-p90) but below a retransmit-scale delay (the tail).
        uint64_t g50 = 0, g90 = 0, g99 = 0;
        if (!qest_recent_gaps.empty()) {
          std::vector<uint64_t> g(qest_recent_gaps.begin(), qest_recent_gaps.end());
          std::sort(g.begin(), g.end());
          g50 = g[g.size() * 50 / 100];
          g90 = g[g.size() * 90 / 100];
          g99 = g[std::min(g.size() - 1, g.size() * 99 / 100)];
        }
        dbglogf(dbg, "[adapt-model t=%llu q=%.3f q_c2s=%.3f q_s2c=%.3f n=%u r_model=%.2f copies=%u "
                     "stall_ms=%llu q_jit=%.3f int_ms=%llu gap_ms_p50=%.1f p90=%.1f p99=%.1f]\n",
                (unsigned long long)(now_ns_val/1000000ULL), q_used,
                est_loss_q, (double)s2c_loss_q, n_now,
                (double)runtime_rs_redundancy, copies,
                (unsigned long long)(carrier_adapt::stall_threshold_ns(get_base_rtt_ns())/1000000ULL),
                q_jitter, (unsigned long long)(b_interactive/1000000ULL),
                g50/1e6, g90/1e6, g99/1e6);
      }

      if (runtime_rs_redundancy != last_sent_rs_redundancy || runtime_small_packet_redundancy != last_sent_small_packet_redundancy) {
        last_sent_rs_redundancy = runtime_rs_redundancy;
        last_sent_small_packet_redundancy = runtime_small_packet_redundancy;
        if (dbg.f) dbglogf(dbg, "[adapt-config-sent t=%llu rs_red=%.2f small_copies=%u carriers=%zu]\n",
                         (unsigned long long)(now_ns_val/1000000ULL), (double)runtime_rs_redundancy,
                         (unsigned)runtime_small_packet_redundancy, carriers.size());
        queue_server_config_to_carrier(carriers.begin()->first);
      }
    }
    // Report observed link quality (from ACKs received from client) so client can adapt carriers.
    if (!carriers.empty() && !server_recent_rtt_ns.empty() && now_ns_val - last_metrics_ns >= metrics_interval_ns) {
      last_metrics_ns = now_ns_val;
      // Report p90, not the max: a single queue-delayed outlier sample must not poison the
      // client's effective-RTT for the whole window.
      uint64_t p90_rtt = p90_ns(server_recent_rtt_ns);
      // Spread periodic control traffic over the carrier we've sent on least recently
      // (every carrier is an equal TCP connection; concentrating control on one just makes
      // that one more likely to HoL-block on a lost control packet).
      int fd = -1; uint64_t oldest = 0;
      for (auto& [cfd, cs] : carriers) {
        uint64_t age = now_ns_val - cs.last_send_ns;
        if (fd < 0 || age > oldest) { fd = cfd; oldest = age; }
      }
      if (fd >= 0) queue_server_metrics_to_carrier(fd, p90_rtt);
    }

    ensure_backend_connected();
    if (dbg.f && !backend_read_buf.empty() && carriers.empty()) {
      static uint64_t last_stall_log = 0;
      if (now_ns_val - last_stall_log >= 1000000000ULL) {
        last_stall_log = now_ns_val;
        dbglogf(dbg, "[srv-t2c-stall t=%llu] backend_buf=%zu carriers=0 unacked=%zu retransmit=%d\n",
                (unsigned long long)(now_ns_val/1000000ULL),
                backend_read_buf.size(), unacked_data.size(), (int)retransmit_needed);
        dbg_flush(dbg);
      }
    }
    // Refresh the send-window state once per loop pass: outstanding = queued-but-unACKed
    // data; the window caps it (see RateWindow in net_util.h). Reading the backend is wanted
    // only while the window is open AND the pre-encode buffer isn't already holding a full
    // window's worth — otherwise the bytes just queue one buffer earlier.
    {
      uint64_t ob = 0;
      for (const auto& [uid, ui] : unacked_data) ob += ui.wire_cost();
      unacked_bytes_cache = ob;
    }
    // The pre-encode read buffer is only a pipe for the encoder — bound it to a fraction of the
    // window so the s2c pipeline's head is the window itself, not a hidden second queue in front
    // of it (measured: with the buf allowed to grow to the window cap it added ~1.5 s of standing
    // pipeline lag on top of the window).
    backend_read_wanted = rate_window_open(unacked_bytes_cache, s2c_window, get_window_base_rtt_ns()) &&
                          backend_read_buf.size() < static_cast<size_t>(std::max<uint64_t>(
                              rate_window_cap(s2c_window, get_window_base_rtt_ns()) / 4, 64 * 1024));
    arm_backend();  // re-arm/disarm EPOLLIN as the window opened/closed this pass
    if (backend_connected && backend_fd >= 0 && !backend_read_buf.empty() && !carriers.empty()) {
      const size_t block_size = max_packet;
      // Each RS group uses exactly n_carriers shards (one per carrier) so that a slow or
      // dead carrier never prevents decoding. k = floor(n / (1 + rs_redundancy)) data shards
      // per group; the RS guarantee means any k of n shards suffice to reconstruct.
      // Loop so that large buffers produce multiple correctly-sized groups rather than one
      // oversized group that demands too many shards from each carrier.
      // Interactive (small backlog) s2c groups get smoothness-grade parity so a small low-k
      // burst (e.g. a short command's output) is as robust as a duplicated small packet —
      // any k shards within the jitter budget decode it — instead of the bulk
      // parity-as-fraction that would leave a 2-block burst with only 1 parity. We recover the
      // per-carrier jitter q from the copy count (q ≈ eps^(1/copies)). Bulk (heavy unacked
      // backlog) passes 0 → parity-as-fraction (throughput-oriented).
      double s_iq = 0.0;
      if (runtime_auto_adapt &&
          !carrier_adapt::is_heavy_backlog(0, unacked_data.size())) {
        unsigned c = std::max(2u, runtime_small_packet_redundancy);
        s_iq = std::pow(carrier_adapt::kInteractiveEps, 1.0 / static_cast<double>(c));
      }
      // The SEND WINDOW gates only bulk RS groups: encoding stops once outstanding data
      // reaches the ACK-clocked cap, which is what actually bounds the queue a late shard
      // can sit in. The while-loop always allows a first group (window opens when empty),
      // so a single group bigger than the cap can never deadlock the stream.
      while (backend_read_buf.size() >= block_size && !carriers.empty() &&
             rate_window_open(unacked_bytes_cache, s2c_window, get_window_base_rtt_ns())) {
        // One shard per carrier so any k of them suffice to decode (see rs_group_params).
        auto gp = packet_io::rs_group_params(carriers.size(), runtime_rs_redundancy,
                                             backend_read_buf.size() / block_size,
                                             s_iq, carrier_adapt::kInteractiveEps);
        unsigned k = gp.k;
        if (k < 1) break;
        unsigned m = gp.m;
        unsigned n = gp.n;
        if (m == 0) {
          // Single carrier: can't do RS (need m>=1). Send one block as SMALL and continue
          // draining, matching the client-side behaviour. Do NOT break — falling through to
          // the "sub-block remainder" path would send the entire (potentially huge) buffer
          // as one SMALL packet, whose size field can exceed MAX_PACKET_PAYLOAD and cause
          // the receiver to close the connection (READ_BUF_SIZE=65536 > MAX_PACKET_PAYLOAD=16384).
          size_t chunk = block_size;
          {
            UnackedItem ui;
            ui.data.assign(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
            ui.is_small = true;
            ui.send_ns = now_ns();
            unacked_data[next_send_id] = std::move(ui);
          }
          unacked_bytes_cache += chunk;  // single copy: wire cost == payload
          queue_small_to_carriers(backend_read_buf.data(), chunk);
          backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
          continue;
        }
        std::vector<const uint8_t*> data_ptrs(k);
        for (unsigned i = 0; i < k; ++i)
          data_ptrs[i] = backend_read_buf.data() + i * block_size;
        std::vector<std::vector<uint8_t>> parity(m, std::vector<uint8_t>(block_size));
        std::vector<uint8_t*> parity_ptrs(m);
        for (unsigned i = 0; i < m; ++i) parity_ptrs[i] = parity[i].data();
        reed_solomon::encode(k, m, data_ptrs.data(), parity_ptrs.data(), block_size);
        std::vector<int> carrier_fds;
        for (auto& [fd, _] : carriers) carrier_fds.push_back(fd);
        std::vector<uint64_t> shard_carriers(n);
        for (size_t i = 0; i < n; ++i) {
          int fd = carrier_fds[(next_rr + i) % carrier_fds.size()];
          auto itc = carriers.find(fd);
          if (itc == carriers.end()) continue;
          shard_carriers[i] = itc->second.carrier_id;
          const uint8_t* shard = (i < k) ? (backend_read_buf.data() + i * block_size) : parity[i - k].data();
          queue_rs_shard_to_carrier(fd, n, k, static_cast<uint16_t>(block_size), static_cast<unsigned>(i), shard);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
        }
        if (!carrier_fds.empty())
          next_rr = (next_rr + static_cast<unsigned>(n)) % static_cast<unsigned>(carrier_fds.size());
        ack_send_time_ns[next_send_id] = now_ns();
        {
          UnackedItem ui;
          ui.data.assign(backend_read_buf.begin(), backend_read_buf.begin() + k * block_size);
          ui.n = n;  ui.k = static_cast<unsigned>(k);
          ui.block_size = static_cast<uint16_t>(block_size);
          ui.is_small = false;
          ui.wire_bytes = static_cast<uint64_t>(n) * block_size;  // wire cost: all n shards
          ui.send_ns = now_ns();
          for (unsigned si = 0; si < n; ++si) {
            ui.rs_shard_sent_on[si].insert(shard_carriers[si]);
          }
          unacked_data[next_send_id] = std::move(ui);
        }
        next_send_id++;
        unacked_bytes_cache += static_cast<uint64_t>(n) * block_size;  // wire cost
        backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + k * block_size);
      }
      // Any sub-block remainder: send as SMALL (no RS needed for < block_size).
      // The RS loop above exits only when backend_read_buf.size() < block_size (natural
      // exit) or carriers.empty() (early exit). The explicit size check matches the
      // equivalent guard on the client side and prevents a too-large SMALL packet if
      // somehow a full block remains (e.g. future code change removes the m==0 continue).
      // Hold the remainder up to --max-delay so it can coalesce into a full RS block first.
      // SMALL sends count at WIRE cost in the window (payload x copies — otherwise a
      // duplicated small-packet producer (interactive redraw storm) grows carrier queues
      // ~copies-fold past the cap; measured ~15x overhead, multi-MB queue per minute).
      if (!backend_read_buf.empty() && backend_read_buf.size() < block_size && !carriers.empty()) {
        if (backend_partial_since_ns == 0) backend_partial_since_ns = now_ns();
        const bool small_gate_closed = !rate_window_open(
            unacked_bytes_cache + backend_read_buf.size() * runtime_small_packet_redundancy,
            s2c_window, get_window_base_rtt_ns());
        if ((runtime_max_delay_ns == 0 || now_ns() - backend_partial_since_ns >= runtime_max_delay_ns)
            && !small_gate_closed) {
          size_t chunk = backend_read_buf.size();
          const unsigned copies = std::max(1u, std::min(runtime_small_packet_redundancy,
                                                        static_cast<unsigned>(carriers.size())));
          { UnackedItem ui; ui.data.assign(backend_read_buf.begin(), backend_read_buf.end());
            ui.is_small = true; ui.wire_bytes = static_cast<uint64_t>(chunk) * copies;
            ui.send_ns = now_ns(); unacked_data[next_send_id] = std::move(ui); }
          unacked_bytes_cache += static_cast<uint64_t>(chunk) * copies;  // wire cost
          queue_small_to_carriers(backend_read_buf.data(), chunk);
          backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
          backend_partial_since_ns = 0;
        }
      } else {
        backend_partial_since_ns = 0;
      }
    }
    flush_backend_pending();
    flush_pending_ack();  // belt-and-suspenders: emit the coalesced ACK even if a backend
                          // early-return above skipped flush_backend_pending's own flush
    flush_carrier_writes();
    // If the backend write failed and was closed, stop running — there's nowhere to
    // deliver client data and no way to send sshd's responses to the client.
    if (backend_fd < 0 && backend_connected == false && !backend_pending.empty()) {
      if (dbg.f) dbglogf(dbg, "[backend-closed-with-pending t=%llu pending=%zu]\n",
                       (unsigned long long)(now_ns()/1000000ULL), backend_pending.size());
      running = false;
    }
    if (dbg.f) {
      static uint64_t loop_count = 0;
      static uint64_t last_log_ns = 0;
      loop_count++;
      uint64_t t = now_ns();
      if (t - last_log_ns >= 5000000000ULL) {
        last_log_ns = t;
        dbglogf(dbg, "[loop-count t=%llu loops=%llu carriers=%zu]\n",
                (unsigned long long)(t/1000000ULL), (unsigned long long)loop_count, carriers.size());
        dbg_flush(dbg);
      }
    }
  }

  if (dbg.f) {
    dbglogf(dbg, "[server-exit t=%llu carriers=%zu unacked=%zu next_send_id=%llu backend_fd=%d connected=%d]\n",
            (unsigned long long)(now_ns()/1000000ULL),
            carriers.size(), unacked_data.size(), (unsigned long long)next_send_id,
            backend_fd, (int)backend_connected);
    dbg_flush(dbg);
    fclose(dbg.f);
  }
  for (auto& [fd, _] : carriers)
    close(fd);
  if (backend_fd >= 0) close(backend_fd);
  close(listen_fd);
  unlink(socket_path.c_str());
  close(epfd);
  return 0;
}

}  // namespace ssholl
