#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
#include "carrier_adapt.h"
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
  FILE* dbg = nullptr;
  if (args.debug) {
    char dbg_path[128];
    snprintf(dbg_path, sizeof dbg_path, "/tmp/ssh-oll-server-%d.log", (int)getpid());
    dbg = fopen(dbg_path, "w");
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
  float runtime_rs_redundancy = args.config.rs_redundancy;
  unsigned runtime_small_packet_redundancy = args.config.small_packet_redundancy;
  bool runtime_auto_adapt = false;  // set from SET_CONFIG; when true, server adapts and sends SERVER_CONFIG
  float last_sent_rs_redundancy = -1.0f;
  unsigned last_sent_small_packet_redundancy = 0;
  uint64_t last_adapt_ns = 0;
  const uint64_t adapt_interval_ns = 300 * 1000000ULL;
  unsigned next_carrier_for_rs = 0;


  // Server-side link monitoring: record when we send each id; when client sends ACK, measure RTT.
  auto now_ns = []() {
    return static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  };
  std::map<uint64_t, uint64_t> ack_send_time_ns;  // id -> when we sent it (for server→client RTT)
  std::deque<uint64_t> server_recent_rtt_ns;
  const size_t max_server_recent_rtt = 50;
  const uint64_t metrics_interval_ns = 400 * 1000000ULL;  // 400ms
  uint64_t last_metrics_ns = 0;
  // Rolling shard spread samples for the client→server direction.
  std::deque<uint64_t> c2s_shard_spread_ns;
  // gap_final: time between (k-1)-th and k-th shard per group (how close to the edge).
  std::deque<uint64_t> c2s_gap_final_ns;
  // extra_shard_gap: time from k-th shard to (k+1)-th shard (how much headroom we have).
  std::deque<uint64_t> c2s_extra_shard_gap_ns;
  std::deque<uint64_t> c2s_small_extra_copy_gap_ns;  // copy 1->2 gap for small packets (c2s)
  static constexpr size_t kMaxSpreadSamples = 100;
  // s2c metrics from CLIENT_METRICS (client measures server→client path).
  float s2c_fraction_struggling = 0.0f;
  bool s2c_can_decrease_rs = false;
  bool s2c_can_decrease_small = false;
  uint64_t s2c_last_received_ns = 0;
  // Shared map for tracking when RS groups decoded so extra shards can be timed.
  std::map<uint64_t, uint64_t> recently_decoded_ns;
  std::map<uint64_t, std::vector<uint64_t>> small_copy_arrival_times;

  // Unacked retransmit buffer: holds original bytes for each outstanding send_id
  // so we can re-encode and resend on a new carrier when all existing ones die.
  struct UnackedItem {
    std::vector<uint8_t> data;
    unsigned n = 0;
    unsigned k = 0;
    uint16_t block_size = 0;
    bool is_small = false;
    uint64_t send_ns = 0;
  };
  std::map<uint64_t, UnackedItem> unacked_data;
  bool retransmit_needed = false;  // set when last carrier dies with unacked data

  uint64_t last_ping_check_ns       = 0;
  uint64_t last_keepalive_check_ns  = 0;
  uint64_t last_rs_drain_ns                = 0;
  uint64_t next_deliver_id_stuck_since_ns  = 0;
  uint64_t last_retransmit_check_ns = 0;
  uint64_t last_global_recv_ns      = now_ns();  // last time any data arrived from any carrier
  uint64_t last_suggest_close_ns = 0;  // rate-limit SUGGEST_CLOSE to at most 1 per 10s
  static constexpr uint64_t suggest_close_min_interval_ns = 10 * 1000000000ULL;

  // RTT-scaled timeouts: server observes server→client RTT from ACKs. Use 5 s default when unknown.
  auto get_effective_rtt_ns = [&]() -> uint64_t {
    if (server_recent_rtt_ns.size() >= 3) {
      std::vector<uint64_t> sorted(server_recent_rtt_ns.begin(), server_recent_rtt_ns.end());
      std::sort(sorted.begin(), sorted.end());
      return sorted[static_cast<size_t>(sorted.size() * 0.9)];
    }
    return 5000000000ULL;  // 5 s conservative when unknown
  };
  auto scaled_ns = [&](unsigned mult, uint64_t min_ns, uint64_t max_ns) -> uint64_t {
    uint64_t rtt = get_effective_rtt_ns();
    uint64_t v = static_cast<uint64_t>(mult) * rtt;
    if (v < min_ns) return min_ns;
    if (v > max_ns) return max_ns;
    return v;
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
      int one = 1;
      setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      ev.events = EPOLLIN;  // EPOLLOUT only when we have backend_pending data to write
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
    } else if (err != EINPROGRESS && err != 0) {
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

  // Send small chunk (< block_size) to the fastest n_copies carriers (by last_rtt_ns).
  // Preferring low-RTT carriers minimises latency: unlike RS packets there is no erasure
  // coding fallback, so every copy counts and we want the quickest ones.
  // Carriers with no RTT sample yet (last_rtt_ns == 0) sort last (unknown, not fast).
  auto queue_small_to_carriers = [&](const uint8_t* data, size_t len) {
    if (len == 0 || carriers.empty()) return;
    ack_send_time_ns[next_send_id] = now_ns();
    const unsigned n_copies = std::max(1u, std::min(runtime_small_packet_redundancy,
                                                     static_cast<unsigned>(carriers.size())));
    // Sort carriers by RTT ascending; treat 0 (no sample) as slowest.
    std::vector<std::pair<uint64_t, int>> by_rtt;
    by_rtt.reserve(carriers.size());
    for (auto& [fd, cs] : carriers)
      by_rtt.push_back({cs.last_rtt_ns == 0 ? UINT64_MAX : cs.last_rtt_ns, fd});
    std::sort(by_rtt.begin(), by_rtt.end());
    for (unsigned i = 0; i < n_copies; ++i) {
      int fd = by_rtt[i].second;
      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        packet_io::append_small(it->second.write_buf, next_send_id, data, len);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
      }
    }
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
        if (dbg) fprintf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=%s]\n",
                         (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1, reason);
      });
    if (carriers.empty() && !unacked_data.empty())
      retransmit_needed = true;
    // If survivors remain after a write-error removal, force the retransmit check
    // to run on the next iteration so we retransmit onto survivors immediately.
    if (any_removed && !carriers.empty() && !unacked_data.empty())
      last_retransmit_check_ns = 0;
  };

  auto queue_ack_to_carrier = [&](int fd, uint64_t acked_id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_ack(it->second.write_buf, acked_id);
  };

  auto queue_server_metrics_to_carrier = [&](int fd, uint64_t max_rtt_ns) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    auto deque_avg = [](const std::deque<uint64_t>& d) -> uint64_t {
      if (d.empty()) return 0;
      uint64_t sum = 0; for (uint64_t v : d) sum += v;
      return sum / d.size();
    };
    packet_io::append_server_metrics(it->second.write_buf, max_rtt_ns,
                                     deque_avg(c2s_shard_spread_ns),
                                     deque_avg(c2s_extra_shard_gap_ns),
                                     static_cast<uint32_t>(rs_pending.size()));
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

  // Delivered data is queued here; we write to backend and ACK when a chunk is fully written.
  // completing_fd is the carrier that triggered delivery — ACK goes back there for per-carrier RTT measurement.
  struct BackendItem { uint64_t id; std::vector<uint8_t> data; int completing_fd; };
  std::deque<BackendItem> backend_pending;

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
          if (dbg) fprintf(dbg, "[backend-write-err t=%llu errno=%d]\n",
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
      uint64_t acked_id = front.id;
      int cfd = front.completing_fd;
      backend_pending.pop_front();
      // ACK on the completing carrier: gives the client accurate per-carrier RTT with no extra packets.
      // Fall back to any available carrier if completing_fd was already closed.
      if (!carriers.empty()) {
        if (!carriers.count(cfd)) cfd = carriers.begin()->first;
        queue_ack_to_carrier(cfd, acked_id);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = cfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
      }
    }
    if (backend_fd >= 0 && backend_pending.empty()) {
      ev.events = EPOLLIN;
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
    }
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
  recv_cb.on_rs_extra_shard = [&](uint64_t gap_ns) {
    c2s_extra_shard_gap_ns.push_back(gap_ns);
    while (c2s_extra_shard_gap_ns.size() > kMaxSpreadSamples) c2s_extra_shard_gap_ns.pop_front();
  };
  recv_cb.on_small_extra_copy = [&](uint64_t gap_ns) {
    c2s_small_extra_copy_gap_ns.push_back(gap_ns);
    while (c2s_small_extra_copy_gap_ns.size() > kMaxSpreadSamples) c2s_small_extra_copy_gap_ns.pop_front();
  };
  recv_cb.on_ping = [&](int fd, uint64_t id, size_t payload_size) { send_pong(fd, id, payload_size); };
  recv_cb.on_ack = [&](int fd, uint64_t acked_id) {
    auto it = ack_send_time_ns.find(acked_id);
    if (it != ack_send_time_ns.end()) {
      uint64_t rtt = now_ns() - it->second;
      // Sanity check: discard clearly-bogus values (> 60s); wrap-around produces ~1.8e19 ns.
      if (rtt < 60000000000ULL) {
        server_recent_rtt_ns.push_back(rtt);
        while (server_recent_rtt_ns.size() > max_server_recent_rtt) server_recent_rtt_ns.pop_front();
        auto cs = carriers.find(fd);
        if (cs != carriers.end()) cs->second.last_rtt_ns = rtt;
      }
    }
    for (auto it_m = ack_send_time_ns.begin(); it_m != ack_send_time_ns.end(); )
      if (it_m->first <= acked_id) it_m = ack_send_time_ns.erase(it_m);
      else ++it_m;
    // Data confirmed received: remove from retransmit buffer.
    for (auto it_u = unacked_data.begin(); it_u != unacked_data.end() && it_u->first <= acked_id; )
      it_u = unacked_data.erase(it_u);
  };
  recv_cb.on_client_metrics = [&](uint64_t avg_shard_spread_ns, uint64_t avg_extra_shard_gap_ns,
                                  float fraction_struggling, uint32_t rs_pending_count,
                                  bool can_decrease_rs, bool can_decrease_small) {
    (void)avg_shard_spread_ns;
    (void)avg_extra_shard_gap_ns;
    (void)rs_pending_count;
    s2c_fraction_struggling = fraction_struggling;
    s2c_can_decrease_rs = can_decrease_rs;
    s2c_can_decrease_small = can_decrease_small;
    s2c_last_received_ns = now_ns();
  };
  recv_cb.on_set_config = [&](const PacketConfig& pc) {
    runtime_auto_adapt = (pc.auto_adapt != 0);
    max_packet = std::min(static_cast<size_t>(pc.packet_size), MAX_PACKET_PAYLOAD);
    if (max_packet == 0) max_packet = 800;
    runtime_small_packet_redundancy = pc.small_packet_redundancy;
    if (runtime_small_packet_redundancy == 0) runtime_small_packet_redundancy = 1;
    runtime_small_packet_redundancy = std::min(runtime_small_packet_redundancy, std::max(1u, static_cast<unsigned>(carriers.size())));
    runtime_rs_redundancy = pc.reed_solomon_redundancy;
    if (runtime_rs_redundancy < 0.1f) runtime_rs_redundancy = 0.1f;
    // When auto_adapt, send current config so client has initial sync; server will send again when it adapts.
    if (runtime_auto_adapt && !carriers.empty()) {
      last_sent_rs_redundancy = runtime_rs_redundancy;
      last_sent_small_packet_redundancy = runtime_small_packet_redundancy;
      queue_server_config_to_carrier(carriers.begin()->first);
    }
  };

  auto process_carrier_read = [&](int fd, CarrierState& s) {
    uint8_t buf[READ_BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n <= 0) {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        return false;
      return true;
    }
    s.read_buf.insert(s.read_buf.end(), buf, buf + n);
    return packet_io::process_carrier_read(fd, s, reassembly, rs_pending, recently_decoded_ns, small_copy_arrival_times, next_deliver_id, recv_cb);
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    // 500ms bound ensures retransmit/ping checks run promptly even when carriers are idle.
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), 500);
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
            carriers[client].connect_ns = now_ns();
            if (dbg) { fprintf(dbg, "[carrier-open t=%llu fd=%d total=%zu]\n",
                               (unsigned long long)(now_ns()/1000000ULL), client, carriers.size());
                        fflush(dbg); }
            // Send READY so client knows the link is up before it sends data.
            packet_io::append_ready(carriers[client].write_buf);
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
              for (auto& [uid, ui] : unacked_data) {
                if (ui.is_small) {
                  packet_io::append_small(cs.write_buf, uid, ui.data.data(), ui.data.size());
                } else {
                  std::vector<const uint8_t*> dptrs(ui.k);
                  for (unsigned si = 0; si < ui.k; ++si)
                    dptrs[si] = ui.data.data() + si * ui.block_size;
                  unsigned m = ui.n - ui.k;
                  std::vector<std::vector<uint8_t>> par;
                  std::vector<uint8_t*> pptrs;
                  if (m > 0) {
                    par.resize(m, std::vector<uint8_t>(ui.block_size));
                    pptrs.resize(m);
                    for (unsigned si = 0; si < m; ++si) pptrs[si] = par[si].data();
                    reed_solomon::encode(ui.k, m, dptrs.data(), pptrs.data(), ui.block_size);
                  }
                  for (unsigned si = 0; si < ui.n; ++si) {
                    const uint8_t* shard = (si < ui.k)
                        ? (ui.data.data() + si * ui.block_size)
                        : par[si - ui.k].data();
                    packet_io::append_rs_shard(cs.write_buf, uid, ui.n, ui.k, ui.block_size, si, shard);
                  }
                }
                // Reset timer so the periodic 3 s retransmit doesn't immediately
                // fire a redundant duplicate of what we just queued.
                ui.send_ns = retransmit_now;
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
        if (e & EPOLLIN) {
          uint8_t buf[READ_BUF_SIZE];
          ssize_t nr = read(backend_fd, buf, sizeof buf);
          if (nr <= 0) {
            if (nr == 0) {
              running = false;
              if (dbg) fprintf(dbg, "[backend-eof t=%llu]\n", (unsigned long long)(now_ns()/1000000ULL));
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
              if (dbg) fprintf(dbg, "[backend-read-err t=%llu errno=%d]\n",
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
          if (dbg) fprintf(dbg, "[backend-err t=%llu]\n", (unsigned long long)(now_ns()/1000000ULL));
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
            if (dbg) fprintf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=read_error]\n",
                             (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1);
            close(fd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            carriers.erase(it);
            if (carriers.empty() && !unacked_data.empty())
              retransmit_needed = true;
            if (!carriers.empty() && !unacked_data.empty())
              last_retransmit_check_ns = 0;
            carrier_removed = true;
          }
        }
        if (!carrier_removed && (e & (EPOLLERR | EPOLLHUP))) {
          if (dbg) fprintf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=epoll_err_hup]\n",
                           (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1);
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
          if (carriers.empty() && !unacked_data.empty())
            retransmit_needed = true;
          if (!carriers.empty() && !unacked_data.empty())
            last_retransmit_check_ns = 0;
        }
      }
    }

    const uint64_t now_ns_val = now_ns();

    // ── Debug: periodic state dump (mirrors client format) ────────────────────
    if (dbg) {
      static uint64_t last_dbg_ns = 0;
      if (now_ns_val - last_dbg_ns >= 1000000000ULL) {
        last_dbg_ns = now_ns_val;
        size_t unacked_bytes = 0;
        for (const auto& [_, ui] : unacked_data) unacked_bytes += ui.data.size();
        if (rs_pending.empty()) {
          fprintf(dbg, "[srv] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=0 next_deliver_id=%llu backend_buf=%zu rs_redundancy=%.2f small_packet_copies=%u\n",
                  carriers.size(), unacked_data.size(), unacked_bytes, reassembly.size(),
                  (unsigned long long)next_deliver_id, backend_read_buf.size(),
                  (double)runtime_rs_redundancy, (unsigned)runtime_small_packet_redundancy);
        } else {
          auto it = rs_pending.begin();
          fprintf(dbg, "[srv] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=%zu next_deliver_id=%llu backend_buf=%zu rs_redundancy=%.2f small_packet_copies=%u first_rs_id=%llu shards=%zu k=%u n=%u\n",
                  carriers.size(), unacked_data.size(), unacked_bytes, reassembly.size(), rs_pending.size(),
                  (unsigned long long)next_deliver_id, backend_read_buf.size(),
                  (double)runtime_rs_redundancy, (unsigned)runtime_small_packet_redundancy,
                  (unsigned long long)it->first, it->second.shards.size(), it->second.k, it->second.n);
        }
        fflush(dbg);
      }
    }

    // ── Ping / inactivity-check / carrier quality (suggest close) ───────────
    if (now_ns_val - last_ping_check_ns >= 1000000000ULL) {
      last_ping_check_ns = now_ns_val;
      uint64_t ping_idle_ns = scaled_ns(2, 5000000000ULL, 30000000000ULL);

      std::vector<carrier_adapt::CarrierInfo> carrier_infos;
      for (auto& [cfd, cs] : carriers) {
        carrier_infos.push_back({cfd, cs.last_rtt_ns, cs.last_recv_ns, cs.connect_ns, cs.last_send_ns});
      }
      auto quality = carrier_adapt::assess_carriers(carrier_infos, now_ns_val, scaled_ns);

      // Send PING to idle carriers; dead ones get SUGGEST_CLOSE (skip PING).
      for (auto& [cfd, cs] : carriers) {
        bool is_dead = std::find(quality.dead_idle_fds.begin(), quality.dead_idle_fds.end(), cfd)
            != quality.dead_idle_fds.end();
        if (is_dead) continue;
        if (cs.write_buf.empty()
            && now_ns_val - cs.last_send_ns > ping_idle_ns
            && now_ns_val - cs.last_recv_ns > ping_idle_ns) {
          packet_io::append_ping(cs.write_buf, 0);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = cfd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
        }
      }

      // --min-data-per-minute: send keepalive data every few seconds so links stay active.
      const unsigned min_bpm = args.config.min_data_per_minute;
      if (min_bpm > 0 && now_ns_val - last_keepalive_check_ns >= 4000000000ULL) {
        last_keepalive_check_ns = now_ns_val;
        const uint64_t minute_ns = 60 * 1000000000ULL;
        size_t pkt_max = std::min(max_packet, static_cast<size_t>(MAX_PACKET_PAYLOAD));
        for (auto& [cfd, cs] : carriers) {
          if (now_ns_val - cs.last_minute_reset_ns >= minute_ns) {
            cs.bytes_sent_this_minute = 0;
            cs.last_minute_reset_ns = now_ns_val;
          }
          if (cs.bytes_sent_this_minute < min_bpm && cs.write_buf.empty()) {
            std::uniform_int_distribution<size_t> len_dist(50, std::max(size_t(50), pkt_max));
            size_t len = len_dist(keepalive_gen);
            std::vector<uint8_t> payload(len);
            std::uniform_int_distribution<int> byte_dist(0, 255);
            for (size_t i = 0; i < len; ++i) payload[i] = static_cast<uint8_t>(byte_dist(keepalive_gen));
            packet_io::append_ping(cs.write_buf, 0, payload.data(), len);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
        }
      }

      // SUGGEST_CLOSE: server cannot close; client performs actual close. Rate-limit 1 per 10s.
      for (int cfd : quality.dead_idle_fds) {
        if (now_ns_val - last_suggest_close_ns < suggest_close_min_interval_ns) break;
        last_suggest_close_ns = now_ns_val;
        packet_io::append_suggest_close(carriers[cfd].write_buf);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = cfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
        if (dbg) fprintf(dbg, "[suggest-close t=%llu fd=%d reason=dead_idle]\n",
                         (unsigned long long)(now_ns_val/1000000ULL), cfd);
      }
      if (quality.rtt_outlier_fd >= 0
          && now_ns_val - last_suggest_close_ns >= suggest_close_min_interval_ns) {
        last_suggest_close_ns = now_ns_val;
        packet_io::append_suggest_close(carriers[quality.rtt_outlier_fd].write_buf);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = quality.rtt_outlier_fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, quality.rtt_outlier_fd, &ev);
        if (dbg) fprintf(dbg, "[suggest-close t=%llu fd=%d reason=rtt_outlier]\n",
                         (unsigned long long)(now_ns_val/1000000ULL), quality.rtt_outlier_fd);
      }

      // Update global receive timestamp from all live carriers.
      for (auto& [cfd, cs] : carriers)
        if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

      // Global idle timeout: if nothing from any carrier for 12×RTT the client is gone.
      uint64_t global_idle_ns = scaled_ns(12, 60000000000ULL, 300000000000ULL);
      if (now_ns_val - last_global_recv_ns > global_idle_ns) {
        if (dbg) fprintf(dbg, "[global-idle-timeout t=%llu]\n", (unsigned long long)(now_ns_val/1000000ULL));
        running = false;
      }
    }

    // Timeout-based retransmit: re-send any group unACK'd for 4×RTT (or 2.5 s when no RTT) to carriers.
    if (!unacked_data.empty() && !carriers.empty()
        && now_ns_val - last_retransmit_check_ns >= 500000000ULL) {
      last_retransmit_check_ns = now_ns_val;
      // 4×RTT, floored at 500 ms. Mirrors the client change: the old 2 s floor caused
      // multi-second stalls after carrier death on low-latency test links.
      uint64_t retransmit_timeout_ns = (server_recent_rtt_ns.size() >= 2)
          ? scaled_ns(4, 500000000ULL, 60000000000ULL)
          : 2500000000ULL;  // 2.5 s when no RTT known yet (cold start)
      std::vector<int> rt_carriers;
      for (auto& [cfd, cs] : carriers)
        if (!cs.connecting) rt_carriers.push_back(cfd);
      if (!rt_carriers.empty()) {
        unsigned rt_idx = 0;
        const unsigned small_rt_copies = std::max(1u, std::min(3u, static_cast<unsigned>(rt_carriers.size())));
        for (auto& [uid, ui] : unacked_data) {
          if (ui.send_ns == 0 || now_ns_val - ui.send_ns < retransmit_timeout_ns) continue;
          if (ui.is_small) {
            for (unsigned c = 0; c < small_rt_copies; ++c) {
              int cfd = rt_carriers[(rt_idx + c) % rt_carriers.size()];
              packet_io::append_small(carriers[cfd].write_buf, uid, ui.data.data(), ui.data.size());
              ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
            }
            rt_idx += small_rt_copies;
          } else {
            std::vector<const uint8_t*> dptrs(ui.k);
            for (unsigned si = 0; si < ui.k; ++si) dptrs[si] = ui.data.data() + si * ui.block_size;
            unsigned rm = ui.n - ui.k;
            std::vector<std::vector<uint8_t>> rpar;
            std::vector<uint8_t*> rpptrs;
            if (rm > 0) {
              rpar.resize(rm, std::vector<uint8_t>(ui.block_size));
              rpptrs.resize(rm);
              for (unsigned si = 0; si < rm; ++si) rpptrs[si] = rpar[si].data();
              reed_solomon::encode(ui.k, rm, dptrs.data(), rpptrs.data(), ui.block_size);
            }
            std::set<int> touched;
            for (unsigned si = 0; si < ui.n; ++si) {
              int cfd = rt_carriers[(rt_idx + si) % rt_carriers.size()];
              const uint8_t* shard = (si < ui.k)
                  ? (ui.data.data() + si * ui.block_size) : rpar[si - ui.k].data();
              packet_io::append_rs_shard(carriers[cfd].write_buf, uid,
                                         ui.n, ui.k, ui.block_size, si, shard);
              touched.insert(cfd);
            }
            for (int cfd : touched) {
              ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
            }
            rt_idx += ui.n;
          }
          ui.send_ns = now_ns_val;  // throttle: don't retransmit again for 3 s
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
        if (it->second.first_recv_ns > 0 && now_ns_val - it->second.first_recv_ns > rs_stale_ns)
          it = rs_pending.erase(it);
        else
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
          if (next_deliver_id_stuck_since_ns == 0)
            next_deliver_id_stuck_since_ns = now_ns_val;
          break;
        }
      }
    }

    // When auto_adapt, server manages its own redundancy and informs the client.
    if (runtime_auto_adapt && !carriers.empty() && now_ns_val - last_adapt_ns >= adapt_interval_ns
        && c2s_shard_spread_ns.size() >= carrier_adapt::kMinSamplesForAdapt) {
      last_adapt_ns = now_ns_val;
      const uint64_t s2c_stale_ns = 2 * metrics_interval_ns;

      auto c2s = carrier_adapt::compute_from_deques(c2s_shard_spread_ns, c2s_gap_final_ns,
                                                    c2s_extra_shard_gap_ns, c2s_small_extra_copy_gap_ns);
      carrier_adapt::PathMetrics s2c;
      s2c.fraction_struggling = s2c_fraction_struggling;
      s2c.can_decrease_rs = s2c_can_decrease_rs;
      s2c.can_decrease_small = s2c_can_decrease_small;
      bool s2c_fresh = (now_ns_val - s2c_last_received_ns < s2c_stale_ns);
      auto merged = carrier_adapt::merge(c2s, s2c, s2c_fresh);

      auto res = carrier_adapt::run_adapt(merged, runtime_rs_redundancy,
                                          runtime_small_packet_redundancy,
                                          static_cast<unsigned>(carriers.size()));
      runtime_rs_redundancy = res.rs_redundancy;
      runtime_small_packet_redundancy = res.small_packet_redundancy;
      if (res.clear_spread) {
        c2s_shard_spread_ns.clear();
        c2s_gap_final_ns.clear();
      }

      if (runtime_rs_redundancy != last_sent_rs_redundancy || runtime_small_packet_redundancy != last_sent_small_packet_redundancy) {
        last_sent_rs_redundancy = runtime_rs_redundancy;
        last_sent_small_packet_redundancy = runtime_small_packet_redundancy;
        queue_server_config_to_carrier(carriers.begin()->first);
      }
    }
    // Report observed link quality (from ACKs received from client) so client can adapt carriers.
    if (!carriers.empty() && !server_recent_rtt_ns.empty() && now_ns_val - last_metrics_ns >= metrics_interval_ns) {
      last_metrics_ns = now_ns_val;
      uint64_t max_rtt = 0;
      for (uint64_t r : server_recent_rtt_ns) if (r > max_rtt) max_rtt = r;
      int fd = carriers.begin()->first;
      queue_server_metrics_to_carrier(fd, max_rtt);
    }

    ensure_backend_connected();
    if (dbg && !backend_read_buf.empty() && carriers.empty()) {
      static uint64_t last_stall_log = 0;
      if (now_ns_val - last_stall_log >= 1000000000ULL) {
        last_stall_log = now_ns_val;
        fprintf(dbg, "[srv-t2c-stall t=%llu] backend_buf=%zu carriers=0 unacked=%zu retransmit=%d\n",
                (unsigned long long)(now_ns_val/1000000ULL),
                backend_read_buf.size(), unacked_data.size(), (int)retransmit_needed);
        fflush(dbg);
      }
    }
    if (backend_connected && backend_fd >= 0 && !backend_read_buf.empty() && !carriers.empty()) {
      const size_t block_size = max_packet;
      // Each RS group uses exactly n_carriers shards (one per carrier) so that a slow or
      // dead carrier never prevents decoding. k = floor(n / (1 + rs_redundancy)) data shards
      // per group; the RS guarantee means any k of n shards suffice to reconstruct.
      // Loop so that large buffers produce multiple correctly-sized groups rather than one
      // oversized group that demands too many shards from each carrier.
      while (backend_read_buf.size() >= block_size && !carriers.empty()) {
        unsigned n_carriers = static_cast<unsigned>(std::min(carriers.size(), static_cast<size_t>(255)));
        // k = floor(n / (1 + rs_frac)): the max data shards that still leave room for parity
        // within the n_carriers budget.
        unsigned k = std::max(1u, static_cast<unsigned>(
            static_cast<float>(n_carriers) / (1.0f + runtime_rs_redundancy)));
        // Cap by how many full blocks are actually in the buffer.
        k = static_cast<unsigned>(std::min(static_cast<size_t>(k),
                                           backend_read_buf.size() / block_size));
        if (k < 1) break;
        unsigned m = std::max(1u, static_cast<unsigned>(k * runtime_rs_redundancy + 0.5f));
        // n must not exceed n_carriers so every shard lands on a different carrier.
        unsigned n = std::min(k + m, n_carriers);
        m = n - k;
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
        for (size_t i = 0; i < n; ++i) {
          int fd = carrier_fds[(next_carrier_for_rs + i) % carrier_fds.size()];
          const uint8_t* shard = (i < k) ? (backend_read_buf.data() + i * block_size) : parity[i - k].data();
          queue_rs_shard_to_carrier(fd, n, k, static_cast<uint16_t>(block_size), static_cast<unsigned>(i), shard);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
        }
        next_carrier_for_rs += n;
        ack_send_time_ns[next_send_id] = now_ns();
        {
          UnackedItem ui;
          ui.data.assign(backend_read_buf.begin(), backend_read_buf.begin() + k * block_size);
          ui.n = n;  ui.k = static_cast<unsigned>(k);
          ui.block_size = static_cast<uint16_t>(block_size);
          ui.is_small = false;
          ui.send_ns = now_ns();
          unacked_data[next_send_id] = std::move(ui);
        }
        next_send_id++;
        backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + k * block_size);
      }
      // Any sub-block remainder: send as SMALL (no RS needed for < block_size).
      // The RS loop above exits only when backend_read_buf.size() < block_size (natural
      // exit) or carriers.empty() (early exit). The explicit size check matches the
      // equivalent guard on the client side and prevents a too-large SMALL packet if
      // somehow a full block remains (e.g. future code change removes the m==0 continue).
      if (!backend_read_buf.empty() && backend_read_buf.size() < block_size && !carriers.empty()) {
        size_t chunk = backend_read_buf.size();
        { UnackedItem ui; ui.data.assign(backend_read_buf.begin(), backend_read_buf.end());
          ui.is_small = true; ui.send_ns = now_ns(); unacked_data[next_send_id] = std::move(ui); }
        queue_small_to_carriers(backend_read_buf.data(), chunk);
        backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
      }
    }
    flush_backend_pending();
    flush_carrier_writes();
    // If the backend write failed and was closed, stop running — there's nowhere to
    // deliver client data and no way to send sshd's responses to the client.
    if (backend_fd < 0 && backend_connected == false && !backend_pending.empty()) {
      if (dbg) fprintf(dbg, "[backend-closed-with-pending t=%llu pending=%zu]\n",
                       (unsigned long long)(now_ns()/1000000ULL), backend_pending.size());
      running = false;
    }
    if (dbg) {
      static uint64_t loop_count = 0;
      static uint64_t last_log_ns = 0;
      loop_count++;
      uint64_t t = now_ns();
      if (t - last_log_ns >= 5000000000ULL) {
        last_log_ns = t;
        fprintf(dbg, "[loop-count t=%llu loops=%llu carriers=%zu]\n",
                (unsigned long long)(t/1000000ULL), (unsigned long long)loop_count, carriers.size());
        fflush(dbg);
      }
    }
  }

  if (dbg) {
    fprintf(dbg, "[server-exit t=%llu carriers=%zu unacked=%zu next_send_id=%llu backend_fd=%d connected=%d]\n",
            (unsigned long long)(now_ns()/1000000ULL),
            carriers.size(), unacked_data.size(), (unsigned long long)next_send_id,
            backend_fd, (int)backend_connected);
    fflush(dbg);
    fclose(dbg);
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
