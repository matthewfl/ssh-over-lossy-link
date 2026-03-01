#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
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

  // Fraction-slow thresholds: what fraction of recent RTT samples are significantly
  // above the minimum (fast-path floor) before we increase/decrease redundancy.
  static constexpr float kFractionSlowIncreaseFast   = 0.05f;  // >5% slow → big increase
  static constexpr float kFractionSlowIncreaseMedium = 0.01f;  // >1% slow → medium increase
  static constexpr float kFractionSlowDecrease       = 0.002f; // <0.2% slow → decrease
  static constexpr size_t kMinSamplesForAdapt = 20;            // need ≥20 samples
  unsigned next_carrier_for_rs = 0;
  size_t next_carrier_for_small = 0;  // round-robin for small-packet redundancy

  // Server-side link monitoring: record when we send each id; when client sends ACK, measure RTT.
  auto now_ns = []() {
    return static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  };
  std::map<uint64_t, uint64_t> ack_send_time_ns;  // id -> when we sent it (for server→client RTT)
  std::deque<uint64_t> server_recent_rtt_ns;
  const size_t max_server_recent_rtt = 50;
  const uint64_t metrics_interval_ns = 400 * 1000000ULL;  // 400ms
  uint64_t last_metrics_ns = 0;

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
  uint64_t last_rs_drain_ns         = 0;
  uint64_t last_retransmit_check_ns = 0;
  uint64_t last_global_recv_ns      = now_ns();  // last time any data arrived from any carrier

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

  auto send_pong = [&](int fd, uint64_t id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_pong(it->second.write_buf, id);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
  };

  // Send small chunk (< block_size) to runtime_small_packet_redundancy carriers only (not Reed–Solomon).
  auto queue_small_to_carriers = [&](const uint8_t* data, size_t len) {
    if (len == 0 || carriers.empty()) return;
    ack_send_time_ns[next_send_id] = now_ns();
    const unsigned n_copies = std::max(1u, std::min(runtime_small_packet_redundancy, static_cast<unsigned>(carriers.size())));
    std::vector<int> carrier_fds;
    for (auto& [fd, _] : carriers) carrier_fds.push_back(fd);
    for (unsigned i = 0; i < n_copies; ++i) {
      int fd = carrier_fds[(next_carrier_for_small + i) % carrier_fds.size()];
      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        packet_io::append_small(it->second.write_buf, next_send_id, data, len);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
      }
    }
    next_carrier_for_small += n_copies;
    next_send_id++;
  };

  auto queue_rs_shard_to_carrier = [&](int fd, unsigned n, unsigned k, uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_rs_shard(it->second.write_buf, next_send_id, n, k, block_size, shard_index, shard_data);
  };

  auto flush_carrier_writes = [&]() {
    packet_io::flush_carrier_writes(carriers, epfd, ev);
    if (carriers.empty() && !unacked_data.empty())
      retransmit_needed = true;
  };

  auto queue_ack_to_carrier = [&](int fd, uint64_t acked_id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_ack(it->second.write_buf, acked_id);
  };

  auto queue_server_metrics_to_carrier = [&](int fd, uint64_t max_rtt_ns) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_server_metrics(it->second.write_buf, max_rtt_ns);
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
    if (backend_fd < 0 || !backend_connected || backend_pending.empty()) return;
    auto& front = backend_pending.front();
    ssize_t n = write(backend_fd, front.data.data(), front.data.size());
    if (n <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = backend_fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
      }
      return;
    }
    front.data.erase(front.data.begin(), front.data.begin() + n);
    if (front.data.empty()) {
      uint64_t acked_id = front.id;
      int cfd = front.completing_fd;
      backend_pending.pop_front();
      if (backend_pending.empty()) {
        ev.events = EPOLLIN;
        ev.data.fd = backend_fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
      }
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
  recv_cb.on_ping = [&](int fd, uint64_t id) { send_pong(fd, id); };  // client may still send PING for health
  recv_cb.on_ack = [&](int /*fd*/, uint64_t acked_id) {
    auto it = ack_send_time_ns.find(acked_id);
    if (it != ack_send_time_ns.end()) {
      uint64_t rtt = now_ns() - it->second;
      // Sanity check: discard clearly-bogus values (> 60s); wrap-around produces ~1.8e19 ns.
      if (rtt < 60000000000ULL) {
        server_recent_rtt_ns.push_back(rtt);
        while (server_recent_rtt_ns.size() > max_server_recent_rtt) server_recent_rtt_ns.pop_front();
      }
    }
    for (auto it_m = ack_send_time_ns.begin(); it_m != ack_send_time_ns.end(); )
      if (it_m->first <= acked_id) it_m = ack_send_time_ns.erase(it_m);
      else ++it_m;
    // Data confirmed received: remove from retransmit buffer.
    for (auto it_u = unacked_data.begin(); it_u != unacked_data.end() && it_u->first <= acked_id; )
      it_u = unacked_data.erase(it_u);
  };
  recv_cb.on_set_config = [&](const PacketConfig& pc) {
    runtime_auto_adapt = (pc.auto_adapt != 0);
    max_packet = std::min(static_cast<size_t>(pc.packet_size), MAX_PACKET_PAYLOAD);
    if (max_packet == 0) max_packet = 800;
    runtime_small_packet_redundancy = pc.small_packet_redundancy;
    if (runtime_small_packet_redundancy == 0) runtime_small_packet_redundancy = 1;
    runtime_rs_redundancy = pc.reed_solomon_redundancy;
    if (runtime_rs_redundancy < 0.1f) runtime_rs_redundancy = 0.2f;
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
    return packet_io::process_carrier_read(fd, s, reassembly, rs_pending, next_deliver_id, recv_cb);
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    // 15-second bound ensures we run ping/inactivity/RS-drain even when fully idle.
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), 15000);
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
                  std::vector<std::vector<uint8_t>> par(m, std::vector<uint8_t>(ui.block_size));
                  std::vector<uint8_t*> pptrs(m);
                  for (unsigned si = 0; si < m; ++si) pptrs[si] = par[si].data();
                  reed_solomon::encode(ui.k, m, dptrs.data(), pptrs.data(), ui.block_size);
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
            if (nr == 0) { FILE* dbgf = fopen("/tmp/ssh-oll-server-exit.log","a"); if(dbgf){fprintf(dbgf,"backend EOF → exit\n");fclose(dbgf);} running = false; }
            else if (errno != EAGAIN && errno != EWOULDBLOCK) { FILE* dbgf = fopen("/tmp/ssh-oll-server-exit.log","a"); if(dbgf){fprintf(dbgf,"backend read error errno=%d\n",errno);fclose(dbgf);} }
            break;
          }
          backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
        }
        if (e & EPOLLOUT) {
          flush_backend_pending();
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          { FILE* dbgf = fopen("/tmp/ssh-oll-server-exit.log","a"); if(dbgf){fprintf(dbgf,"backend EPOLLERR|HUP → exit\n");fclose(dbgf);} }
          running = false;
          break;
        }
        continue;
      }

      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        if (e & EPOLLIN) {
          if (!process_carrier_read(fd, it->second)) {
            close(fd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            carriers.erase(it);
            if (carriers.empty() && !unacked_data.empty())
              retransmit_needed = true;
          }
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
          if (carriers.empty() && !unacked_data.empty())
            retransmit_needed = true;
        }
      }
    }

    const uint64_t now_ns_val = now_ns();

    // ── Ping / inactivity-check / RS stale-drain ────────────────────────────
    if (now_ns_val - last_ping_check_ns >= 1000000000ULL) {
      last_ping_check_ns = now_ns_val;
      static constexpr uint64_t PING_IDLE_NS = 15000000000ULL;
      static constexpr uint64_t DEAD_IDLE_NS = 20000000000ULL;
      static constexpr uint64_t GRACE_NS     =  5000000000ULL;
      std::vector<int> to_kill;
      for (auto& [cfd, cs] : carriers) {
        if (now_ns_val - cs.connect_ns < GRACE_NS) continue;
        uint64_t last_activity = std::max(cs.connect_ns, cs.last_recv_ns);
        if (now_ns_val - last_activity > DEAD_IDLE_NS) {
          to_kill.push_back(cfd);
        } else if (cs.write_buf.empty()
                   && now_ns_val - cs.last_send_ns > PING_IDLE_NS
                   && now_ns_val - cs.last_recv_ns  > PING_IDLE_NS) {
          packet_io::append_ping(cs.write_buf, 0);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = cfd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
        }
      }
      for (int cfd : to_kill) {
        close(cfd);
        epoll_ctl(epfd, EPOLL_CTL_DEL, cfd, nullptr);
        carriers.erase(cfd);
        if (carriers.empty() && !unacked_data.empty())
          retransmit_needed = true;
      }

      // Update global receive timestamp from all live carriers.
      for (auto& [cfd, cs] : carriers)
        if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

      // Global idle timeout: if nothing has been received from any carrier for
      // 2 minutes the client is gone; exit so the server process doesn't linger.
      static constexpr uint64_t SERVER_GLOBAL_IDLE_NS = 120000000000ULL;  // 2 min
      if (now_ns_val - last_global_recv_ns > SERVER_GLOBAL_IDLE_NS) {
        FILE* dbgf = fopen("/tmp/ssh-oll-server-exit.log","a"); if(dbgf){fprintf(dbgf,"global idle timeout → exit\n");fclose(dbgf);}
        running = false;
      }
    }

    // Timeout-based retransmit: re-send any group unACK'd for > 3s to all alive carriers.
    if (!unacked_data.empty() && !carriers.empty()
        && now_ns_val - last_retransmit_check_ns >= 500000000ULL) {
      last_retransmit_check_ns = now_ns_val;
      static constexpr uint64_t RETRANSMIT_TIMEOUT_NS = 3000000000ULL;
      // Pick one non-busy carrier for retransmit.
      int rfd = carriers.begin()->first;
      for (auto& [uid, ui] : unacked_data) {
        if (ui.send_ns == 0 || now_ns_val - ui.send_ns < RETRANSMIT_TIMEOUT_NS) continue;
        auto& rcs = carriers[rfd];
        if (ui.is_small) {
          packet_io::append_small(rcs.write_buf, uid, ui.data.data(), ui.data.size());
        } else {
          std::vector<const uint8_t*> dptrs(ui.k);
          for (unsigned si = 0; si < ui.k; ++si) dptrs[si] = ui.data.data() + si * ui.block_size;
          unsigned rm = ui.n - ui.k;
          std::vector<std::vector<uint8_t>> rpar(rm, std::vector<uint8_t>(ui.block_size));
          std::vector<uint8_t*> rpptrs(rm);
          for (unsigned si = 0; si < rm; ++si) rpptrs[si] = rpar[si].data();
          reed_solomon::encode(ui.k, rm, dptrs.data(), rpptrs.data(), ui.block_size);
          for (unsigned si = 0; si < ui.n; ++si) {
            const uint8_t* shard = (si < ui.k)
                ? (ui.data.data() + si * ui.block_size) : rpar[si - ui.k].data();
            packet_io::append_rs_shard(rcs.write_buf, uid, ui.n, ui.k, ui.block_size, si, shard);
          }
        }
        ui.send_ns = now_ns_val;  // throttle: don't retransmit again for 3 s
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = rfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, rfd, &ev);
      }
    }

    if (now_ns_val - last_rs_drain_ns >= 1000000000ULL) {
      last_rs_drain_ns = now_ns_val;
      static constexpr uint64_t RS_STALE_NS = 10000000000ULL;
      for (auto it = rs_pending.begin(); it != rs_pending.end(); ) {
        if (it->second.first_recv_ns > 0 && now_ns_val - it->second.first_recv_ns > RS_STALE_NS)
          it = rs_pending.erase(it);
        else
          ++it;
      }
      while (true) {
        auto ra = reassembly.find(next_deliver_id);
        if (ra != reassembly.end()) {
          recv_cb.on_deliver(-1, next_deliver_id, ra->second.data(), ra->second.size());
          reassembly.erase(ra);
          next_deliver_id++;
        } else if (rs_pending.count(next_deliver_id)) {
          break;
        } else {
          uint64_t nxt = UINT64_MAX;
          if (!reassembly.empty())  nxt = std::min(nxt, reassembly.begin()->first);
          if (!rs_pending.empty())  nxt = std::min(nxt, rs_pending.begin()->first);
          if (nxt > next_deliver_id && nxt < UINT64_MAX)
            next_deliver_id = nxt;
          else
            break;
        }
      }
    }

    // When auto_adapt, server manages its own redundancy and informs the client.
    if (runtime_auto_adapt && !carriers.empty() && now_ns_val - last_adapt_ns >= adapt_interval_ns
        && server_recent_rtt_ns.size() >= kMinSamplesForAdapt) {
      last_adapt_ns = now_ns_val;
      // Compute min-gap metric: what fraction of recent RTTs are significantly above
      // the fast-path floor?  The 10th-percentile acts as a robust "minimum achievable
      // RTT" estimate (insensitive to a few extreme outliers skewing the sample).
      std::vector<uint64_t> sorted_rtt(server_recent_rtt_ns.begin(), server_recent_rtt_ns.end());
      std::sort(sorted_rtt.begin(), sorted_rtt.end());
      size_t p10_idx = std::max(size_t{0}, sorted_rtt.size() / 10);
      uint64_t min_rtt = sorted_rtt[p10_idx];
      // Only adapt when min_rtt is in a plausible range (1ms..30s).
      if (min_rtt > 1000000ULL && min_rtt < 30000000000ULL) {
        uint64_t slow_thr = min_rtt * 2;  // packets taking >2× the fast floor are "slow"
        size_t n_slow = 0;
        for (uint64_t r : server_recent_rtt_ns) if (r > slow_thr) n_slow++;
        float fraction_slow = static_cast<float>(n_slow) / static_cast<float>(server_recent_rtt_ns.size());

        if (fraction_slow > kFractionSlowIncreaseFast) {
          runtime_rs_redundancy = std::min(2.0f, runtime_rs_redundancy + 0.5f);
          runtime_small_packet_redundancy = std::min(20u, runtime_small_packet_redundancy + 3u);
        } else if (fraction_slow > kFractionSlowIncreaseMedium) {
          runtime_rs_redundancy = std::min(2.0f, runtime_rs_redundancy + 0.25f);
          runtime_small_packet_redundancy = std::min(20u, runtime_small_packet_redundancy + 1u);
        } else if (fraction_slow < kFractionSlowDecrease && sorted_rtt.size() >= 30) {
          runtime_rs_redundancy = std::max(0.2f, runtime_rs_redundancy - 0.05f);
          runtime_small_packet_redundancy = std::max(2u, runtime_small_packet_redundancy - 1u);
        }
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
    if (backend_connected && backend_fd >= 0 && !backend_read_buf.empty() && !carriers.empty()) {
      const size_t block_size = max_packet;
      if (backend_read_buf.size() >= block_size) {
        unsigned k = static_cast<unsigned>(std::min(backend_read_buf.size() / block_size, static_cast<size_t>(255)));
        if (k >= 1) {
          unsigned m = std::max(1u, static_cast<unsigned>(k * runtime_rs_redundancy + 0.5f));
          unsigned n = std::min(k + m, 255u);
          m = n - k;
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
          // Save original bytes for retransmit if all carriers die before ACK.
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
          // Send any sub-block_size remainder immediately in the same flush cycle.
          if (!backend_read_buf.empty()) {
            UnackedItem ui;
            ui.data = backend_read_buf;
            ui.is_small = true;
            ui.send_ns = now_ns();
            unacked_data[next_send_id] = std::move(ui);
            queue_small_to_carriers(backend_read_buf.data(), backend_read_buf.size());
            backend_read_buf.clear();
          }
        } else {
          // Chunk < block_size: send as SMALL with small_packet_redundancy copies (no Reed–Solomon).
          size_t chunk = std::min(backend_read_buf.size(), block_size);
          { UnackedItem ui; ui.data.assign(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
            ui.is_small = true; ui.send_ns = now_ns(); unacked_data[next_send_id] = std::move(ui); }
          queue_small_to_carriers(backend_read_buf.data(), chunk);
          backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
        }
      } else {
        // Buffered data < block_size: SMALL with small_packet_redundancy copies.
        size_t chunk = backend_read_buf.size();
        { UnackedItem ui; ui.data.assign(backend_read_buf.begin(), backend_read_buf.end());
          ui.is_small = true; ui.send_ns = now_ns(); unacked_data[next_send_id] = std::move(ui); }
        queue_small_to_carriers(backend_read_buf.data(), chunk);
        backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
      }
    }
    flush_backend_pending();
    flush_carrier_writes();
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
