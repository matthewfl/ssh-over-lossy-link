#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
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
#include <sys/wait.h>
#include <unistd.h>

namespace ssholl {

namespace {

using packet_io::CarrierState;
using packet_io::RsPending;
using packet_io::MAX_PACKET_PAYLOAD;
using packet_io::READ_BUF_SIZE;

void set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return;
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::string make_client_dir() {
  std::random_device rd;
  uint32_t r = rd();
  char suffix[16];
  snprintf(suffix, sizeof suffix, "%08x", r);
  return std::string("/tmp/ssh-oll-client.") + suffix;
}

// Launch server on remote host; read one line (socket path) from stdout. Returns path or empty on failure.
std::string launch_server(const Args& args) {
  int pipefd[2];
  if (pipe2(pipefd, O_CLOEXEC) < 0) {
    std::perror("ssh-oll client: pipe");
    return {};
  }
  pid_t pid = fork();
  if (pid < 0) {
    std::perror("ssh-oll client: fork");
    close(pipefd[0]);
    close(pipefd[1]);
    return {};
  }
  if (pid == 0) {
    close(pipefd[0]);
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
    close(pipefd[1]);
    std::string port_str = std::to_string(args.remote_port);
    const char* argv[] = {
      "ssh",
      args.lossy_ssh_host.c_str(),
      args.config.path_on_server.c_str(),
      "--server",
      args.remote_hostname.c_str(),
      port_str.c_str(),
      nullptr
    };
    execvp("ssh", const_cast<char* const*>(argv));
    _exit(127);
  }
  close(pipefd[1]);
  std::string path;
  char buf[512];
  ssize_t n;
  while (path.find('\n') == std::string::npos && (n = read(pipefd[0], buf, sizeof buf)) > 0)
    path.append(buf, buf + n);
  close(pipefd[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  while (path.back() == '\n' || path.back() == '\r')
    path.pop_back();
  return path;
}

// Connect to Unix socket at path. Non-blocking; returns fd or -1.
int connect_unix(const std::string& path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  set_nonblocking(fd);
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof addr.sun_path) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  int r = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr);
  if (r == 0) return fd;
  if (errno != EINPROGRESS && errno != EAGAIN) {
    close(fd);
    return -1;
  }
  return fd;
}

int get_so_error(int fd) {
  int err = 0;
  socklen_t len = sizeof err;
  return getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 ? err : -1;
}

}  // namespace

int run_client(const Args& args) {
  std::string socket_path;
  std::string client_dir;
  std::vector<pid_t> ssh_pids;

  if (!args.unix_socket_connection.empty()) {
    socket_path = args.unix_socket_connection;
  } else {
    socket_path = launch_server(args);
    if (socket_path.empty()) {
      std::fprintf(stderr, "ssh-oll: failed to launch server on %s\n", args.lossy_ssh_host.c_str());
      return 1;
    }
    client_dir = make_client_dir();
    if (mkdir(client_dir.c_str(), 0700) < 0) {
      std::perror("ssh-oll: mkdir");
      return 1;
    }

    const unsigned N = args.config.connections;
    ssh_pids.reserve(N);

    for (unsigned i = 0; i < N; ++i) {
      std::string local_path = client_dir + "/" + std::to_string(i);
      pid_t pid = fork();
      if (pid < 0) {
        std::perror("ssh-oll: fork");
        for (pid_t p : ssh_pids) kill(p, SIGTERM);
        rmdir(client_dir.c_str());
        return 1;
      }
      if (pid == 0) {
        std::string spec = local_path + ":" + socket_path;
        const char* argv[] = { "ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L", spec.c_str(), args.lossy_ssh_host.c_str(), nullptr };
        execvp("ssh", const_cast<char* const*>(argv));
        _exit(127);
      }
      ssh_pids.push_back(pid);
    }

    // Wait for SSH to create sockets and accept connections.
    for (int wait_ms = 0; wait_ms < 5000; wait_ms += 100) {
      usleep(100 * 1000);
      bool any = false;
      for (unsigned i = 0; i < N; ++i) {
        std::string path = client_dir + "/" + std::to_string(i);
        if (access(path.c_str(), F_OK) == 0) { any = true; break; }
      }
      if (any) break;
    }
  }

  const unsigned N = args.config.connections;
  const unsigned max_connections = args.config.max_connections;
  unsigned next_carrier_index = N;  // next socket index when adding carriers (SSH mode)
  std::vector<std::string> pending_carrier_paths;  // SSH mode: paths we're waiting to connect to

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    std::perror("ssh-oll: epoll_create1");
    if (args.unix_socket_connection.empty()) {
      for (pid_t p : ssh_pids) kill(p, SIGTERM);
      rmdir(client_dir.c_str());
    }
    return 1;
  }

  set_nonblocking(STDIN_FILENO);
  set_nonblocking(STDOUT_FILENO);

  std::map<int, CarrierState> carriers;
  std::map<uint64_t, std::vector<uint8_t>> reassembly;
  std::map<uint64_t, RsPending> rs_pending;
  uint64_t next_deliver_id = 0;
  uint64_t next_send_id = 0;
  std::vector<uint8_t> stdin_buf;
  std::vector<uint8_t> stdout_buf;
  bool stdin_eof = false;
  bool stdin_in_epoll = true;   // tracks whether STDIN_FILENO is registered with epoll
  bool stdout_in_epoll = false; // tracks whether STDOUT_FILENO is registered with epoll
  // Max bytes we buffer from stdin before pausing reads (avoids spinning when carriers are dead).
  static constexpr size_t STDIN_THROTTLE_BYTES = 256 * 1024;
  unsigned next_carrier = 0;
  size_t effective_max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));
  if (effective_max_packet == 0) effective_max_packet = 800;
  auto now_ns = []() {
    return static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  };
  std::map<int, std::deque<std::pair<uint64_t, uint64_t>>> carrier_pending_acks;  // fd -> [(id, time_ns)]

  // Effective config: when auto_adapt and we have SERVER_CONFIG, use server's; else use local.
  bool has_server_config = false;
  float effective_rs_redundancy = args.config.auto_adapt ? std::max(args.config.rs_redundancy, 0.6f) : args.config.rs_redundancy;
  unsigned effective_small_packet_redundancy = args.config.auto_adapt ? std::max(args.config.small_packet_redundancy, 6u) : args.config.small_packet_redundancy;
  std::deque<uint64_t> recent_rtt_ns;
  const size_t max_recent_rtt = 100;
  const uint64_t adapt_interval_ns = 300 * 1000000ULL;   // 300ms
  const uint64_t add_carrier_interval_ns = 100 * 1000000ULL;  // 100ms
  uint64_t last_adapt_ns = 0;
  uint64_t last_add_carrier_ns = 0;
  // Only reap a carrier via RTT-outlier if its RTT is both much worse than its peers (5×
  // median) AND absolutely very slow (5 s).  A 3×/1 s threshold is too aggressive: with
  // natural link latency variance (e.g., 100–2000 ms random) the slowest carrier always
  // looks like an outlier even when it is healthy, causing unnecessary churn that drops
  // in-flight RS shards and creates multi-second stalls.
  const uint64_t very_high_rtt_ns = 5000 * 1000000ULL;
  // Fraction-slow thresholds (mirrors server.cc constants).
  static constexpr float kFractionSlowIncreaseFast   = 0.05f;
  static constexpr float kFractionSlowIncreaseMedium = 0.01f;
  static constexpr float kFractionSlowDecrease       = 0.002f;
  static constexpr size_t kMinSamplesForAdapt = 20;
  uint64_t backpressure_write_threshold = 150 * effective_max_packet;  // updated when effective_max_packet changes
  float last_sent_rs_redundancy = -1.0f;   // sentinel so we send initial config when auto
  unsigned last_sent_small_packet_redundancy = 0;
  uint64_t server_reported_max_rtt_ns = 0;  // server→client path RTT from SERVER_METRICS
  // min carriers to keep during reaping (never drop below the initial configured count)
  const unsigned min_carriers_floor = std::max(2u, args.config.connections);
  uint64_t last_reap_ns = 0;
  const uint64_t reap_check_interval_ns = 2000 * 1000000ULL;

  // Unacked-send retransmit buffer.  Holds the original pre-encoded data for
  // each outstanding send_id so that it can be re-encoded and re-sent on a
  // new carrier when all existing carriers die.
  struct UnackedItem {
    std::vector<uint8_t> data;   // for RS: k*block_size bytes; for SMALL: raw bytes
    unsigned n = 0;
    unsigned k = 0;
    uint16_t block_size = 0;
    bool is_small = false;
    uint64_t send_ns = 0;        // when originally sent (for timeout-based retransmit)
  };
  std::map<uint64_t, UnackedItem> unacked_sends;
  bool retransmit_needed = false;  // set when last carrier dies with unacked data

  // Timing for periodic operations that don't depend on carrier events.
  uint64_t last_ping_check_ns       = 0;
  uint64_t last_rs_drain_ns                = 0;
  uint64_t next_deliver_id_stuck_since_ns  = 0;  // when gap at next_deliver_id first appeared
  uint64_t last_retransmit_check_ns = 0;
  uint64_t last_global_recv_ns      = now_ns();  // last time any data arrived from any carrier

  struct epoll_event ev{};

  ev.events = EPOLLIN;
  ev.data.fd = STDIN_FILENO;
  epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

  for (unsigned i = 0; i < N; ++i) {
    std::string path = args.unix_socket_connection.empty() ? (client_dir + "/" + std::to_string(i)) : socket_path;
    int fd = connect_unix(path);
    if (fd < 0) continue;
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0)
      carriers[fd].connecting = true;
    else
      close(fd);
  }

  if (carriers.empty()) {
    std::fprintf(stderr, "ssh-oll: could not connect any carrier to server\n");
    close(epfd);
    if (args.unix_socket_connection.empty()) {
      for (pid_t p : ssh_pids) kill(p, SIGTERM);
      rmdir(client_dir.c_str());
    }
    return 1;
  }

  // Queue a SMALL packet to one carrier. If same_id is true, use current next_send_id
  // and do not increment (caller will increment once after queuing to all carriers).
  auto queue_to_carrier = [&](int fd, const uint8_t* data, size_t len, bool same_id = false) {
    if (len == 0) return;
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    carrier_pending_acks[fd].emplace_back(next_send_id, now_ns());
    packet_io::append_small(it->second.write_buf, next_send_id, data, len);
    if (!same_id)
      next_send_id++;
  };

  // Queue SET_CONFIG to one carrier (client -> server). Includes auto_adapt so server knows who manages redundancy.
  auto queue_config_to_carrier = [&](int fd, uint16_t pkt_size, uint16_t small_red, float max_delay_ms, float rs_red, uint8_t auto_adapt_val) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_config(it->second.write_buf, pkt_size, small_red, max_delay_ms, rs_red, auto_adapt_val);
  };

  // Queue one Reed-Solomon shard to one carrier (same id for all shards in block).
  auto queue_rs_shard_to_carrier = [&](int fd, unsigned n, unsigned k, uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    carrier_pending_acks[fd].emplace_back(next_send_id, now_ns());
    packet_io::append_rs_shard(it->second.write_buf, next_send_id, n, k, block_size, shard_index, shard_data);
  };

  auto flush_stdout = [&]() {
    while (!stdout_buf.empty()) {
      ssize_t n = write(STDOUT_FILENO, stdout_buf.data(), stdout_buf.size());
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (!stdout_in_epoll) {
            ev.events = EPOLLOUT;
            ev.data.fd = STDOUT_FILENO;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDOUT_FILENO, &ev) == 0)
              stdout_in_epoll = true;
          }
          return;
        }
        // Unrecoverable write error (e.g. EPIPE): discard buffered output.
        stdout_buf.clear();
        if (stdout_in_epoll) {
          epoll_ctl(epfd, EPOLL_CTL_DEL, STDOUT_FILENO, nullptr);
          stdout_in_epoll = false;
        }
        return;
      }
      stdout_buf.erase(stdout_buf.begin(), stdout_buf.begin() + n);
    }
  };

  packet_io::ReceiveCallbacks recv_cb;
  recv_cb.on_deliver = [&](int cfd, uint64_t id, const uint8_t* data, size_t len) {
    stdout_buf.insert(stdout_buf.end(), data, data + len);
    // ACK on the completing carrier so the server gets per-carrier RTT measurements.
    // Fall back to any carrier if completing_fd was already closed.
    if (carriers.empty()) return;
    if (!carriers.count(cfd)) cfd = carriers.begin()->first;
    packet_io::append_ack(carriers[cfd].write_buf, id);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = cfd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
  };
  recv_cb.on_server_metrics = [&](uint64_t max_rtt_ns) {
    // Sanity check: discard obviously-garbage values (> 10s means something is wrong).
    if (max_rtt_ns < 10000000000ULL)
      server_reported_max_rtt_ns = max_rtt_ns;
  };
  recv_cb.on_server_config = [&](const PacketServerConfig& psc) {
    has_server_config = true;
    effective_max_packet = std::min(static_cast<size_t>(psc.packet_size), static_cast<size_t>(MAX_PACKET_PAYLOAD));
    if (effective_max_packet == 0) effective_max_packet = 800;
    effective_rs_redundancy = (psc.reed_solomon_redundancy >= 0.1f) ? psc.reed_solomon_redundancy : 0.2f;
    effective_small_packet_redundancy = (psc.small_packet_redundancy != 0) ? psc.small_packet_redundancy : 2u;
    backpressure_write_threshold = 150 * effective_max_packet;
  };
  recv_cb.on_ack = [&](int fd, uint64_t acked_id) {
    auto it_p = carrier_pending_acks.find(fd);
    if (it_p == carrier_pending_acks.end()) return;
    uint64_t rtt_ns = 0;
    const uint64_t recv_time = now_ns();
    auto& q = it_p->second;
    while (!q.empty() && q.front().first <= acked_id) {
      rtt_ns = recv_time - q.front().second;
      q.pop_front();
    }
    if (rtt_ns != 0) {
      auto it_c = carriers.find(fd);
      if (it_c != carriers.end()) it_c->second.last_rtt_ns = rtt_ns;
      if (args.config.auto_adapt) {
        recent_rtt_ns.push_back(rtt_ns);
        while (recent_rtt_ns.size() > max_recent_rtt) recent_rtt_ns.pop_front();
      }
    }
    // Data confirmed delivered: no longer need to retransmit.
    for (auto it_u = unacked_sends.begin(); it_u != unacked_sends.end() && it_u->first <= acked_id; )
      it_u = unacked_sends.erase(it_u);
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

  auto flush_carrier_writes = [&]() {
    packet_io::flush_carrier_writes(carriers, epfd, ev, [](int, const CarrierState& s) { return s.connecting; });
    for (auto it = carrier_pending_acks.begin(); it != carrier_pending_acks.end(); )
      if (carriers.count(it->first) == 0) it = carrier_pending_acks.erase(it);
      else ++it;
    // packet_io::flush_carrier_writes may silently remove carriers on write error,
    // bypassing remove_carrier.  Make sure retransmit is triggered in that case.
    if (carriers.empty() && !unacked_sends.empty())
      retransmit_needed = true;
  };

  // Maps each carrier fd to its SSH directory index (SSH mode only); used to recycle
  // index slots when a carrier dies so we never exhaust max_connections permanently.
  std::map<int, unsigned> fd_to_ssh_index;
  if (args.unix_socket_connection.empty()) {
    // Populate for the initial N carriers (they were connected just above).
    unsigned idx = 0;
    for (auto& [fd, _] : carriers) fd_to_ssh_index[fd] = idx++;
  }

  // Centralised carrier removal: closes the fd, removes from epoll, cleans up maps.
  // Also returns the SSH index slot to the free pool (SSH mode), and flags retransmit
  // when the very last carrier is lost while data remains unacknowledged.
  auto remove_carrier = [&](int fd) {
    { static FILE* rcf = fopen("/tmp/ssh-oll-cli-events.log","a");
      if(rcf){ fprintf(rcf,"[carrier-remove t=%llu fd=%d total=%zu]\n",
               (unsigned long long)(now_ns()/1000000ULL),fd,carriers.size()-1); fflush(rcf); } }
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    carriers.erase(fd);
    carrier_pending_acks.erase(fd);
    if (!args.unix_socket_connection.empty()) {
      if (carriers.empty() && !unacked_sends.empty())
        retransmit_needed = true;
      return;
    }
    fd_to_ssh_index.erase(fd);
    if (carriers.empty() && !unacked_sends.empty())
      retransmit_needed = true;
  };


  // Find a free SSH directory index in [0, max_connections) that is neither currently
  // connected nor waiting to connect.  Returns max_connections when none is available.
  auto find_free_ssh_index = [&]() -> unsigned {
    std::set<unsigned> in_use;
    for (auto& [fd, idx] : fd_to_ssh_index) in_use.insert(idx);
    for (auto& path : pending_carrier_paths) {
      // Path is client_dir + "/" + index
      std::string prefix = client_dir + "/";
      if (path.size() > prefix.size())
        in_use.insert(static_cast<unsigned>(std::stoul(path.substr(prefix.size()))));
    }
    for (unsigned i = 0; i < max_connections; ++i)
      if (!in_use.count(i)) return i;
    return max_connections;
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    // Bound epoll_wait so we can run periodic tasks (ping, inactivity check, RS drain)
    // at least every 15 seconds even when the link is completely idle.
    int epoll_timeout_ms = 15000;
    if (carriers.size() < min_carriers_floor) {
      // Below floor: use a much shorter timeout to reconnect promptly.
      uint64_t elapsed = now_ns() - last_add_carrier_ns;
      uint64_t floor_interval = carriers.empty() ? 50000000ULL : add_carrier_interval_ns;
      if (elapsed >= floor_interval)
        epoll_timeout_ms = 0;
      else
        epoll_timeout_ms = static_cast<int>((floor_interval - elapsed) / 1000000ULL + 1);
    }
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), epoll_timeout_ms);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }

    for (int i = 0; i < n; ++i) {
      int fd = events[i].data.fd;
      uint32_t e = events[i].events;

      if (fd == STDIN_FILENO) {
        if (stdin_eof) continue;
        uint8_t buf[READ_BUF_SIZE];
        // Drain stdin completely in one epoll iteration so we don't need multiple
        // wakeups to receive a full payload (avoids extra ~scheduler latency).
        while (true) {
          ssize_t nr = read(STDIN_FILENO, buf, sizeof buf);
          if (nr <= 0) {
            if (nr == 0) {
              stdin_eof = true;
              // Remove stdin from epoll: EOF makes the fd permanently readable
              // (level-triggered), which would spin the event loop.
              epoll_ctl(epfd, EPOLL_CTL_DEL, STDIN_FILENO, nullptr);
              stdin_in_epoll = false;
            }
            // EINTR is transient; only treat other errors as EOF
            break;
          }
          stdin_buf.insert(stdin_buf.end(), buf, buf + nr);
        }
        // If stdin_buf has grown large and there are no carriers to send to,
        // temporarily remove STDIN from epoll so we don't spin while waiting for
        // carriers to reconnect.  It is re-armed below whenever conditions improve.
        if (!stdin_eof && carriers.empty() && stdin_buf.size() >= STDIN_THROTTLE_BYTES
            && stdin_in_epoll) {
          epoll_ctl(epfd, EPOLL_CTL_DEL, STDIN_FILENO, nullptr);
          stdin_in_epoll = false;
        }
        while (stdin_buf.size() >= effective_max_packet && !carriers.empty()) {
          const size_t block_size = effective_max_packet;
          unsigned k = static_cast<unsigned>(std::min(stdin_buf.size() / block_size, static_cast<size_t>(255)));
          if (k == 0) break;
          float rs_frac = args.config.auto_adapt ? effective_rs_redundancy : args.config.rs_redundancy;
          unsigned m = std::max(1u, static_cast<unsigned>(k * rs_frac + 0.5f));
          unsigned n = std::min(k + m, 255u);
          m = n - k;
          std::vector<const uint8_t*> data_ptrs(k);
          for (unsigned i = 0; i < k; ++i)
            data_ptrs[i] = stdin_buf.data() + i * block_size;
          std::vector<std::vector<uint8_t>> parity(m, std::vector<uint8_t>(block_size));
          std::vector<uint8_t*> parity_ptrs(m);
          for (unsigned i = 0; i < m; ++i) parity_ptrs[i] = parity[i].data();
          reed_solomon::encode(k, m, data_ptrs.data(), parity_ptrs.data(), block_size);
          size_t num_shards = n;
          for (size_t i = 0; i < num_shards; ++i) {
            auto it = carriers.begin();
            std::advance(it, (next_carrier + i) % carriers.size());
            const uint8_t* shard = (i < k) ? (stdin_buf.data() + i * block_size) : parity[i - k].data();
            queue_rs_shard_to_carrier(it->first, n, k, static_cast<uint16_t>(block_size), static_cast<unsigned>(i), shard);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = it->first;
            epoll_ctl(epfd, EPOLL_CTL_MOD, it->first, &ev);
          }
          // Save original data so we can retransmit on reconnect if all carriers die.
          {
            UnackedItem ui;
            ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + k * block_size);
            ui.n = n;  ui.k = static_cast<unsigned>(k);
            ui.block_size = static_cast<uint16_t>(block_size);
            ui.is_small = false;
            ui.send_ns = now_ns();
            unacked_sends[next_send_id] = std::move(ui);
          }
          next_send_id++;
          next_carrier += num_shards;
          stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + k * block_size);
        }
        // Send any remainder smaller than one block as SMALL (no Reed–Solomon) with small_packet_redundancy copies.
        if (!stdin_buf.empty() && stdin_buf.size() < effective_max_packet && !carriers.empty()) {
          size_t chunk = stdin_buf.size();
          const unsigned n_copies = std::max(1u, std::min(static_cast<unsigned>(carriers.size()), effective_small_packet_redundancy));
          {
            UnackedItem ui;
            ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
            ui.is_small = true;
            ui.send_ns = now_ns();
            unacked_sends[next_send_id] = std::move(ui);
          }
          for (unsigned i = 0; i < n_copies; ++i) {
            auto it = carriers.begin();
            std::advance(it, (next_carrier + i) % carriers.size());
            queue_to_carrier(it->first, stdin_buf.data(), chunk, n_copies > 1);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = it->first;
            epoll_ctl(epfd, EPOLL_CTL_MOD, it->first, &ev);
          }
          if (n_copies > 1) next_send_id++;
          next_carrier += n_copies;
          stdin_buf.clear();
        }
        // Flush immediately so data reaches kernel (and thus server) in this
        // iteration instead of after processing other events in the batch.
        flush_carrier_writes();
        continue;
      }

      if (fd == STDOUT_FILENO) {
        if (e & (EPOLLERR | EPOLLHUP)) {
          // Write end of stdout pipe broken; discard remaining output.
          stdout_buf.clear();
          epoll_ctl(epfd, EPOLL_CTL_DEL, STDOUT_FILENO, nullptr);
          stdout_in_epoll = false;
        } else if (e & EPOLLOUT) {
          flush_stdout();
          if (stdout_buf.empty() && stdout_in_epoll) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, STDOUT_FILENO, nullptr);
            stdout_in_epoll = false;
          }
        }
        continue;
      }

      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        if (it->second.connecting && (e & EPOLLOUT)) {
          int err = get_so_error(fd);
          if (err == 0) {
            it->second.connecting = false;
            it->second.connect_ns = now_ns();
            // Re-send any data that was in-flight on carriers that all died, using
            // the same send_ids so the receiver can combine with any partial shards
            // it already buffered — allowing RS groups to complete without data loss.
            if (retransmit_needed && !unacked_sends.empty()) {
              retransmit_needed = false;
              const uint64_t retransmit_now = now_ns();
              for (auto& [uid, ui] : unacked_sends) {
                if (ui.is_small) {
                  packet_io::append_small(it->second.write_buf, uid,
                                          ui.data.data(), ui.data.size());
                } else {
                  // Re-encode RS with the same parameters (n, k, block_size) so the
                  // receiver can combine these shards with any partials it retained.
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
                    packet_io::append_rs_shard(it->second.write_buf, uid,
                                               ui.n, ui.k, ui.block_size, si, shard);
                  }
                }
                // Reset timer so the periodic 3 s retransmit doesn't immediately
                // fire a redundant duplicate of what we just queued.
                ui.send_ns = retransmit_now;
              }
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            }
          } else if (err != EINPROGRESS && err != 0) {
            remove_carrier(fd);
            continue;
          }
        }
        if (e & EPOLLIN) {
          if (!process_carrier_read(fd, it->second))
            remove_carrier(fd);
        }
        if (carriers.count(fd) && (e & (EPOLLERR | EPOLLHUP))) {
          remove_carrier(fd);
        }
      }
    }

    if (stdin_eof && !stdin_buf.empty() && !carriers.empty()) {
      while (!stdin_buf.empty()) {
        size_t chunk = std::min(stdin_buf.size(), effective_max_packet);
        const bool small_packet = (chunk < effective_max_packet);
        // Small: n_copies = effective_small_packet_redundancy (RTT-adjusted). Full block: 1 copy (RS handles redundancy).
        const unsigned n_copies = small_packet
            ? std::max(1u, std::min(static_cast<unsigned>(carriers.size()), effective_small_packet_redundancy))
            : 1u;
        {
          UnackedItem ui;
          ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
          ui.is_small = true;
          ui.send_ns = now_ns();
          unacked_sends[next_send_id] = std::move(ui);
        }
        for (unsigned i = 0; i < n_copies; ++i) {
          auto it = carriers.begin();
          std::advance(it, (next_carrier + i) % carriers.size());
          queue_to_carrier(it->first, stdin_buf.data(), chunk, small_packet && n_copies > 1);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = it->first;
          epoll_ctl(epfd, EPOLL_CTL_MOD, it->first, &ev);
        }
        if (small_packet && n_copies > 1)
          next_send_id++;
        stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + chunk);
        next_carrier += n_copies;
      }
    }

    flush_carrier_writes();
    flush_stdout();

    // Try to complete pending SSH carrier connections
    for (auto it = pending_carrier_paths.begin(); it != pending_carrier_paths.end(); ) {
      if (access(it->c_str(), F_OK) != 0) { ++it; continue; }
      int fd = connect_unix(*it);
      if (fd >= 0) {
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
          carriers[fd].connecting = true;
          // Record SSH index for later recycling.
          std::string prefix = client_dir + "/";
          if (it->size() > prefix.size())
            fd_to_ssh_index[fd] = static_cast<unsigned>(std::stoul(it->substr(prefix.size())));
        } else {
          close(fd);
        }
      }
      it = pending_carrier_paths.erase(it);
    }

    // When !auto_adapt, client manages redundancy and pushes SET_CONFIG. When auto_adapt, server manages it and sends SERVER_CONFIG.
    if (args.config.auto_adapt && !carriers.empty()) {
      // Send initial SET_CONFIG once so server knows auto is on and gets initial values.
      if (last_sent_rs_redundancy == -1.0f) {
        last_sent_rs_redundancy = effective_rs_redundancy;
        last_sent_small_packet_redundancy = effective_small_packet_redundancy;
        int fd = carriers.begin()->first;
        queue_config_to_carrier(fd,
                               static_cast<uint16_t>(effective_max_packet),
                               static_cast<uint16_t>(effective_small_packet_redundancy),
                               args.config.max_delay_ms,
                               effective_rs_redundancy,
                               1u);  // auto_adapt=1: server will manage and send SERVER_CONFIG
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
      }
    } else if (!carriers.empty()) {
      const uint64_t now = now_ns();
      if (now - last_adapt_ns >= adapt_interval_ns && recent_rtt_ns.size() >= kMinSamplesForAdapt) {
        last_adapt_ns = now;
        std::vector<uint64_t> sorted_rtt(recent_rtt_ns.begin(), recent_rtt_ns.end());
        std::sort(sorted_rtt.begin(), sorted_rtt.end());
        size_t p10_idx = std::max(size_t{0}, sorted_rtt.size() / 10);
        uint64_t min_rtt = sorted_rtt[p10_idx];
        if (min_rtt > 1000000ULL && min_rtt < 30000000000ULL) {
          uint64_t slow_thr = min_rtt * 2;
          size_t n_slow = 0;
          for (uint64_t r : recent_rtt_ns) if (r > slow_thr) n_slow++;
          float fraction_slow = static_cast<float>(n_slow) / static_cast<float>(recent_rtt_ns.size());
          if (fraction_slow > kFractionSlowIncreaseFast) {
            effective_rs_redundancy = std::min(2.0f, effective_rs_redundancy + 0.5f);
            effective_small_packet_redundancy = std::min(20u, effective_small_packet_redundancy + 3u);
          } else if (fraction_slow > kFractionSlowIncreaseMedium) {
            effective_rs_redundancy = std::min(2.0f, effective_rs_redundancy + 0.25f);
            effective_small_packet_redundancy = std::min(20u, effective_small_packet_redundancy + 1u);
          } else if (fraction_slow < kFractionSlowDecrease && sorted_rtt.size() >= 30) {
            effective_rs_redundancy = std::max(0.2f, effective_rs_redundancy - 0.05f);
            effective_small_packet_redundancy = std::max(2u, effective_small_packet_redundancy - 1u);
          }
        }
      }
      if (effective_rs_redundancy != last_sent_rs_redundancy || effective_small_packet_redundancy != last_sent_small_packet_redundancy) {
        last_sent_rs_redundancy = effective_rs_redundancy;
        last_sent_small_packet_redundancy = effective_small_packet_redundancy;
        int fd = carriers.begin()->first;
        queue_config_to_carrier(fd,
                               static_cast<uint16_t>(effective_max_packet),
                               static_cast<uint16_t>(effective_small_packet_redundancy),
                               args.config.max_delay_ms,
                               effective_rs_redundancy,
                               0u);  // auto_adapt=0
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
      }
    }

    if (args.config.auto_adapt && !carriers.empty()) {
      const uint64_t now = now_ns();

      // Compute per-carrier stats for both carrier-add and reaping decisions.
      size_t total_write = 0;
      std::vector<uint64_t> rtt_samples;
      for (const auto& [cfd, st] : carriers) {
        (void)cfd;
        total_write += st.write_buf.size();
        if (st.last_rtt_ns > 0) rtt_samples.push_back(st.last_rtt_ns);
      }
      uint64_t max_carrier_rtt = rtt_samples.empty() ? 0 :
          *std::max_element(rtt_samples.begin(), rtt_samples.end());

      // RTT outlier: a carrier is stalled when its RTT is both extremely high in absolute terms
      // AND much worse than its peers (3× median). With a single carrier, skip the peer comparison.
      bool rtt_outlier = false;
      if (max_carrier_rtt > very_high_rtt_ns) {
        if (rtt_samples.size() <= 1) {
          rtt_outlier = true;
        } else {
          std::vector<uint64_t> sorted = rtt_samples;
          std::sort(sorted.begin(), sorted.end());
          uint64_t median_rtt = sorted[sorted.size() / 2];
          rtt_outlier = (max_carrier_rtt > 5 * median_rtt);
        }
      }

      // Carrier addition: when a carrier is stalled (clear RTT outlier), allow an add after
      // reap_check_interval_ns so the reap logic has time to run before we add another.
      // For backpressure or fraction_slow-based additions use the normal 100ms add interval.
      // All triggers share the same cap (min_carriers_floor * 3) to prevent unbounded growth:
      // the reap-and-replace pattern for rtt_outlier works within that budget.
      bool within_carrier_cap = (carriers.size() < min_carriers_floor * 3u);
      uint64_t add_interval = add_carrier_interval_ns;
      if (rtt_outlier && within_carrier_cap)
        add_interval = reap_check_interval_ns;  // at most one add per reap cycle when replacing a stall

      if (carriers.size() < max_connections && now - last_add_carrier_ns >= add_interval) {
        // Add a carrier for backpressure (write queues filling) or to replace a clear
        // RTT outlier.  Fraction-slow alone is NOT a trigger: with natural latency
        // variance every link looks "slow" relative to its fastest samples, which
        // would cause the connection count to balloon to min_carriers_floor*3 and
        // create RS-shard churn that stalls data delivery.
        bool need_more = (total_write > backpressure_write_threshold) || (rtt_outlier && within_carrier_cap);
        if (need_more) {
          last_add_carrier_ns = now;
          if (!args.unix_socket_connection.empty()) {
            int fd = connect_unix(socket_path);
            if (fd >= 0) {
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0)
                carriers[fd].connecting = true;
              else
                close(fd);
            }
          } else if (pending_carrier_paths.empty()) {
            unsigned free_idx = find_free_ssh_index();
            if (free_idx < max_connections) {
              std::string path = client_dir + "/" + std::to_string(free_idx);
              pid_t pid = fork();
              if (pid == 0) {
                std::string spec = path + ":" + socket_path;
                const char* argv[] = { "ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L", spec.c_str(), args.lossy_ssh_host.c_str(), nullptr };
                execvp("ssh", const_cast<char* const*>(argv));
                _exit(127);
              }
              if (pid > 0) {
                ssh_pids.push_back(pid);
                pending_carrier_paths.push_back(path);
                if (free_idx >= next_carrier_index) next_carrier_index = free_idx + 1;
              }
            }
          }
        }
      }

      // Carrier reaping: periodically close carriers that are clearly worse than their peers.
      // Two criteria (either triggers a reap):
      //   1. RTT outlier: last_rtt_ns > 3× median AND > 1s (stalled on client→server path).
      //   2. Silence: no shard received from server in 10s while other carriers are active
      //      (stalled on server→client path).
      if (carriers.size() > min_carriers_floor && now - last_reap_ns >= reap_check_interval_ns) {
        last_reap_ns = now;

        // RTT-based reap: find worst carrier and reap if it's a clear outlier.
        if (rtt_samples.size() >= 2) {
          std::vector<uint64_t> sorted = rtt_samples;
          std::sort(sorted.begin(), sorted.end());
          uint64_t median_rtt = sorted[sorted.size() / 2];
          // Find carrier with worst RTT.
          int worst_fd = -1;
          uint64_t worst_rtt = 0;
          for (auto& [fd, st] : carriers)
            if (st.last_rtt_ns > worst_rtt) { worst_rtt = st.last_rtt_ns; worst_fd = fd; }
          if (worst_fd >= 0 && worst_rtt > 5 * median_rtt && worst_rtt > very_high_rtt_ns &&
              carriers.size() > min_carriers_floor) {
            remove_carrier(worst_fd);
          }
        }

        // Silence-based reap: carrier hasn't received a shard from server in 10s while others have.
        if (carriers.size() > min_carriers_floor) {
          uint64_t latest_recv = 0;
          for (auto& [fd, st] : carriers)
            if (st.last_recv_ns > latest_recv) latest_recv = st.last_recv_ns;
          if (latest_recv + 5000000000ULL > now) {  // active server→client traffic in last 5s
            std::vector<int> to_reap;
            for (auto& [fd, st] : carriers)
              if (st.last_recv_ns > 0 && st.last_recv_ns + 10000000000ULL < now)
                to_reap.push_back(fd);
            for (int fd : to_reap) {
              if (carriers.size() <= min_carriers_floor) break;
              remove_carrier(fd);
            }
          }
        }
      }
    }

    // ── Ping / inactivity-check / RS stale-drain ────────────────────────────
    {
      const uint64_t now_p = now_ns();

      // Ping + dead-carrier detection.  Run at most once per second to avoid overhead.
      if (now_p - last_ping_check_ns >= 1000000000ULL) {
        last_ping_check_ns = now_p;
        static constexpr uint64_t PING_IDLE_NS = 15000000000ULL;  // 15 s
        static constexpr uint64_t DEAD_IDLE_NS = 20000000000ULL;  // 20 s
        static constexpr uint64_t GRACE_NS     =  5000000000ULL;  //  5 s connect grace
        std::vector<int> to_kill;
        for (auto& [cfd, cs] : carriers) {
          if (cs.connecting) continue;
          if (now_p - cs.connect_ns < GRACE_NS) continue;
          // Use the later of connect_ns and last_recv_ns as "last activity".
          uint64_t last_activity = std::max(cs.connect_ns, cs.last_recv_ns);
          if (now_p - last_activity > DEAD_IDLE_NS) {
            to_kill.push_back(cfd);
          } else if (cs.write_buf.empty()
                     && now_p - cs.last_send_ns > PING_IDLE_NS
                     && now_p - cs.last_recv_ns  > PING_IDLE_NS) {
            // Truly idle: send a keepalive ping.
            packet_io::append_ping(cs.write_buf, next_send_id);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
        }
        for (int cfd : to_kill)
          remove_carrier(cfd);

        // Update global receive timestamp from all live carriers.
        for (auto& [cfd, cs] : carriers)
          if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

        // Global idle timeout: if nothing has been received from the server for
        // 1 min 50 s the connection is dead; exit so the SSH client gets a clean EOF.
        static constexpr uint64_t CLIENT_GLOBAL_IDLE_NS = 110000000000ULL;  // 1 min 50 s
        if (now_p - last_global_recv_ns > CLIENT_GLOBAL_IDLE_NS)
          running = false;
      }

      // Timeout-based retransmit: if a send has been unACK'd for > 3s AND we have
      // alive carriers, re-encode and resend all its shards to one carrier.  This
      // recovers from the case where some (not all) carriers died, leaving the
      // server's rs_pending incomplete without triggering retransmit_needed.
      if (!unacked_sends.empty() && !carriers.empty()
          && now_p - last_retransmit_check_ns >= 500000000ULL) {
        last_retransmit_check_ns = now_p;
        static constexpr uint64_t RETRANSMIT_TIMEOUT_NS = 3000000000ULL;  // 3 s
        // Collect all ready (non-connecting) carriers for round-robin retransmit.
        // Spreading shards across multiple carriers means no single carrier failure
        // can wipe out a retransmit attempt.
        std::vector<int> rt_carriers;
        for (auto& [cfd, cs] : carriers)
          if (!cs.connecting) rt_carriers.push_back(cfd);
        if (!rt_carriers.empty()) {
          unsigned rt_idx = 0;  // round-robin index across rt_carriers
          for (auto& [uid, ui] : unacked_sends) {
            if (ui.send_ns == 0 || now_p - ui.send_ns < RETRANSMIT_TIMEOUT_NS) continue;
            if (ui.is_small) {
              int cfd = rt_carriers[rt_idx % rt_carriers.size()];
              packet_io::append_small(carriers[cfd].write_buf, uid, ui.data.data(), ui.data.size());
              ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
              rt_idx++;
            } else {
              std::vector<const uint8_t*> dptrs(ui.k);
              for (unsigned si = 0; si < ui.k; ++si)
                dptrs[si] = ui.data.data() + si * ui.block_size;
              unsigned m2 = ui.n - ui.k;
              std::vector<std::vector<uint8_t>> par2(m2, std::vector<uint8_t>(ui.block_size));
              std::vector<uint8_t*> pptrs2(m2);
              for (unsigned si = 0; si < m2; ++si) pptrs2[si] = par2[si].data();
              reed_solomon::encode(ui.k, m2, dptrs.data(), pptrs2.data(), ui.block_size);
              std::set<int> touched;
              for (unsigned si = 0; si < ui.n; ++si) {
                int cfd = rt_carriers[(rt_idx + si) % rt_carriers.size()];
                const uint8_t* shard = (si < ui.k)
                    ? (ui.data.data() + si * ui.block_size)
                    : par2[si - ui.k].data();
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
            // Reset send_ns so we don't retransmit this group again for another 3 s.
            ui.send_ns = now_p;
          }
        }
      }

      // ── Debug: periodic state dump ────────────────────────────────────────
      {
        static FILE* cdbgf = fopen("/tmp/ssh-oll-cli-state.log","a");
        if (cdbgf) {
          fprintf(cdbgf,"[cli] carriers=%zu unacked=%zu reassembly=%zu rs_pending=%zu next_deliver_id=%llu stdout_buf=%zu\n",
                  carriers.size(), unacked_sends.size(), reassembly.size(), rs_pending.size(),
                  (unsigned long long)next_deliver_id, stdout_buf.size());
          if (!rs_pending.empty()) {
            auto it = rs_pending.begin();
            fprintf(cdbgf,"  first rs_pending id=%llu shards=%zu k=%u n=%u\n",
                    (unsigned long long)it->first, it->second.shards.size(), it->second.k, it->second.n);
          }
          fflush(cdbgf);
        }
      }

      // RS stale-group drain: safety net for RS groups that can never complete
      // (e.g., all shards were on carriers that died before the retransmit arrived).
      // After 10 s, drop the incomplete group and advance next_deliver_id past the
      // gap so that later groups can be delivered.
      if (now_p - last_rs_drain_ns >= 1000000000ULL) {
        last_rs_drain_ns = now_p;
        static constexpr uint64_t RS_STALE_NS = 10000000000ULL;  // 10 s
        // Collect IDs that are actually being erased (had partial shards but timed out).
        // We must only gap-jump past IDs that were genuinely stale — not past IDs that
        // simply haven't received any shard yet (e.g. a SMALL arrived before the RS shard).
        std::vector<uint64_t> drained_ids;
        for (auto it = rs_pending.begin(); it != rs_pending.end(); ) {
          if (it->second.first_recv_ns > 0 && now_p - it->second.first_recv_ns > RS_STALE_NS) {
            drained_ids.push_back(it->first);
            it = rs_pending.erase(it);
          } else
            ++it;
        }
        // Build a set of drained IDs for O(1) lookup in the loop below.
        std::set<uint64_t> drained_set(drained_ids.begin(), drained_ids.end());
        // Advance next_deliver_id past any gaps left by the drain, delivering
        // any reassembly entries that were previously blocked behind them.
        //
        // Gap-jump rules (to avoid the RS+SMALL-split race):
        //  1. Always jump a gap that was explicitly stale-drained (partial shards timed out).
        //  2. Always jump when all carriers are dead (shards can never arrive).
        //  3. Jump a gap that has been continuously present for > RS_STALE_NS —
        //     this covers RS groups where NO shard ever arrived (e.g., carrier
        //     died before delivering any shard) while giving enough time for
        //     retransmission to succeed before we give up.
        //  Never jump a gap that just appeared (out-of-order SMALL/RS race).
        while (true) {
          auto ra = reassembly.find(next_deliver_id);
          if (ra != reassembly.end()) {
            recv_cb.on_deliver(-1, next_deliver_id, ra->second.data(), ra->second.size());
            reassembly.erase(ra);
            next_deliver_id++;
            next_deliver_id_stuck_since_ns = 0;  // gap resolved
          } else if (rs_pending.count(next_deliver_id)) {
            next_deliver_id_stuck_since_ns = 0;  // waiting normally, not stuck
            break;
          } else {
            // Gap: next_deliver_id is absent from both reassembly and rs_pending.
            bool has_higher = !reassembly.empty() || !rs_pending.empty();
            if (!has_higher) {
              next_deliver_id_stuck_since_ns = 0;
              break;
            }
            bool explicitly_drained = drained_set.count(next_deliver_id) > 0;
            bool no_carriers        = carriers.empty();
            bool gap_timed_out      = (next_deliver_id_stuck_since_ns > 0 &&
                                       now_p - next_deliver_id_stuck_since_ns >= RS_STALE_NS);
            if (explicitly_drained || no_carriers || gap_timed_out) {
              uint64_t nxt = UINT64_MAX;
              if (!reassembly.empty())  nxt = std::min(nxt, reassembly.begin()->first);
              if (!rs_pending.empty())  nxt = std::min(nxt, rs_pending.begin()->first);
              if (nxt > next_deliver_id && nxt < UINT64_MAX) {
                next_deliver_id = nxt;
                next_deliver_id_stuck_since_ns = 0;
              } else {
                break;
              }
            } else {
              // Gap just appeared or retransmit still in flight — start/continue timer.
              if (next_deliver_id_stuck_since_ns == 0)
                next_deliver_id_stuck_since_ns = now_p;
              break;
            }
          }
        }
      }
    }

    // ── Unconditional floor maintenance ─────────────────────────────────────
    // Always try to keep at least min_carriers_floor connections alive,
    // regardless of auto_adapt mode.  This also handles the case where ALL
    // carriers have died: the auto_adapt block above is skipped when
    // carriers.empty(), so we need a separate path here.
    {
      const uint64_t now_f = now_ns();
      // Use a faster re-add interval when critically low on carriers.
      const uint64_t floor_interval = carriers.empty()
                                        ? 50000000ULL          // 50 ms when all are gone
                                        : add_carrier_interval_ns;  // 100 ms otherwise
      if (carriers.size() < min_carriers_floor
          && now_f - last_add_carrier_ns >= floor_interval) {
        last_add_carrier_ns = now_f;
        if (!args.unix_socket_connection.empty()) {
          // Unix-socket mode: just dial a fresh connection.
          if (carriers.size() < max_connections) {
            int fd = connect_unix(socket_path);
            { static FILE* cef = fopen("/tmp/ssh-oll-cli-reconnect.log","a");
              if(cef){ fprintf(cef,"[floor-add t=%llu carriers=%zu fd=%d errno=%d]\n",
                       (unsigned long long)(now_ns()/1000000ULL),carriers.size(),fd,fd<0?errno:0); fflush(cef); } }
            if (fd >= 0) {
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0)
                carriers[fd].connecting = true;
              else
                close(fd);
            }
          }
        } else if (pending_carrier_paths.empty()) {
          // SSH mode: reuse a free index so we never permanently exhaust slots.
          unsigned free_idx = find_free_ssh_index();
          if (free_idx < max_connections) {
            std::string path = client_dir + "/" + std::to_string(free_idx);
            pid_t pid = fork();
            if (pid == 0) {
              std::string spec = path + ":" + socket_path;
              const char* argv[] = { "ssh", "-N", "-o", "ExitOnForwardFailure=yes",
                                     "-L", spec.c_str(), args.lossy_ssh_host.c_str(), nullptr };
              execvp("ssh", const_cast<char* const*>(argv));
              _exit(127);
            }
            if (pid > 0) {
              ssh_pids.push_back(pid);
              pending_carrier_paths.push_back(path);
              if (free_idx >= next_carrier_index) next_carrier_index = free_idx + 1;
            }
          }
        }
      }
    }

    // ── Re-arm stdin if it was throttled ────────────────────────────────────
    // Re-register STDIN with epoll once we have carriers again (can send data)
    // or when stdin_buf drains below the throttle threshold (need more data).
    if (!stdin_in_epoll && !stdin_eof &&
        (!carriers.empty() || stdin_buf.size() < STDIN_THROTTLE_BYTES)) {
      ev.events = EPOLLIN;
      ev.data.fd = STDIN_FILENO;
      if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == 0)
        stdin_in_epoll = true;
    }

    // ── Exit conditions ──────────────────────────────────────────────────────
    // Normal completion: stdin done and nothing left in flight.
    if (stdin_eof && stdin_buf.empty() && reassembly.empty() && stdout_buf.empty() && rs_pending.empty()) {
      { FILE* dbgf = fopen("/tmp/ssh-oll-client-exit.log","a"); if(dbgf){fprintf(dbgf,"stdin_eof normal exit: stdin_buf=%zu reassembly=%zu rs_pending=%zu\n",stdin_buf.size(),reassembly.size(),rs_pending.size());fclose(dbgf);} }
      running = false;
    }
    // Fatal: no carriers AND we cannot reconnect AND nothing in flight.
    // In unix-socket mode we can always reconnect, so we never exit here.
    // In SSH mode we give up only when every index is occupied or being tried.
    if (carriers.empty() && pending_carrier_paths.empty()
        && reassembly.empty() && stdout_buf.empty() && rs_pending.empty()) {
      bool can_reconnect;
      if (!args.unix_socket_connection.empty()) {
        can_reconnect = true;  // server socket is always there; keep retrying
      } else {
        can_reconnect = (find_free_ssh_index() < max_connections);
      }
      if (!can_reconnect)
        running = false;
    }
  }

  for (auto& [fd, _] : carriers)
    close(fd);
  close(epfd);
  if (!args.unix_socket_connection.empty()) {
    // Direct Unix socket mode: no SSH processes or client_dir to clean up
  } else {
    for (pid_t p : ssh_pids)
      kill(p, SIGTERM);
    for (unsigned i = 0; i < next_carrier_index; ++i)
      unlink((client_dir + "/" + std::to_string(i)).c_str());
    rmdir(client_dir.c_str());
  }
  return 0;
}

}  // namespace ssholl
