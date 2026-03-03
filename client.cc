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
#include <signal.h>
#include <string>
#include <vector>
#include <sys/epoll.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>

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

// Remove all entries in dir_path (socket files) and the directory itself.
// Retries a few times to handle SSH processes that may not have released sockets yet.
void remove_client_dir(const std::string& dir_path) {
  for (int attempt = 0; attempt < 5; ++attempt) {
    DIR* d = opendir(dir_path.c_str());
    if (d) {
      struct dirent* ent;
      while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
          continue;
        std::string p = dir_path + "/" + ent->d_name;
        unlink(p.c_str());
      }
      closedir(d);
    }
    if (rmdir(dir_path.c_str()) == 0)
      return;
    if (errno != ENOTEMPTY && errno != EEXIST)
      return;
    usleep(50000);  // 50 ms before retry
  }
}

// Launch server on remote host; read one line (socket path) from stdout. Returns path or empty on failure.
std::string launch_server(const Args& args) {
  int pipefd[2];
#ifdef __linux__
  if (pipe2(pipefd, O_CLOEXEC) < 0) {
#else
  if (pipe(pipefd) < 0) {
#endif
    std::perror("ssh-oll client: pipe");
    return {};
  }
#ifndef __linux__
  fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
  fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
#endif
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
    // Redirect stdin to /dev/null. The launch ssh inherits our stdin (the real SSH stream).
    // If it forwarded that to the remote, it would consume and lose the SSH version string
    // before our main loop can forward it—sshd would respond "Invalid SSH identification string".
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
    std::string port_str = std::to_string(args.remote_port);
    std::vector<const char*> argv_vec;
    argv_vec.push_back("ssh");
    argv_vec.push_back("-n");
    argv_vec.push_back(args.lossy_ssh_host.c_str());
    argv_vec.push_back(args.config.path_on_server.c_str());
    argv_vec.push_back("--server");
    if (args.debug)
      argv_vec.push_back("--debug");
    argv_vec.push_back(args.remote_hostname.c_str());
    argv_vec.push_back(port_str.c_str());
    argv_vec.push_back(nullptr);
    execvp("ssh", const_cast<char* const*>(argv_vec.data()));
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

// Set by SIGINT/SIGTERM/SIGHUP handler; causes the main event loop to exit cleanly.
static volatile sig_atomic_t g_shutdown_requested = 0;
static void shutdown_handler(int) { g_shutdown_requested = 1; }

}  // namespace

int run_client(const Args& args) {
  // Catch SIGINT (Ctrl-C), SIGTERM, and SIGHUP so the cleanup path (kill SSH children,
  // unlink sockets) runs. SIGHUP is sent when the SSH session closes (e.g. user
  // disconnects); without a handler, the process would be killed before cleanup.
  {
    struct sigaction sa{};
    sa.sa_handler = shutdown_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP,  &sa, nullptr);
  }

  std::string socket_path;
  std::string client_dir;
  std::map<unsigned, pid_t> ssh_idx_to_pid;  // SSH slot index -> PID
  std::vector<pid_t> pids_to_reap;           // SIGTERMed but not yet waitpid'd

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

    for (unsigned i = 0; i < N; ++i) {
      std::string local_path = client_dir + "/" + std::to_string(i);
      pid_t pid = fork();
      if (pid < 0) {
        std::perror("ssh-oll: fork");
        for (auto& [_, p] : ssh_idx_to_pid) kill(p, SIGTERM);
        for (auto& [_, p] : ssh_idx_to_pid) waitpid(p, nullptr, 0);
        remove_client_dir(client_dir);
        return 1;
      }
      if (pid == 0) {
#ifdef __linux__
        // Exit automatically if the parent (ssh-oll) dies for any reason.
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
        // Redirect stdout and stderr to /dev/null. stdout must never be written to—
        // the carrier inherits the ProxyCommand stdout; any output would corrupt the SSH stream.
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
          dup2(dn, STDOUT_FILENO);
          dup2(dn, STDERR_FILENO);
          close(dn);
        }
        std::string spec = local_path + ":" + socket_path;
        const char* argv[] = {
          "ssh", "-n", "-N",
          "-o", "ExitOnForwardFailure=yes",
          // "-o", "ServerAliveInterval=10",
          // "-o", "ServerAliveCountMax=3",
          "-L", spec.c_str(),
          args.lossy_ssh_host.c_str(), nullptr
        };
        execvp("ssh", const_cast<char* const*>(argv));
        _exit(127);
      }
      ssh_idx_to_pid[i] = pid;
    }

    // Wait for SSH to create sockets and accept connections.
    // On high-latency links, each ssh -L can take 10+ seconds to establish.
    for (int wait_ms = 0; wait_ms < 30000; wait_ms += 200) {
      usleep(200 * 1000);
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
      for (auto& [_, p] : ssh_idx_to_pid) kill(p, SIGTERM);
      for (auto& [_, p] : ssh_idx_to_pid) waitpid(p, nullptr, 0);
      remove_client_dir(client_dir);
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
  uint64_t last_redundancy_pressure_add_ns = 0;  // rate-limit: at most one add per 60s from rs ratio
  uint64_t last_rs_pending_pressure_add_ns = 0;  // rate-limit: add every 10s when rs_pending is very high
  // RTT outlier threshold: carrier must be both 5× median AND above this absolute. Scales with link.
  // Fraction-slow thresholds (mirrors server.cc constants).
  // Shard-spread thresholds: what fraction of RS groups are "struggling" (spread > 2× floor).
  static constexpr float kFractionSlowIncreaseFast   = 0.05f;  // >5% struggling → big increase
  static constexpr float kFractionSlowIncreaseMedium = 0.01f;  // >1% struggling → medium increase
  static constexpr float kFractionSlowDecrease       = 0.002f; // <0.2% struggling → decrease
  static constexpr size_t kMinSamplesForAdapt = 20;            // need ≥20 RS groups decoded
  uint64_t backpressure_write_threshold = 150 * effective_max_packet;  // updated when effective_max_packet changes
  float last_sent_rs_redundancy = -1.0f;   // sentinel so we send initial config when auto
  unsigned last_sent_small_packet_redundancy = 0;
  uint64_t server_reported_max_rtt_ns = 0;  // server→client path RTT from SERVER_METRICS
  uint32_t server_rs_pending_count = 0;     // c2s RS groups server is waiting to decode (from SERVER_METRICS)
  // s2c metrics (measured locally on decoded RS groups from server).
  std::deque<uint64_t> s2c_shard_spread_ns;
  std::deque<uint64_t> s2c_gap_final_ns;
  std::deque<uint64_t> s2c_extra_shard_gap_ns;
  // c2s metrics reported back by server in SERVER_METRICS.
  uint64_t c2s_avg_shard_spread_ns  = 0;
  uint64_t c2s_avg_extra_shard_gap_ns = 0;
  static constexpr size_t kMaxSpreadSamples = 100;
  // Shared map for recently decoded RS groups (to time extra shards).
  std::map<uint64_t, uint64_t> recently_decoded_ns;
  // min carriers to keep during reaping (never drop below the initial configured count)
  const unsigned min_carriers_floor = std::max(2u, args.config.connections);
  uint64_t last_reap_ns = 0;
  const uint64_t reap_check_interval_ns = 2000 * 1000000ULL;

  // RTT-scaled timeouts: use observed latency so low-latency links get tighter timeouts,
  // high-latency links get longer. Cold start uses rtt_hint_ms or 5 s conservative default.
  auto get_effective_rtt_ns = [&]() -> uint64_t {
    uint64_t hint_ns = static_cast<uint64_t>(args.config.rtt_hint_ms) * 1000000ULL;
    if (recent_rtt_ns.size() >= 3) {
      std::vector<uint64_t> sorted(recent_rtt_ns.begin(), recent_rtt_ns.end());
      std::sort(sorted.begin(), sorted.end());
      uint64_t p90 = sorted[static_cast<size_t>(sorted.size() * 0.9)];
      uint64_t observed = std::max(p90, server_reported_max_rtt_ns);
      uint64_t fallback = hint_ns ? hint_ns : 5000000000ULL;
      return std::max(observed, fallback);
    }
    return hint_ns ? hint_ns : 5000000000ULL;  // 5 s conservative when unknown
  };
  auto scaled_ns = [&](unsigned mult, uint64_t min_ns, uint64_t max_ns) -> uint64_t {
    uint64_t rtt = get_effective_rtt_ns();
    uint64_t v = static_cast<uint64_t>(mult) * rtt;
    if (v < min_ns) return min_ns;
    if (v > max_ns) return max_ns;
    return v;
  };

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

  // Open per-process debug log if --debug was passed.
  FILE* dbg = nullptr;
  if (args.debug) {
    char dbg_path[128];
    snprintf(dbg_path, sizeof dbg_path, "/tmp/ssh-oll-client-%d.log", (int)getpid());
    dbg = fopen(dbg_path, "w");
  }

  struct epoll_event ev{};

  // Maps each carrier fd to its SSH directory index (SSH mode only).
  // Declared here so the initial connect loop and remove_carrier lambda can both use it.
  std::map<int, unsigned> fd_to_ssh_index;

  ev.events = EPOLLIN;
  ev.data.fd = STDIN_FILENO;
  epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

  for (unsigned i = 0; i < N; ++i) {
    std::string path = args.unix_socket_connection.empty() ? (client_dir + "/" + std::to_string(i)) : socket_path;
    int fd = connect_unix(path);
    if (fd < 0) {
      // SSH for this slot isn't ready yet; queue it so the main loop picks it up.
      if (args.unix_socket_connection.empty())
        pending_carrier_paths.push_back(path);
      continue;
    }
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
      carriers[fd].connecting = true;
      if (args.unix_socket_connection.empty())
        fd_to_ssh_index[fd] = i;  // correct slot→fd mapping
    } else {
      close(fd);
    }
  }

  if (carriers.empty()) {
    std::fprintf(stderr, "ssh-oll: could not connect any carrier to server\n");
    close(epfd);
    if (args.unix_socket_connection.empty()) {
      for (auto& [_, p] : ssh_idx_to_pid) kill(p, SIGTERM);
      for (auto& [_, p] : ssh_idx_to_pid) waitpid(p, nullptr, 0);
      remove_client_dir(client_dir);
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

  // Return carrier fds sorted by last_rtt_ns ascending (fastest first).
  // Carriers with no RTT sample yet (last_rtt_ns == 0) sort last.
  auto fastest_carriers = [&]() -> std::vector<int> {
    std::vector<std::pair<uint64_t, int>> by_rtt;
    by_rtt.reserve(carriers.size());
    for (auto& [fd, cs] : carriers)
      by_rtt.push_back({cs.last_rtt_ns == 0 ? UINT64_MAX : cs.last_rtt_ns, fd});
    std::sort(by_rtt.begin(), by_rtt.end());
    std::vector<int> result;
    result.reserve(by_rtt.size());
    for (auto& [rtt, fd] : by_rtt) result.push_back(fd);
    return result;
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
  recv_cb.on_rs_decode = [&](unsigned /*shards_received*/, unsigned /*n*/,
                              uint64_t spread_ns, uint64_t gap_final_ns) {
    s2c_shard_spread_ns.push_back(spread_ns);
    while (s2c_shard_spread_ns.size() > kMaxSpreadSamples) s2c_shard_spread_ns.pop_front();
    s2c_gap_final_ns.push_back(gap_final_ns);
    while (s2c_gap_final_ns.size() > kMaxSpreadSamples) s2c_gap_final_ns.pop_front();
  };
  recv_cb.on_rs_extra_shard = [&](uint64_t gap_ns) {
    s2c_extra_shard_gap_ns.push_back(gap_ns);
    while (s2c_extra_shard_gap_ns.size() > kMaxSpreadSamples) s2c_extra_shard_gap_ns.pop_front();
  };
  recv_cb.on_server_metrics = [&](uint64_t max_rtt_ns, uint64_t avg_spread_ns,
                                   uint64_t avg_extra_gap_ns, uint32_t rs_pending_count) {
    if (max_rtt_ns < 10000000000ULL)
      server_reported_max_rtt_ns = max_rtt_ns;
    c2s_avg_shard_spread_ns   = avg_spread_ns;
    c2s_avg_extra_shard_gap_ns = avg_extra_gap_ns;
    server_rs_pending_count   = rs_pending_count;
  };
  recv_cb.on_server_config = [&](const PacketServerConfig& psc) {
    has_server_config = true;
    effective_max_packet = std::min(static_cast<size_t>(psc.packet_size), static_cast<size_t>(MAX_PACKET_PAYLOAD));
    if (effective_max_packet == 0) effective_max_packet = 800;
    effective_rs_redundancy = (psc.reed_solomon_redundancy >= 0.1f) ? psc.reed_solomon_redundancy : 0.1f;
    effective_small_packet_redundancy = (psc.small_packet_redundancy != 0) ? psc.small_packet_redundancy : 2u;
    backpressure_write_threshold = 150 * effective_max_packet;
  };
  recv_cb.on_ping = [&](int fd, uint64_t id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_pong(it->second.write_buf, id);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
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
    return packet_io::process_carrier_read(fd, s, reassembly, rs_pending, recently_decoded_ns, next_deliver_id, recv_cb);
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

  // fd_to_ssh_index is declared and populated above in the initial connect loop.

  // Centralised carrier removal: closes the fd, removes from epoll, cleans up maps.
  // In SSH mode: kills the owning SSH process and unlinks its socket file so the
  // slot can be reused cleanly.  Flags retransmit when the last carrier is lost.
  auto remove_carrier = [&](int fd) {
    if (dbg) fprintf(dbg, "[carrier-remove t=%llu fd=%d total=%zu]\n",
                     (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1);
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    carriers.erase(fd);
    carrier_pending_acks.erase(fd);
    if (!args.unix_socket_connection.empty()) {
      if (carriers.empty() && !unacked_sends.empty())
        retransmit_needed = true;
      return;
    }
    // SSH mode: kill the SSH process that owns this carrier slot so it doesn't
    // linger as an orphan, and unlink its socket file so the index is reusable.
    auto idx_it = fd_to_ssh_index.find(fd);
    if (idx_it != fd_to_ssh_index.end()) {
      unsigned idx = idx_it->second;
      auto pid_it = ssh_idx_to_pid.find(idx);
      if (pid_it != ssh_idx_to_pid.end()) {
        kill(pid_it->second, SIGTERM);
        pids_to_reap.push_back(pid_it->second);
        ssh_idx_to_pid.erase(pid_it);
      }
      unlink((client_dir + "/" + std::to_string(idx)).c_str());
      fd_to_ssh_index.erase(idx_it);
    }
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
    // Also exclude slots that have a live SSH process (prevents double-launching when a
    // carrier's connect failed/was delayed and the process is still starting up).
    for (auto& [idx, _] : ssh_idx_to_pid) in_use.insert(idx);
    for (unsigned i = 0; i < max_connections; ++i)
      if (!in_use.count(i)) return i;
    return max_connections;
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    if (g_shutdown_requested) break;

    // Bound epoll_wait so we can run periodic tasks (ping, inactivity check, RS drain)
    // promptly even when the link is idle.  500 ms ensures carrier death is detected
    // within one epoll cycle even if the kernel-level EOF event is delayed on a
    // unix-socket carrier (observed: close() on proxy side takes up to one poll
    // cycle to propagate on some Linux configurations).
    int epoll_timeout_ms = 500;
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
      if (errno == EINTR) {
        // Signal interrupted the wait; re-check shutdown flag at the top of the loop.
        continue;
      }
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
          float rs_frac = args.config.auto_adapt ? effective_rs_redundancy : args.config.rs_redundancy;
          // n = carriers: one shard per carrier so any k of them suffice to decode.
          // k = floor(n / (1 + rs_frac)): max data shards within the carrier budget.
          unsigned n_carriers = static_cast<unsigned>(std::min(carriers.size(), static_cast<size_t>(255)));
          unsigned k = std::max(1u, static_cast<unsigned>(
              static_cast<float>(n_carriers) / (1.0f + rs_frac)));
          k = static_cast<unsigned>(std::min(static_cast<size_t>(k),
                                             stdin_buf.size() / block_size));
          if (k == 0) break;
          unsigned m = std::max(1u, static_cast<unsigned>(k * rs_frac + 0.5f));
          // Cap n to n_carriers so every shard goes on a different carrier.
          unsigned n = std::min(k + m, n_carriers);
          m = n - k;
          if (m == 0) {
            // Single carrier: can't do RS (need m>=1). Send block as SMALL.
            size_t chunk = block_size;
            UnackedItem ui;
            ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
            ui.is_small = true;
            ui.send_ns = now_ns();
            unacked_sends[next_send_id] = std::move(ui);
            auto it = carriers.begin();
            queue_to_carrier(it->first, stdin_buf.data(), chunk, false);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = it->first;
            epoll_ctl(epfd, EPOLL_CTL_MOD, it->first, &ev);
            next_send_id++;
            stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + chunk);
            continue;
          }
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
        // Send any remainder smaller than one block as SMALL (no Reed–Solomon).
        // Use the fastest carriers (by RTT) so the copy most likely to arrive first
        // does so as quickly as possible — no erasure coding fallback here.
        if (!stdin_buf.empty() && stdin_buf.size() < effective_max_packet && !carriers.empty()) {
          size_t chunk = stdin_buf.size();
          const unsigned n_copies = std::max(1u, std::min(static_cast<unsigned>(carriers.size()),
                                                           effective_small_packet_redundancy));
          {
            UnackedItem ui;
            ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
            ui.is_small = true;
            ui.send_ns = now_ns();
            unacked_sends[next_send_id] = std::move(ui);
          }
          auto fast = fastest_carriers();
          for (unsigned i = 0; i < n_copies; ++i) {
            int cfd = fast[i % fast.size()];
            queue_to_carrier(cfd, stdin_buf.data(), chunk, n_copies > 1);
            ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
          if (n_copies > 1) next_send_id++;
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
                        : par[si - ui.k].data();  // m>0 ensures par has parity when si>=k
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
        if (small_packet) {
          auto fast = fastest_carriers();
          for (unsigned i = 0; i < n_copies; ++i) {
            int cfd = fast[i % fast.size()];
            queue_to_carrier(cfd, stdin_buf.data(), chunk, n_copies > 1);
            ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
        } else {
          auto it = carriers.begin();
          std::advance(it, next_carrier % carriers.size());
          queue_to_carrier(it->first, stdin_buf.data(), chunk, false);
          ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = it->first;
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

    // Try to complete pending SSH carrier connections.
    for (auto it = pending_carrier_paths.begin(); it != pending_carrier_paths.end(); ) {
      std::string prefix = client_dir + "/";
      unsigned slot = (it->size() > prefix.size())
          ? static_cast<unsigned>(std::stoul(it->substr(prefix.size()))) : 0;
      // If the SSH process for this slot has exited on its own (e.g. auth failure,
      // ExitOnForwardFailure), remove the entry so the slot is freed for relaunch.
      if (auto pit = ssh_idx_to_pid.find(slot); pit != ssh_idx_to_pid.end()) {
        if (waitpid(pit->second, nullptr, WNOHANG) != 0) {
          // Process exited; clean up and let find_free_ssh_index reclaim this slot.
          ssh_idx_to_pid.erase(pit);
          unlink(it->c_str());
          it = pending_carrier_paths.erase(it);
          continue;
        }
      }
      if (access(it->c_str(), F_OK) != 0) { ++it; continue; }
      int fd = connect_unix(*it);
      if (fd >= 0) {
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
          carriers[fd].connecting = true;
          // Record SSH index for later recycling.
          if (it->size() > prefix.size())
            fd_to_ssh_index[fd] = slot;
        } else {
          close(fd);
        }
        it = pending_carrier_paths.erase(it);  // success: remove from pending
      } else {
        ++it;  // transient failure (SSH still starting): retry next iteration
      }
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
      if (now - last_adapt_ns >= adapt_interval_ns
          && s2c_shard_spread_ns.size() >= kMinSamplesForAdapt) {
        last_adapt_ns = now;

        static constexpr uint64_t kSpreadIncreaseThresholdNs   = 2000000ULL;  // 2 ms
        static constexpr uint64_t kExtraGapDecreaseThresholdNs = 100000ULL;   // 0.1 ms

        // --- Increase signal (s2c): spread > 2ms AND gap_final > half the spread ---
        size_t n_struggling_s2c = 0;
        for (size_t i = 0; i < s2c_shard_spread_ns.size(); ++i) {
          uint64_t spread = s2c_shard_spread_ns[i];
          uint64_t gfinal = (i < s2c_gap_final_ns.size()) ? s2c_gap_final_ns[i] : 0;
          if (spread > kSpreadIncreaseThresholdNs && gfinal > spread / 2)
            n_struggling_s2c++;
        }
        float s2c_struggling = static_cast<float>(n_struggling_s2c)
                               / static_cast<float>(s2c_shard_spread_ns.size());

        // --- Increase signal (c2s, from server report): treat non-trivial avg spread
        //     as evidence the c2s path is under the same kind of pressure.
        float c2s_struggling = (c2s_avg_shard_spread_ns > kSpreadIncreaseThresholdNs)
                                ? kFractionSlowIncreaseFast * 2.0f : 0.0f;

        float fraction_struggling = std::max(s2c_struggling, c2s_struggling);

        // --- Decrease signal: extra shard (k+1) arrives within 0.1ms of k-th ---
        // Use the better of both directions: if either direction shows easy headroom,
        // the link is likely healthy enough to reduce parity slightly.
        bool can_decrease_s2c = false;
        if (s2c_extra_shard_gap_ns.size() >= 10) {
          std::vector<uint64_t> sg(s2c_extra_shard_gap_ns.begin(), s2c_extra_shard_gap_ns.end());
          std::sort(sg.begin(), sg.end());
          can_decrease_s2c = sg[(sg.size() * 9) / 10] < kExtraGapDecreaseThresholdNs;
        }
        bool can_decrease_c2s = (c2s_avg_extra_shard_gap_ns > 0
                                  && c2s_avg_extra_shard_gap_ns < kExtraGapDecreaseThresholdNs);
        bool can_decrease = can_decrease_s2c || can_decrease_c2s;

        if (fraction_struggling > kFractionSlowIncreaseFast) {
          effective_rs_redundancy = std::min(2.0f, effective_rs_redundancy + 0.10f);
          effective_small_packet_redundancy = std::min(20u, effective_small_packet_redundancy + 1u);
        } else if (fraction_struggling > kFractionSlowIncreaseMedium) {
          effective_rs_redundancy = std::min(2.0f, effective_rs_redundancy + 0.05f);
        } else if (can_decrease && fraction_struggling < kFractionSlowDecrease) {
          effective_rs_redundancy = std::max(0.1f, effective_rs_redundancy - 0.02f);
          effective_small_packet_redundancy = std::max(2u, effective_small_packet_redundancy - 1u);
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

    // Ping + dead-carrier detection. Run BEFORE reap so we send PING first and give PONG
    // time to arrive before considering silence-based reap.
    {
      const uint64_t now_p = now_ns();
      if (now_p - last_ping_check_ns >= 1000000000ULL) {
        last_ping_check_ns = now_p;

        // Reap any SSH processes that have exited after receiving SIGTERM.
        if (!pids_to_reap.empty()) {
          pids_to_reap.erase(
              std::remove_if(pids_to_reap.begin(), pids_to_reap.end(),
                  [](pid_t p) { return waitpid(p, nullptr, WNOHANG) != 0; }),
              pids_to_reap.end());
        }
        if (args.unix_socket_connection.empty()) {
          std::vector<unsigned> dead_slots;
          for (auto& [idx, pid] : ssh_idx_to_pid) {
            bool active = false;
            for (auto& [fd, fi] : fd_to_ssh_index) if (fi == idx) { active = true; break; }
            if (active) continue;
            if (waitpid(pid, nullptr, WNOHANG) != 0)
              dead_slots.push_back(idx);
          }
          for (unsigned idx : dead_slots) {
            ssh_idx_to_pid.erase(idx);
            unlink((client_dir + "/" + std::to_string(idx)).c_str());
          }
        }
        uint64_t ping_idle_ns  = scaled_ns(2,  5000000000ULL, 30000000000ULL);
        uint64_t dead_idle_ns  = scaled_ns(5, 15000000000ULL, 120000000000ULL);
        uint64_t grace_ns      = scaled_ns(2,  5000000000ULL,  30000000000ULL);
        std::vector<int> to_kill;
        for (auto& [cfd, cs] : carriers) {
          if (cs.connecting) continue;
          if (now_p - cs.connect_ns < grace_ns) continue;
          uint64_t last_activity = std::max(cs.connect_ns, cs.last_recv_ns);
          if (now_p - last_activity > dead_idle_ns) {
            to_kill.push_back(cfd);
            continue;
          }
          if (cs.write_buf.empty()
              && now_p - cs.last_send_ns > ping_idle_ns
              && now_p - cs.last_recv_ns  > ping_idle_ns) {
            packet_io::append_ping(cs.write_buf, next_send_id);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
        }
        for (int cfd : to_kill)
          remove_carrier(cfd);

        for (auto& [cfd, cs] : carriers)
          if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

        uint64_t global_idle_ns = scaled_ns(12, 60000000000ULL, 300000000000ULL);
        if (now_p - last_global_recv_ns > global_idle_ns)
          running = false;
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
      // AND much worse than its peers (5× median). Threshold scales with link RTT.
      uint64_t very_high_rtt_ns = scaled_ns(3, 5000000000ULL, 30000000000ULL);
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
      // For backpressure or redundancy-pressure additions use the normal 100ms add interval.
      // Growth is capped by max_connections (user-configured, default 200).
      uint64_t add_interval = add_carrier_interval_ns;
      if (rtt_outlier)
        add_interval = reap_check_interval_ns;  // at most one add per reap cycle when replacing a stall

      // rs_pending pressure: many RS groups waiting to decode = need more carriers.
      // Client rs_pending: s2c path lossy (client waiting for server shards).
      // Server rs_pending: c2s path lossy (server waiting for client shards); reported via SERVER_METRICS.
      // On very lossy links we add every 10s so n grows and more shards have a chance to arrive.
      static constexpr size_t RS_PENDING_PRESSURE_THRESHOLD = 50;
      static constexpr uint64_t RS_PENDING_PRESSURE_ADD_INTERVAL_NS = 10 * 1000000000ULL;
      bool rs_pending_pressure = args.config.auto_adapt
                                && rs_pending.size() > RS_PENDING_PRESSURE_THRESHOLD
                                && (now - last_rs_pending_pressure_add_ns >= RS_PENDING_PRESSURE_ADD_INTERVAL_NS
                                    || last_rs_pending_pressure_add_ns == 0);
      bool server_rs_pending_pressure = args.config.auto_adapt
                                       && server_rs_pending_count > RS_PENDING_PRESSURE_THRESHOLD
                                       && (now - last_rs_pending_pressure_add_ns >= RS_PENDING_PRESSURE_ADD_INTERVAL_NS
                                           || last_rs_pending_pressure_add_ns == 0);
      bool any_rs_pending_pressure = rs_pending_pressure || server_rs_pending_pressure;
      if (any_rs_pending_pressure && add_interval > RS_PENDING_PRESSURE_ADD_INTERVAL_NS)
        add_interval = RS_PENDING_PRESSURE_ADD_INTERVAL_NS;

      if (carriers.size() < max_connections && now - last_add_carrier_ns >= add_interval) {
        // Five triggers:
        //   1. Write backlog: existing carriers can't drain fast enough.
        //   2. RTT outlier: one carrier is clearly stalled vs peers; open a replacement.
        //   3. Redundancy pressure: RS redundancy has climbed above 0.4 (link is lossy).
        //   4. rs_pending pressure: client has many s2c RS groups stuck (lossy s2c path).
        //   5. server_rs_pending pressure: server has many c2s RS groups stuck (lossy c2s path).
        static constexpr uint64_t REDUNDANCY_PRESSURE_ADD_INTERVAL_NS = 60 * 1000000000ULL;
        bool redundancy_pressure = args.config.auto_adapt
                                   && (effective_rs_redundancy > 0.4f)
                                   && (now - last_redundancy_pressure_add_ns >= REDUNDANCY_PRESSURE_ADD_INTERVAL_NS
                                       || last_redundancy_pressure_add_ns == 0);
        bool need_more = (total_write > backpressure_write_threshold)
                         || (rtt_outlier && !unacked_sends.empty())  // no replace-add when idle
                         || redundancy_pressure
                         || any_rs_pending_pressure;
        if (need_more) {
          last_add_carrier_ns = now;
          if (redundancy_pressure)
            last_redundancy_pressure_add_ns = now;
          if (any_rs_pending_pressure)
            last_rs_pending_pressure_add_ns = now;
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
#ifdef __linux__
                prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
                int dn = open("/dev/null", O_WRONLY);
                if (dn >= 0) {
                  dup2(dn, STDOUT_FILENO);
                  dup2(dn, STDERR_FILENO);
                  close(dn);
                }
                std::string spec = path + ":" + socket_path;
                const char* argv[] = {
                  "ssh", "-n", "-N",
                  "-o", "ExitOnForwardFailure=yes",
                  // "-o", "ServerAliveInterval=10",
                  // "-o", "ServerAliveCountMax=3",
                  "-L", spec.c_str(),
                  args.lossy_ssh_host.c_str(), nullptr
                };
                execvp("ssh", const_cast<char* const*>(argv));
                _exit(127);
              }
              if (pid > 0) {
                ssh_idx_to_pid[free_idx] = pid;
                pending_carrier_paths.push_back(path);
                if (free_idx >= next_carrier_index) next_carrier_index = free_idx + 1;
              }
            }
          }
        }
      }

      // Carrier reaping: periodically close carriers that are clearly worse than their peers.
      // Two criteria (either triggers a reap):
      //   1. RTT outlier: last_rtt_ns > 5× median AND > 3×RTT (stalled on client→server path).
      //   2. Silence: no shard received from server in N×RTT while other carriers are active
      //      (stalled on server→client path).
      // Skip reaping during initial handshake: when we have unacked data and few RTT samples.
      // Skip RTT outlier reap when idle: a slower carrier still works (PING/PONG keeps it alive).
      //
      // Never reap if it would bring us to the floor: require carriers.size() > min_carriers_floor + 1.
      // Add logic above starts a replacement when we have an outlier; we only reap once that
      // replacement has connected (carriers grew). This avoids briefly dropping below min.
      const bool early_handshake = (unacked_sends.size() > 0 && rtt_samples.size() < 10);
      const bool idle = unacked_sends.empty();
      const bool can_reap_without_dropping_below_min = (carriers.size() > min_carriers_floor + 1u);
      if (!early_handshake && carriers.size() > min_carriers_floor && now - last_reap_ns >= reap_check_interval_ns) {
        last_reap_ns = now;

        // RTT-based reap: find worst carrier and reap if it's a clear outlier.
        // When idle, skip—no benefit to replacing a marginally slower carrier.
        // Only reap when we have a replacement (carriers > min+1); add logic started one above.
        if (!idle && can_reap_without_dropping_below_min && rtt_samples.size() >= 2) {
          std::vector<uint64_t> sorted = rtt_samples;
          std::sort(sorted.begin(), sorted.end());
          uint64_t median_rtt = sorted[sorted.size() / 2];
          int worst_fd = -1;
          uint64_t worst_rtt = 0;
          for (auto& [fd, st] : carriers)
            if (st.last_rtt_ns > worst_rtt) { worst_rtt = st.last_rtt_ns; worst_fd = fd; }
          if (worst_fd >= 0 && worst_rtt > 5 * median_rtt && worst_rtt > very_high_rtt_ns) {
            remove_carrier(worst_fd);
          }
        }

        // Silence-based reap: carrier hasn't received in N×RTT while others have.
        // Only reap when we have headroom so a replacement can be added first if needed.
        if (can_reap_without_dropping_below_min) {
          uint64_t latest_recv = 0;
          for (auto& [fd, st] : carriers)
            if (st.last_recv_ns > latest_recv) latest_recv = st.last_recv_ns;
          uint64_t silence_reap_ns = scaled_ns(4, 20000000000ULL, 60000000000ULL);
          if (latest_recv + 5000000000ULL > now) {  // active server→client traffic in last 5s
            std::vector<int> to_reap;
            for (auto& [fd, st] : carriers)
              if (st.last_recv_ns > 0 && st.last_recv_ns + silence_reap_ns < now)
                to_reap.push_back(fd);
            for (int fd : to_reap) {
              if (carriers.size() <= min_carriers_floor + 1u) break;  // stop before we'd hit floor
              remove_carrier(fd);
            }
          }
        }
      }
    }

    // ── Timeout-based retransmit / RS stale-drain ────────────────────────────
    {
      const uint64_t now_p = now_ns();

      // Timeout-based retransmit: if a send has been unACK'd AND we have alive carriers, resend.
      // When we have no RTT samples (cold start), use 2.5 s so we retransmit aggressively.
      // Once RTT is known, use 4×RTT so we don't retransmit before the original could arrive.
      if (!unacked_sends.empty() && !carriers.empty()
          && now_p - last_retransmit_check_ns >= 500000000ULL) {
        last_retransmit_check_ns = now_p;
        uint64_t retransmit_timeout_ns = (recent_rtt_ns.size() >= 2)
            ? scaled_ns(4, 2000000000ULL, 60000000000ULL)
            : 2500000000ULL;  // 2.5 s when no RTT known
        // Collect all ready (non-connecting) carriers for round-robin retransmit.
        // Spreading shards across multiple carriers means no single carrier failure
        // can wipe out a retransmit attempt.
        std::vector<int> rt_carriers;
        for (auto& [cfd, cs] : carriers)
          if (!cs.connecting) rt_carriers.push_back(cfd);
        if (!rt_carriers.empty()) {
          unsigned rt_idx = 0;
          const unsigned small_rt_copies = std::max(1u, std::min(3u, static_cast<unsigned>(rt_carriers.size())));
          for (auto& [uid, ui] : unacked_sends) {
            if (ui.send_ns == 0 || now_p - ui.send_ns < retransmit_timeout_ns) continue;
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
              for (unsigned si = 0; si < ui.k; ++si)
                dptrs[si] = ui.data.data() + si * ui.block_size;
              unsigned m2 = ui.n - ui.k;
              std::vector<std::vector<uint8_t>> par2;
              std::vector<uint8_t*> pptrs2;
              if (m2 > 0) {
                par2.resize(m2, std::vector<uint8_t>(ui.block_size));
                pptrs2.resize(m2);
                for (unsigned si = 0; si < m2; ++si) pptrs2[si] = par2[si].data();
                reed_solomon::encode(ui.k, m2, dptrs.data(), pptrs2.data(), ui.block_size);
              }
              std::set<int> touched;
              for (unsigned si = 0; si < ui.n; ++si) {
                int cfd = rt_carriers[(rt_idx + si) % rt_carriers.size()];
                const uint8_t* shard = (si < ui.k)
                    ? (ui.data.data() + si * ui.block_size)
                    : par2[si - ui.k].data();  // m2>0 when si>=k
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
      if (dbg) {
        size_t unacked_bytes = 0;
        for (const auto& [_, ui] : unacked_sends) unacked_bytes += ui.data.size();
        fprintf(dbg, "[cli] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=%zu next_deliver_id=%llu stdout_buf=%zu\n",
                carriers.size(), unacked_sends.size(), unacked_bytes, reassembly.size(), rs_pending.size(),
                (unsigned long long)next_deliver_id, stdout_buf.size());
        fprintf(dbg, "  rs_redundancy=%.2f small_packet_copies=%u server_rs_pending=%u\n",
                effective_rs_redundancy, effective_small_packet_redundancy, server_rs_pending_count);
        if (!rs_pending.empty()) {
          auto it = rs_pending.begin();
          fprintf(dbg, "  first rs_pending id=%llu shards=%zu k=%u n=%u\n",
                  (unsigned long long)it->first, it->second.shards.size(), it->second.k, it->second.n);
        }
        fflush(dbg);
      }

      // RS stale-group drain: safety net for RS groups that can never complete.
      // After 4×RTT, drop incomplete group so later groups can be delivered. Scales with link.
      if (now_p - last_rs_drain_ns >= 1000000000ULL) {
        last_rs_drain_ns = now_p;
        uint64_t rs_stale_ns = scaled_ns(4, 10000000000ULL, 60000000000ULL);
        // Collect IDs that are actually being erased (had partial shards but timed out).
        // We must only gap-jump past IDs that were genuinely stale — not past IDs that
        // simply haven't received any shard yet (e.g. a SMALL arrived before the RS shard).
        std::vector<uint64_t> drained_ids;
        for (auto it = rs_pending.begin(); it != rs_pending.end(); ) {
          if (it->second.first_recv_ns > 0 && now_p - it->second.first_recv_ns > rs_stale_ns) {
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
        //  3. Jump a gap that has been continuously present for > rs_stale_ns —
        //     this covers RS groups where NO shard ever arrived while giving
        //     enough time for retransmission to succeed before we give up.
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
                                       now_p - next_deliver_id_stuck_since_ns >= rs_stale_ns);
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
            if (dbg) fprintf(dbg, "[floor-add t=%llu carriers=%zu fd=%d errno=%d]\n",
                             (unsigned long long)(now_ns()/1000000ULL), carriers.size(), fd, fd<0?errno:0);
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
#ifdef __linux__
              prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
              int dn = open("/dev/null", O_WRONLY);
              if (dn >= 0) {
                dup2(dn, STDOUT_FILENO);
                dup2(dn, STDERR_FILENO);
                close(dn);
              }
              std::string spec = path + ":" + socket_path;
              const char* argv[] = {
                "ssh", "-n", "-N",
                "-o", "ExitOnForwardFailure=yes",
                // "-o", "ServerAliveInterval=10",
                // "-o", "ServerAliveCountMax=3",
                "-L", spec.c_str(),
                args.lossy_ssh_host.c_str(), nullptr
              };
              execvp("ssh", const_cast<char* const*>(argv));
              _exit(127);
            }
            if (pid > 0) {
              ssh_idx_to_pid[free_idx] = pid;
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
      if (dbg) fprintf(dbg, "[client-exit-normal t=%llu stdin_buf=%zu reassembly=%zu rs_pending=%zu]\n",
                       (unsigned long long)(now_ns()/1000000ULL), stdin_buf.size(), reassembly.size(), rs_pending.size());
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
    // Kill all remaining SSH processes (those not yet killed by remove_carrier).
    for (auto& [_, p] : ssh_idx_to_pid)
      kill(p, SIGTERM);
    // Reap previously-killed-but-not-yet-waited processes.
    for (pid_t p : pids_to_reap)
      waitpid(p, nullptr, 0);
    // Reap the freshly-killed ones.
    for (auto& [_, p] : ssh_idx_to_pid)
      waitpid(p, nullptr, 0);
    remove_client_dir(client_dir);
  }
  if (dbg) fclose(dbg);
  return 0;
}

}  // namespace ssholl
