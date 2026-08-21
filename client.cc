#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
#include "carrier_adapt.h"
#include "net_util.h"
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
using packet_io::MAX_ID_AHEAD;
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
    char ct_buf[64];
    if (args.config.connect_timeout_sec > 0) {
      snprintf(ct_buf, sizeof ct_buf, "ConnectTimeout=%u", args.config.connect_timeout_sec);
      argv_vec.push_back("-o");
      argv_vec.push_back(ct_buf);
    }
    argv_vec.push_back(args.lossy_ssh_host.c_str());
    argv_vec.push_back(args.config.path_on_server.c_str());
    argv_vec.push_back("--server");
    if (args.debug)
      argv_vec.push_back("--debug");
    // Propagate the cold-start RTT hint so the server scales its timeouts correctly
    // before it has measured RTT (otherwise it falls back to a 5 s default, which is
    // too aggressive on high-latency links — see README "RTT-scaled timeouts").
    char rtt_buf[32];
    if (args.config.rtt_hint_ms > 0) {
      snprintf(rtt_buf, sizeof rtt_buf, "%u", args.config.rtt_hint_ms);
      argv_vec.push_back("--rtt-ms");
      argv_vec.push_back(rtt_buf);
    }
    // Propagate the keepalive floor so the server also sends ≥N bytes/min on each carrier
    // (the server→client direction), keeping NAT/firewall state alive on idle links.
    char mbpm_buf[32];
    if (args.config.min_data_per_minute > 0) {
      snprintf(mbpm_buf, sizeof mbpm_buf, "%u", args.config.min_data_per_minute);
      argv_vec.push_back("--min-data-per-minute");
      argv_vec.push_back(mbpm_buf);
    }
    // The server owns RS redundancy in auto_adapt and measures the latency budget, so it
    // needs the budget value the user configured on the client side.
    char mal_buf[32];
    snprintf(mal_buf, sizeof mal_buf, "%u", args.config.max_added_latency_ms);
    argv_vec.push_back("--max-added-latency-ms");
    argv_vec.push_back(mal_buf);
    // Propagate the configured initial redundancy so the server cold-starts the
    // server->client direction at the user's --rs-redundancy / --small-packet-redundancy
    // (the "initial" values) before its probability model has enough samples to adapt.
    char rs_buf[32];
    snprintf(rs_buf, sizeof rs_buf, "%.4f", (double)args.config.rs_redundancy);
    argv_vec.push_back("--rs-redundancy");
    argv_vec.push_back(rs_buf);
    char sp_buf[32];
    snprintf(sp_buf, sizeof sp_buf, "%u", args.config.small_packet_redundancy);
    argv_vec.push_back("--small-packet-redundancy");
    argv_vec.push_back(sp_buf);
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
    const unsigned initial_fork_count = std::min(5u, N);  // fork 5 initially; start connection sooner

    for (unsigned i = 0; i < initial_fork_count; ++i) {
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
        std::vector<const char*> argv_vec;
        argv_vec.push_back("ssh");
        argv_vec.push_back("-n");
        argv_vec.push_back("-N");
        argv_vec.push_back("-o");
        argv_vec.push_back("ExitOnForwardFailure=yes");
        char ct_buf[64];
        if (args.config.connect_timeout_sec > 0) {
          snprintf(ct_buf, sizeof ct_buf, "ConnectTimeout=%u", args.config.connect_timeout_sec);
          argv_vec.push_back("-o");
          argv_vec.push_back(ct_buf);
        }
        argv_vec.push_back("-L");
        argv_vec.push_back(spec.c_str());
        argv_vec.push_back(args.lossy_ssh_host.c_str());
        argv_vec.push_back(nullptr);
        execvp("ssh", const_cast<char* const*>(argv_vec.data()));
        _exit(127);
      }
      ssh_idx_to_pid[i] = pid;
    }

    // Wait for SSH to create sockets and accept connections.
    // On high-latency links, each ssh -L can take 10+ seconds to establish.
    for (int wait_ms = 0; wait_ms < 30000; wait_ms += 200) {
      usleep(200 * 1000);
      bool any = false;
      for (unsigned i = 0; i < initial_fork_count; ++i) {
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
  std::map<unsigned, uint64_t> pending_connect_started_ns;  // slot -> pending-start timestamp

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
  // --max-delay: hold a sub-block remainder up to this long so small writes can coalesce
  // into a full Reed-Solomon block before being sent as (weaker) SMALL copies. 0 = send
  // immediately. stdin_partial_since_ns marks when the current remainder began waiting.
  const uint64_t max_delay_ns = static_cast<uint64_t>(args.config.max_delay_ms * 1000000.0f);
  uint64_t stdin_partial_since_ns = 0;
  // Max bytes we buffer from stdin before pausing reads (avoids spinning when carriers are dead).
  static constexpr size_t STDIN_THROTTLE_BYTES = 256 * 1024;
  // Round-robin index shared by both SMALL packets and RS shards (client→server).
  unsigned next_rr = 0;
  size_t effective_max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));
  if (effective_max_packet == 0) effective_max_packet = 800;
  std::map<int, std::deque<std::pair<uint64_t, uint64_t>>> carrier_pending_acks;  // fd -> [(id, time_ns)]
  uint64_t next_carrier_id_global = 1;
  // shared_carrier_id -> last time the server reported it dead (via CARRIER_STATUS).
  // Phase 2: populated and logged only. Phase 3 will act on it (reap the union of this
  // and our own s2c-dead detection).
  std::map<uint64_t, uint64_t> server_reported_dead_ns;

  // Effective config: when auto_adapt and we have SERVER_CONFIG, use server's; else use local.
  bool has_server_config = false;
  // Cold-start at the user's CONFIGURED redundancy (with only the system minimums), in both
  // modes. In auto mode this is the "initial" value; the server's model then takes over via
  // SERVER_CONFIG. (Previously auto mode forced 0.6/6 here, ignoring the configured values
  // until the model kicked in — which is what made the initial --rs-redundancy /
  // --small-packet-redundancy look unrespected.)
  float effective_rs_redundancy = std::max(0.1f, args.config.rs_redundancy);
  unsigned effective_small_packet_redundancy = std::max(2u, args.config.small_packet_redundancy);
  std::deque<uint64_t> recent_rtt_ns;
  const size_t max_recent_rtt = 100;
  const uint64_t adapt_interval_ns = 300 * 1000000ULL;   // 300ms
  const uint64_t add_carrier_interval_ns = 100 * 1000000ULL;  // 100ms
  uint64_t last_adapt_ns = 0;
  uint64_t last_add_carrier_ns = 0;
  uint64_t last_rs_pending_pressure_add_ns = 0;  // rate-limit: add every 10s when rs_pending is very high
  uint64_t last_stall_recovery_add_ns = 0;       // rate-limit: add a fresh carrier during a link stall
  // RTT outlier threshold: carrier must be both 5× median AND above this absolute. Scales with link.
  uint64_t backpressure_write_threshold = 150 * effective_max_packet;  // updated when effective_max_packet changes
  float last_sent_rs_redundancy = -1.0f;   // sentinel so we send initial config when auto
  unsigned last_sent_small_packet_redundancy = 0;
  uint64_t server_reported_max_rtt_ns = 0;  // server→client path RTT from SERVER_METRICS
  uint32_t server_rs_pending_count = 0;     // c2s RS groups server is waiting to decode (from SERVER_METRICS)
  bool server_s2c_window_saturated = false; // server's s2c send window deliberately full (link at capacity)
  // s2c metrics (measured locally on decoded RS groups from server).
  std::deque<uint64_t> s2c_shard_spread_ns;
  std::deque<uint64_t> s2c_gap_final_ns;
  std::deque<uint64_t> s2c_extra_shard_gap_ns;
  std::deque<uint64_t> s2c_small_extra_copy_gap_ns;  // copy 1->2 gap for small packets (s2c)
  // s2c per-shard loss estimate (same latency-budget method the server runs for c2s):
  // a received shard is "late" if its gap from the group's first shard exceeds B. Reported
  // to the server via CLIENT_METRICS so it can size redundancy for the worse direction.
  uint64_t s2c_qest_total_gaps = 0;
  uint64_t s2c_qest_late_gaps = 0;
  float    s2c_loss_q = 0.0f;   // smoothed s2c late-fraction; sent in CLIENT_METRICS
  // Load measurement for the load-driven carrier target (Lever 1). Count physical packets
  // crossing the fleet per window in both directions (c2s shards/copies we send + s2c shards
  // we receive); the rate drives desired_carriers so each carrier carries only ~tau packets
  // per recovery window. This decouples carrier count from redundancy (kills the old runaway).
  uint64_t c2s_packets_sent_window = 0;
  uint64_t s2c_shards_recv_window = 0;
  uint64_t load_window_start_ns = 0;
  double   measured_pkt_rate = 0.0;          // smoothed packets/s across the fleet
  unsigned desired_carriers_dyn = std::max(2u, args.config.connections);  // load-driven target (>= floor)
  // c2s metrics reported back by server in SERVER_METRICS.
  uint64_t c2s_avg_shard_spread_ns  = 0;
  uint64_t c2s_avg_extra_shard_gap_ns = 0;
  static constexpr size_t kMaxSpreadSamples = 100;
  // Shared map for recently decoded RS groups (to time extra shards).
  std::map<uint64_t, uint64_t> recently_decoded_ns;
  std::map<uint64_t, std::vector<uint64_t>> small_copy_arrival_times;
  const unsigned target_carriers = std::max(2u, args.config.connections);
  std::vector<int> pending_reap;  // carriers to close once a replacement has connected (or slowly when above target)
  uint64_t last_reap_ns = 0;
  uint64_t last_reduction_close_ns = 0;  // rate-limit: at most 1 close per 60s when reducing from above target
  uint64_t last_excess_release_ns = 0;   // rate-limit: release 1 excess carrier per interval when rs is low
  uint64_t last_recovery_log_ns = 0;  // rate-limit: "still waiting" message when carriers.empty()
  const uint64_t reap_check_interval_ns = 2000 * 1000000ULL;
  static constexpr uint64_t reduction_close_interval_ns = 60 * 1000000000ULL;  // 60s between reduction closes
  static constexpr uint64_t excess_release_interval_ns = 15 * 1000000000ULL;   // 15s between excess releases

  // RTT-scaled timeouts: use observed latency so low-latency links get tighter timeouts,
  // high-latency links get longer. Cold start uses rtt_hint_ms or 5 s conservative default,
  // but once RTT is measured we rely on the observed p90/server-reported max instead of the
  // conservative 5 s floor (otherwise all timeouts behave as if RTT≥5 s forever).
  auto get_effective_rtt_ns = [&]() -> uint64_t {
    uint64_t hint_ns = static_cast<uint64_t>(args.config.rtt_hint_ms) * 1000000ULL;
    bool have_observed = (recent_rtt_ns.size() >= 3) || (server_reported_max_rtt_ns > 0);
    if (have_observed) {
      uint64_t observed = server_reported_max_rtt_ns;
      if (recent_rtt_ns.size() >= 3)
        observed = std::max(observed, p90_ns(recent_rtt_ns));
      if (observed == 0) {
        // Should not normally happen, but fall back to hint/default if it does.
        return hint_ns ? hint_ns : 5000000000ULL;
      }
      // When a hint is provided, treat it as a lower bound for RTT; otherwise just
      // use the observed value so low-latency links get appropriately short timeouts.
      return hint_ns ? std::max(observed, hint_ns) : observed;
    }
    // Cold start: no RTT samples and no server metrics yet. Use hint when provided,
    // otherwise a conservative 5 s default until RTT is measured.
    return hint_ns ? hint_ns : 5000000000ULL;
  };
  // Base RTT = the MINIMUM of recent c2s samples: the closest thing we have to the queue-free
  // path RTT. Used for thresholds that must NOT move with load (the s2c per-shard stall
  // cutoff), where the usual p90 would chase the queue depth the window itself grants.
  auto get_base_rtt_ns = [&]() -> uint64_t {
    if (!recent_rtt_ns.empty())
      return *std::min_element(recent_rtt_ns.begin(), recent_rtt_ns.end());
    uint64_t hint_ns = static_cast<uint64_t>(args.config.rtt_hint_ms) * 1000000ULL;
    return hint_ns ? hint_ns : 5000000000ULL;
  };
  auto scaled_ns = [&](unsigned mult, uint64_t min_ns, uint64_t max_ns) -> uint64_t {
    return ssholl::scaled_ns(mult, min_ns, max_ns, get_effective_rtt_ns());
  };
  // Session-minimum RTT, for the send-window budget (net_util.h): queueing can only raise
  // an RTT sample, so a monotone session min cannot ratchet the window cap upward.
  uint64_t client_rtt_min_session_ns = 0;  // 0 = no sample yet
  auto get_window_base_rtt_ns = [&]() -> uint64_t {
    return client_rtt_min_session_ns ? client_rtt_min_session_ns : get_base_rtt_ns();
  };

  // Unacked-send retransmit buffer (shared UnackedItem from net_util.h): holds the
  // original pre-encoded data for each outstanding send_id so it can be re-encoded and
  // resent on a new carrier when all existing carriers die.
  std::map<uint64_t, UnackedItem> unacked_sends;
  bool retransmit_needed = false;  // set when last carrier dies with unacked data
  // ACK-clocked send window for the c2s direction: caps outstanding (sent-but-unACKed)
  // data bytes — see RateWindow in net_util.h. When closed, bulk RS-group encoding stops
  // and stdin backpressure (STDIN_THROTTLE_BYTES) catches up, so a bulk producer faster
  // than the link builds only a bounded queue instead of an ever-deepening one. Interactive
  // SMALL packets are counted but never gated.
  RateWindow c2s_window;

  // Track outstanding PINGs so we can debug long RTTs / missing PONGs.
  // Keyed by (fd, ping_id) -> send_time_ns.
  std::map<std::pair<int, uint64_t>, uint64_t> outstanding_pings;
  // Group dead-carrier detection: fd -> when we sent a targeted confirm-ping to a carrier
  // our s2c receive side has gone silent on. If it delivers nothing (no PONG / no data)
  // before the confirm timeout, it's dead and we close it. Replaces blanket idle pinging.
  std::map<int, uint64_t> confirm_ping_sent_ns;

  // Timing for periodic operations that don't depend on carrier events.
  uint64_t last_ping_check_ns       = 0;
  uint64_t last_client_metrics_ns    = 0;
  const uint64_t client_metrics_interval_ns = 400 * 1000000ULL;  // 400ms, match server SERVER_METRICS
  uint64_t last_rs_drain_ns                = 0;
  uint64_t next_deliver_id_stuck_since_ns  = 0;  // when gap at next_deliver_id first appeared
  uint64_t last_deliver_advance_ns = 0;  // last time we delivered s2c data (for mass-death stall detection)
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

  const unsigned initial_connect_count = std::min(5u, args.config.connections);
  for (unsigned i = 0; i < initial_connect_count; ++i) {
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
      CarrierState& cs = carriers[fd];
      cs.connecting = true;
      if (cs.carrier_id == 0) cs.carrier_id = next_carrier_id_global++;
      if (dbg) fprintf(dbg, "[carrier-add t=%llu fd=%d total=%zu reason=initial]\n",
                       (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size());
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

  // Queue SET_CONFIG to one carrier (client -> server). Includes auto_adapt so server knows who manages redundancy.
  auto queue_config_to_carrier = [&](int fd, uint16_t pkt_size, uint16_t small_red, float max_delay_ms, float rs_red, uint8_t auto_adapt_val) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_config(it->second.write_buf, pkt_size, small_red, max_delay_ms, rs_red, auto_adapt_val,
                             (uint32_t)args.config.reconnect_timeout_sec);
  };

  // Queue CLIENT_METRICS to one carrier (s2c path quality for server's dual-direction adapt).
  auto queue_client_metrics_to_carrier = [&](int fd) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    auto m = carrier_adapt::compute_from_deques(s2c_shard_spread_ns, s2c_gap_final_ns,
                                                s2c_extra_shard_gap_ns, s2c_small_extra_copy_gap_ns);
    // Refresh the s2c loss estimate from the latency-budget counters and send it in the
    // (repurposed) fraction_struggling field; the server takes max(c2s_q, s2c_q).
    if (s2c_qest_total_gaps >= 100) {
      float q = static_cast<float>(s2c_qest_late_gaps) / static_cast<float>(s2c_qest_total_gaps);
      if (q > 0.5f) q = 0.5f;
      s2c_loss_q = 0.5f * s2c_loss_q + 0.5f * q;
      s2c_qest_total_gaps = s2c_qest_late_gaps = 0;
    }
    {
      uint64_t mq_outstanding = 0;
      for (const auto& [uid, ui] : unacked_sends) mq_outstanding += ui.data.size();
      bool mq_c2s_sat = mq_outstanding >= rate_window_cap(c2s_window, get_window_base_rtt_ns());
      packet_io::append_client_metrics(it->second.write_buf,
                                      m.avg_shard_spread_ns, m.avg_extra_shard_gap_ns,
                                      s2c_loss_q,
                                      static_cast<uint32_t>(rs_pending.size()),
                                      m.can_decrease_rs, m.can_decrease_small, mq_c2s_sat);
    }
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
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
        if (dbg) fprintf(dbg, "[stdout-write-err t=%llu errno=%d discarded=%zu]\n",
                         (unsigned long long)(now_ns()/1000000ULL), errno, stdout_buf.size());
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

  // Coalesced (cumulative) ACK. An ACK means "every id <= acked_id delivered", so instead of
  // emitting one ACK per delivered group we track only the HIGHEST delivered id (and the carrier
  // that completed it, for per-carrier RTT) and emit a single cumulative ACK per flush. Flushes
  // happen within the same epoll iteration as delivery — no added latency, RTT stays accurate —
  // so on a bulk s2c transfer this collapses the return-path ACK stream to one-per-flush.
  uint64_t pending_ack_id = 0;
  int pending_ack_fd = -1;
  bool have_pending_ack = false;

  packet_io::ReceiveCallbacks recv_cb;
  recv_cb.on_deliver = [&](int cfd, uint64_t id, const uint8_t* data, size_t len) {
    stdout_buf.insert(stdout_buf.end(), data, data + len);
    last_deliver_advance_ns = now_ns();
    // Record the highest delivered id (+completing carrier); one coalesced ACK is emitted per
    // flush at the loop tail. The completing carrier is preferred so the server gets an accurate
    // per-carrier RTT sample; flush_pending_ack falls back to any carrier if it has since closed.
    pending_ack_id = id;
    pending_ack_fd = cfd;
    have_pending_ack = true;
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
  recv_cb.on_carrier_status = [&](const std::vector<uint64_t>& dead_ids) {
    uint64_t now = now_ns();
    for (uint64_t cid : dead_ids) server_reported_dead_ns[cid] = now;
    if (dbg) {
      std::string s;
      for (uint64_t cid : dead_ids) { s += std::to_string(cid); s += ' '; }
      fprintf(dbg, "[carrier-status-recv t=%llu server_says_dead=[ %s]]\n",
              (unsigned long long)(now/1000000ULL), s.c_str());
    }
  };
  // s2c per-shard stall estimate (mirrors the server's c2s measurement): a shard arriving
  // beyond the retransmit-scale threshold (~RTT/2) means its carrier stalled, not jittered.
  recv_cb.on_rs_shard_gap = [&](uint64_t gap_ns) {
    s2c_qest_total_gaps += 1;
    if (gap_ns > carrier_adapt::stall_threshold_ns(get_base_rtt_ns())) s2c_qest_late_gaps += 1;
    s2c_shards_recv_window += 1;
  };
  recv_cb.on_small_extra_copy = [&](uint64_t gap_ns) {
    s2c_small_extra_copy_gap_ns.push_back(gap_ns);
    while (s2c_small_extra_copy_gap_ns.size() > kMaxSpreadSamples) s2c_small_extra_copy_gap_ns.pop_front();
  };
  recv_cb.on_server_metrics = [&](uint64_t max_rtt_ns, uint64_t avg_spread_ns,
                                   uint64_t avg_extra_gap_ns, uint32_t rs_pending_count,
                                   uint32_t flags) {
    if (max_rtt_ns < 10000000000ULL)
      server_reported_max_rtt_ns = max_rtt_ns;
    c2s_avg_shard_spread_ns   = avg_spread_ns;
    c2s_avg_extra_shard_gap_ns = avg_extra_gap_ns;
    server_rs_pending_count   = rs_pending_count;
    server_s2c_window_saturated = (flags & SSHOLL_SERVER_METRICS_FLAG_S2C_WINDOW_SATURATED) != 0;
  };
  recv_cb.on_server_config = [&](const PacketServerConfig& psc) {
    has_server_config = true;
    effective_max_packet = std::min(static_cast<size_t>(psc.packet_size), static_cast<size_t>(MAX_PACKET_PAYLOAD));
    if (effective_max_packet == 0) effective_max_packet = 800;
    effective_rs_redundancy = (psc.reed_solomon_redundancy >= 0.1f) ? psc.reed_solomon_redundancy : 0.1f;
    effective_small_packet_redundancy = (psc.small_packet_redundancy != 0) ? psc.small_packet_redundancy : 2u;
    if (effective_small_packet_redundancy < 2u) effective_small_packet_redundancy = 2u;
    effective_small_packet_redundancy = std::min(effective_small_packet_redundancy, std::max(2u, static_cast<unsigned>(carriers.size())));
    backpressure_write_threshold = 150 * effective_max_packet;
    if (dbg) fprintf(dbg, "[server-config-applied t=%llu pkt_size=%zu rs_red=%.2f small_copies=%u]\n",
                     (unsigned long long)(now_ns()/1000000ULL), effective_max_packet,
                     (double)effective_rs_redundancy, (unsigned)effective_small_packet_redundancy);
  };
  std::mt19937 keepalive_gen(std::random_device{}());
  recv_cb.on_ping = [&](int fd, uint64_t id, size_t payload_size) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    if (payload_size > 0) {
      size_t pkt_max = effective_max_packet;
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
  recv_cb.on_pong = [&](int fd, uint64_t id) {
    auto key = std::make_pair(fd, id);
    auto it = outstanding_pings.find(key);
    if (it == outstanding_pings.end()) return;
    uint64_t rtt_ns = now_ns() - it->second;
    outstanding_pings.erase(it);
    if (dbg && rtt_ns > 5000000000ULL) {  // > 5 s
      fprintf(dbg, "[ping-rtt-high t=%llu fd=%d id=%llu rtt_ms=%llu]\n",
              (unsigned long long)(now_ns()/1000000ULL),
              fd,
              (unsigned long long)id,
              (unsigned long long)(rtt_ns/1000000ULL));
    }
  };
  recv_cb.on_ack = [&](int fd, uint64_t acked_id) {
    const uint64_t recv_time = now_ns();
    uint64_t rtt_ns = 0;
    // Measure RTT only on the carrier the ACK arrived on — that path actually round-tripped.
    auto it_p = carrier_pending_acks.find(fd);
    if (it_p != carrier_pending_acks.end()) {
      auto& q = it_p->second;
      uint64_t last_id = 0; bool have = false;
      while (!q.empty() && q.front().first <= acked_id) {
        last_id = q.front().first; have = true;
        rtt_ns = recv_time - q.front().second;
        q.pop_front();
      }
      // Karn's algorithm: if the acked item was retransmitted, the ACK is ambiguous
      // (could be for any transmission) and a pre-outage send acked post-outage would
      // otherwise be timed as ~the outage duration. Don't record RTT for it. The
      // cross-carrier clear below guarantees unacked_sends[last_id] still exists here.
      if (have) {
        auto uit = unacked_sends.find(last_id);
        if (uit != unacked_sends.end() && uit->second.retransmitted) rtt_ns = 0;
      }
    }
    // ACKs are cumulative: every id <= acked_id is delivered, so clear its pending entry
    // on ALL OTHER carriers too (without timing it). Otherwise an entry on a slow or
    // recovered carrier lingers until that carrier itself gets an ACK and is then timed as
    // a huge RTT (~outage duration), inflating the retransmit timeout and stalling recovery.
    for (auto& [cfd, q2] : carrier_pending_acks) {
      if (cfd == fd) continue;
      while (!q2.empty() && q2.front().first <= acked_id) q2.pop_front();
    }
    if (rtt_ns != 0) {
      if (dbg && rtt_ns > 5000000000ULL)
        fprintf(dbg, "[ack-rtt-high t=%llu fd=%d acked_id=%llu rtt_ms=%llu]\n",
                (unsigned long long)(now_ns()/1000000ULL), fd, (unsigned long long)acked_id,
                (unsigned long long)(rtt_ns/1000000ULL));
      auto it_c = carriers.find(fd);
      if (it_c != carriers.end()) it_c->second.last_rtt_ns = rtt_ns;
      // Always record RTT samples regardless of auto_adapt. RTT drives all timeout
      // scaling (retransmit, dead_idle, ping, rs_stale) — not just carrier adaptation.
      // Without this, non-auto_adapt mode uses the conservative 5s default for all
      // timeouts and the 2.5s hardcoded retransmit, mismatching the server which always
      // scales from measured RTT.
      recent_rtt_ns.push_back(rtt_ns);
      while (recent_rtt_ns.size() > max_recent_rtt) recent_rtt_ns.pop_front();
      if (client_rtt_min_session_ns == 0 || rtt_ns < client_rtt_min_session_ns)
        client_rtt_min_session_ns = rtt_ns;
    }
    // Data confirmed delivered: no longer need to retransmit.
    uint64_t acked_bytes = 0;
    for (auto it_u = unacked_sends.begin(); it_u != unacked_sends.end() && it_u->first <= acked_id; ) {
      acked_bytes += it_u->second.data.size();
      it_u = unacked_sends.erase(it_u);
    }
    // ACK-clocked delivered-rate estimate for the c2s send window (see RateWindow in
    // net_util.h): when the window has closed the pump there is nothing new to ACK, so the
    // rate holds rather than spiralling down.
    uint64_t outstanding_after = 0;
    for (const auto& [uid2, ui2] : unacked_sends) outstanding_after += ui2.data.size();
    rate_window_on_ack(c2s_window, acked_bytes, recv_time, outstanding_after,
                       get_window_base_rtt_ns());
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

  auto do_carrier_cleanup = [&](int fd, const char* reason) {
    if (dbg) fprintf(dbg, "[carrier-remove t=%llu fd=%d total=%zu reason=%s]\n",
                     (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size()-1, reason);
    carrier_pending_acks.erase(fd);
    if (!args.unix_socket_connection.empty()) return;
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
    if (carriers.size() == 1 && !unacked_sends.empty()) {
      retransmit_needed = true;
      if (dbg) fprintf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=last_carrier_dying]\n",
                       (unsigned long long)(now_ns()/1000000ULL), unacked_sends.size());
    }
  };
  auto flush_carrier_writes = [&]() {
    size_t carriers_before = carriers.size();
    packet_io::flush_carrier_writes(carriers, epfd, ev,
        [](int, const CarrierState& s) { return s.connecting; },
        [&](int fd, const char* reason) { do_carrier_cleanup(fd, reason); });
    for (auto it = carrier_pending_acks.begin(); it != carrier_pending_acks.end(); )
      if (carriers.count(it->first) == 0) it = carrier_pending_acks.erase(it);
      else ++it;
    // Write-error removals: reset add throttle when dropping below floor.
    if (carriers_before > 0 && carriers.size() < target_carriers)
      last_add_carrier_ns = 0;
    if (carriers.empty() && !unacked_sends.empty()) {
      retransmit_needed = true;
      if (dbg) fprintf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=write_error_all_dead]\n",
                       (unsigned long long)(now_ns()/1000000ULL), unacked_sends.size());
    }
  };

  // Emit the single coalesced cumulative ACK for the highest id delivered since the last flush.
  auto flush_pending_ack = [&]() {
    if (!have_pending_ack || carriers.empty()) return;
    int cfd = pending_ack_fd;
    if (!carriers.count(cfd)) cfd = carriers.begin()->first;
    packet_io::append_ack(carriers[cfd].write_buf, pending_ack_id);
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = cfd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
    have_pending_ack = false;
  };

  // fd_to_ssh_index is declared and populated above in the initial connect loop.

  // Centralised carrier removal: closes the fd, removes from epoll, cleans up maps.
  // In SSH mode: kills the owning SSH process and unlinks its socket file so the
  // slot can be reused cleanly.  Flags retransmit when the last carrier is lost.
  auto remove_carrier = [&](int fd, const char* reason) {
    pending_reap.erase(std::remove(pending_reap.begin(), pending_reap.end(), fd), pending_reap.end());
    do_carrier_cleanup(fd, reason);
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    carriers.erase(fd);
    // Drop any outstanding PING records for this fd so we don't log against a closed carrier.
    for (auto it = outstanding_pings.begin(); it != outstanding_pings.end(); ) {
      if (it->first.first == fd) it = outstanding_pings.erase(it);
      else ++it;
    }
    if (carriers.empty() && !unacked_sends.empty()) {
      retransmit_needed = true;
      if (dbg) fprintf(dbg, "[retransmit-needed t=%llu unacked=%zu reason=all_dead fd=%d]\n",
                       (unsigned long long)(now_ns()/1000000ULL), unacked_sends.size(), fd);
    }
    // If survivors remain, force the retransmit check to run on the next iteration
    // rather than waiting up to 500 ms for the periodic tick. Shards on the dead
    // carrier were almost certainly lost; the sooner we retransmit the better.
    if (!carriers.empty() && !unacked_sends.empty()) {
      last_retransmit_check_ns = 0;
      if (dbg) fprintf(dbg, "[retransmit-check-reset t=%llu unacked=%zu fd=%d survivors=%zu]\n",
                       (unsigned long long)(now_ns()/1000000ULL), unacked_sends.size(), fd, carriers.size());
    }
    // Below floor: reset add throttle so floor maintenance can burst back to target immediately.
    if (carriers.size() < target_carriers)
      last_add_carrier_ns = 0;
  };

  auto add_to_pending_reap = [&](int fd, const char* reason) {
    if (!carriers.count(fd)) return;
    if (std::find(pending_reap.begin(), pending_reap.end(), fd) != pending_reap.end()) return;
    pending_reap.push_back(fd);
    if (dbg) fprintf(dbg, "[pending-reap t=%llu fd=%d reason=%s total=%zu]\n",
                     (unsigned long long)(now_ns()/1000000ULL), fd, reason, pending_reap.size());
  };

  recv_cb.on_suggest_close = [&](int fd) {
    // Defensive cap unless backlog is genuinely heavy. Tiny in-flight backlogs
    // (a few packets) should not allow large close cascades.
    size_t backlog_bytes = 0;
    for (const auto& [_, ui] : unacked_sends) backlog_bytes += ui.data.size();
    const bool heavy_backlog = carrier_adapt::is_heavy_backlog(backlog_bytes, unacked_sends.size());
    if (!heavy_backlog) {
      size_t reap_cap = std::max<size_t>(3, target_carriers / 3);
      if (pending_reap.size() >= reap_cap) return;
    }
    add_to_pending_reap(fd, "server_suggest_close");
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

  // Packetize buffered stdin onto carriers: full blocks as Reed-Solomon (sent
  // immediately), and any sub-block remainder as SMALL — but the remainder is held up
  // to --max-delay (max_delay_ns) so consecutive small writes can coalesce into a full
  // RS block first. Called both when stdin produces data and periodically (so a held
  // remainder still flushes once its window elapses). Caller flushes carrier writes.
  auto pump_stdin_send = [&]() {
    // SEND WINDOW (see RateWindow in net_util.h): bulk RS-group encoding stops once the
    // outstanding sent-but-unACKed data reaches the ACK-clocked cap — that is what bounds
    // the queue a late shard/interactive packet can sit behind. SMALL/interactive packets
    // are never gated. The window always opens when empty, so one oversized group can't
    // deadlock the stream.
    uint64_t c2s_outstanding = 0;
    for (const auto& [uid, ui] : unacked_sends) c2s_outstanding += ui.data.size();
    while (stdin_buf.size() >= effective_max_packet && !carriers.empty() &&
           rate_window_open(c2s_outstanding, c2s_window, get_window_base_rtt_ns())) {
      const size_t block_size = effective_max_packet;
      float rs_frac = args.config.auto_adapt ? effective_rs_redundancy : args.config.rs_redundancy;
      // Interactive (small backlog) groups get smoothness-grade parity so a small low-k burst
      // is as robust as a duplicated small packet. We recover the per-carrier jitter q from the
      // copy count (copies = ceil(ln eps / ln q), so q ≈ eps^(1/copies)) the server pushes —
      // no extra wire field. Bulk groups (heavy unacked backlog) pass 0 → parity-as-fraction.
      double iq = 0.0;
      if (args.config.auto_adapt &&
          !carrier_adapt::is_heavy_backlog(0, unacked_sends.size())) {
        unsigned c = std::max(2u, effective_small_packet_redundancy);
        iq = std::pow(carrier_adapt::kInteractiveEps, 1.0 / static_cast<double>(c));
      }
      // One shard per carrier so any k of them suffice to decode (see rs_group_params).
      auto gp = packet_io::rs_group_params(carriers.size(), rs_frac, stdin_buf.size() / block_size,
                                           iq, carrier_adapt::kInteractiveEps);
      unsigned k = gp.k;
      if (k == 0) break;
      unsigned m = gp.m;
      unsigned n = gp.n;
      if (m == 0) {
        // Single carrier: can't do RS (need m>=1). Send block as SMALL.
        size_t chunk = block_size;
        UnackedItem& ui = unacked_sends[next_send_id];
        ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
        ui.is_small = true;
        ui.send_ns = now_ns();
        auto it = carriers.begin();
        int cfd = it->first;
        ui.small_sent_on.insert(it->second.carrier_id);
        queue_to_carrier(cfd, stdin_buf.data(), chunk, false);  // increments next_send_id
        c2s_packets_sent_window += 1;
        c2s_outstanding += chunk;
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = cfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
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
      std::vector<uint64_t> shard_carriers(num_shards);
      for (size_t i = 0; i < num_shards; ++i) {
        auto it = carriers.begin();
        std::advance(it, (next_rr + i) % carriers.size());
        int cfd = it->first;
        shard_carriers[i] = it->second.carrier_id;
        const uint8_t* shard = (i < k) ? (stdin_buf.data() + i * block_size) : parity[i - k].data();
        queue_rs_shard_to_carrier(cfd, n, k, static_cast<uint16_t>(block_size), static_cast<unsigned>(i), shard);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = cfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
      }
      {
        UnackedItem& ui = unacked_sends[next_send_id];
        ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + k * block_size);
        ui.n = n;
        ui.k = static_cast<unsigned>(k);
        ui.block_size = static_cast<uint16_t>(block_size);
        ui.is_small = false;
        ui.send_ns = now_ns();
        for (unsigned si = 0; si < num_shards; ++si)
          ui.rs_shard_sent_on[si].insert(shard_carriers[si]);
      }
      next_send_id++;
      c2s_outstanding += k * block_size;  // the window gate re-checks against this
      if (dbg && unacked_sends.size() > 500 && next_send_id % 100 == 0)
        fprintf(dbg, "[pump-grow t=%llu unacked=%zu next_send_id=%llu k=%u block=%zu outstanding_kb=%zu cap_kb=%zu rate_kbps=%.0f]\n",
                (unsigned long long)(now_ns()/1000000ULL), unacked_sends.size(),
                (unsigned long long)next_send_id, k, block_size, c2s_outstanding/1024,
                rate_window_cap(c2s_window, get_window_base_rtt_ns())/1024, c2s_window.rate_bps/1024.0);
      c2s_packets_sent_window += num_shards;
      if (!carriers.empty())
        next_rr = (next_rr + static_cast<unsigned>(num_shards)) % static_cast<unsigned>(carriers.size());
      stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + k * block_size);
    }
    // Sub-block remainder → SMALL, held up to --max-delay so it can coalesce into a block.
    if (!stdin_buf.empty() && stdin_buf.size() < effective_max_packet && !carriers.empty()) {
      if (stdin_partial_since_ns == 0) stdin_partial_since_ns = now_ns();
      if (max_delay_ns == 0 || now_ns() - stdin_partial_since_ns >= max_delay_ns) {
        size_t chunk = stdin_buf.size();
        const unsigned n_copies = std::max(1u, std::min(static_cast<unsigned>(carriers.size()),
                                                        effective_small_packet_redundancy));
        UnackedItem& ui = unacked_sends[next_send_id];
        ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
        ui.is_small = true;
        ui.send_ns = now_ns();
        size_t n_carriers = carriers.size();
        for (unsigned i = 0; i < n_copies && n_carriers > 0; ++i) {
          unsigned idx = (next_rr + i) % static_cast<unsigned>(n_carriers);
          auto it = carriers.begin();
          std::advance(it, idx);
          int cfd = it->first;
          ui.small_sent_on.insert(it->second.carrier_id);
          queue_to_carrier(cfd, stdin_buf.data(), chunk, n_copies > 1);
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = cfd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
        }
        if (!carriers.empty())
          next_rr = (next_rr + n_copies) % static_cast<unsigned>(carriers.size());
        c2s_packets_sent_window += n_copies;
        if (n_copies > 1) next_send_id++;
        stdin_buf.clear();
        stdin_partial_since_ns = 0;
      }
    } else {
      stdin_partial_since_ns = 0;
    }
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
    bool need_replacements = !pending_reap.empty() && carriers.size() <= target_carriers;
    if (carriers.size() < target_carriers || need_replacements) {
      uint64_t elapsed = now_ns() - last_add_carrier_ns;
      uint64_t floor_interval = carriers.empty() ? 50000000ULL : add_carrier_interval_ns;
      if (elapsed >= floor_interval)
        epoll_timeout_ms = 0;
      else
        epoll_timeout_ms = static_cast<int>((floor_interval - elapsed) / 1000000ULL + 1);
    }
    // If a sub-block remainder is being held for coalescing (--max-delay), wake in time
    // to flush it rather than waiting a full poll cycle.
    if (stdin_partial_since_ns != 0 && max_delay_ns > 0) {
      uint64_t elapsed = now_ns() - stdin_partial_since_ns;
      uint64_t remaining_ms = (max_delay_ns > elapsed) ? ((max_delay_ns - elapsed) / 1000000ULL + 1) : 0;
      if (static_cast<int>(remaining_ms) < epoll_timeout_ms) epoll_timeout_ms = static_cast<int>(remaining_ms);
    }
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), epoll_timeout_ms);
    if (n < 0) {
      if (errno == EINTR) {
        // Signal interrupted the wait; re-check shutdown flag at the top of the loop.
        continue;
      }
      if (dbg) fprintf(dbg, "[epoll-wait-error t=%llu errno=%d]\n",
                       (unsigned long long)(now_ns()/1000000ULL), errno);
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
        // If stdin_buf has grown large, remove STDIN from epoll so we don't keep
        // queueing data we cannot push out yet. This applies with carriers up too:
        // the RateWindow pump gate can legitimately stop draining stdin_buf (link at
        // capacity), and without this throttle the queue would just move from the
        // carrier write buffers into stdin_buf, unbounded.
        if (!stdin_eof && stdin_buf.size() >= STDIN_THROTTLE_BYTES && stdin_in_epoll) {
          epoll_ctl(epfd, EPOLL_CTL_DEL, STDIN_FILENO, nullptr);
          stdin_in_epoll = false;
        }
        pump_stdin_send();
        // Flush immediately so data reaches kernel (and thus server) in this
        // iteration instead of after processing other events in the batch.
        flush_carrier_writes();
        continue;
      }

      if (fd == STDOUT_FILENO) {
        if (e & (EPOLLERR | EPOLLHUP)) {
          // Write end of stdout pipe broken; discard remaining output.
          if (dbg) fprintf(dbg, "[stdout-broken t=%llu discarded=%zu reason=epoll_err_hup]\n",
                           (unsigned long long)(now_ns()/1000000ULL), stdout_buf.size());
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
            // First packet on a new carrier: tell the server its shared carrier id so both
            // sides can name this carrier in health/attribution messages. The client's
            // local carrier_id IS the shared id (the client is the carrier authority).
            if (it->second.carrier_id == 0) it->second.carrier_id = next_carrier_id_global++;
            it->second.shared_carrier_id = it->second.carrier_id;
            packet_io::append_start_connection(it->second.write_buf, it->second.carrier_id);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = fd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            // Catch-up cumulative ACK: a freshly connected carrier is our first chance
            // to tell the server how much s2c data we've already delivered to stdout, in
            // case ACKs were lost while carriers were down. Without this the server can
            // keep retransmitting already-delivered data indefinitely on a quiet stream.
            if (next_deliver_id > 0) {
              packet_io::append_ack(it->second.write_buf, next_deliver_id - 1);
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            }
            if (!pending_reap.empty()) {
              int to_close = pending_reap.front();
              pending_reap.erase(pending_reap.begin());
              remove_carrier(to_close, "replaced");
            }
            // Re-send any data that was in-flight on carriers that all died, using
            // the same send_ids so the receiver can combine with any partial shards
            // it already buffered — allowing RS groups to complete without data loss.
            if (retransmit_needed && !unacked_sends.empty()) {
              retransmit_needed = false;
              const uint64_t retransmit_now = now_ns();
              if (dbg) fprintf(dbg, "[retransmit-on-reconnect t=%llu fd=%d items=%zu]\n",
                               (unsigned long long)(retransmit_now/1000000ULL), fd, unacked_sends.size());
              for (auto& [uid, ui] : unacked_sends) {
                if (ui.is_small) {
                  packet_io::append_small(it->second.write_buf, uid,
                                          ui.data.data(), ui.data.size());
                  // Track by logical carrier_id, not raw fd, so the
                  // retransmit logic can correctly avoid resending on
                  // the same logical carrier when fds are reused.
                  ui.small_sent_on.insert(it->second.carrier_id);
                } else {
                  // Re-encode RS with the same (n, k, block_size) so the receiver can
                  // combine these shards with any partials it retained.
                  auto shards = packet_io::rs_reencode_shards(ui);
                  for (unsigned si = 0; si < ui.n; ++si) {
                    packet_io::append_rs_shard(it->second.write_buf, uid,
                                               ui.n, ui.k, ui.block_size, si, shards[si].data());
                    // Track by logical carrier_id, not raw fd, so the retransmit
                    // logic can correctly avoid resending the same shard on the
                    // same logical carrier when fds are reused.
                    ui.rs_shard_sent_on[si].insert(it->second.carrier_id);
                  }
                }
                // Reset timer so the periodic 3 s retransmit doesn't immediately
                // fire a redundant duplicate of what we just queued.
                ui.send_ns = retransmit_now;
                ui.retransmitted = true;  // Karn: don't time this id's ACK as RTT
              }
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            }
          } else if (err != EINPROGRESS && err != 0) {
            remove_carrier(fd, "connect_failed");
            continue;
          }
        }
        if (e & EPOLLIN) {
          if (!process_carrier_read(fd, it->second))
            remove_carrier(fd, "read_error");
        }
        if (carriers.count(fd) && (e & (EPOLLERR | EPOLLHUP))) {
          remove_carrier(fd, "epoll_err_hup");
        }
      }
    }

    if (stdin_eof && !stdin_buf.empty() && !carriers.empty()) {
      stdin_partial_since_ns = 0;  // EOF: flush everything now, don't hold for --max-delay
      while (!stdin_buf.empty()) {
        size_t chunk = std::min(stdin_buf.size(), effective_max_packet);
        const bool small_packet = (chunk < effective_max_packet);
        // Small: n_copies = effective_small_packet_redundancy (RTT-adjusted). Full block: 1 copy (RS handles redundancy).
        const unsigned n_copies = small_packet
            ? std::max(1u, std::min(static_cast<unsigned>(carriers.size()), effective_small_packet_redundancy))
            : 1u;
        UnackedItem& ui = unacked_sends[next_send_id];
        ui.data.assign(stdin_buf.begin(), stdin_buf.begin() + chunk);
        ui.is_small = true;
        ui.send_ns = now_ns();
        if (small_packet) {
          // Round-robin SMALL packets across carriers using the same index as RS shards.
          // With redundancy N and C carriers, copies for each logical packet go to
          // consecutive carriers and RS shards continue from where SMALL left off.
          size_t n_carriers = carriers.size();
          for (unsigned i = 0; i < n_copies && n_carriers > 0; ++i) {
            unsigned idx = (next_rr + i) % static_cast<unsigned>(n_carriers);
            auto it = carriers.begin();
            std::advance(it, idx);
            int cfd = it->first;
            ui.small_sent_on.insert(it->second.carrier_id);
            queue_to_carrier(cfd, stdin_buf.data(), chunk, n_copies > 1);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
          // next_rr is advanced once at the end of the loop body (below) for both
          // branches; don't advance here too or the round-robin skips carriers.
        } else {
          auto it = carriers.begin();
          std::advance(it, next_rr % carriers.size());
          queue_to_carrier(it->first, stdin_buf.data(), chunk, false);
          ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = it->first;
          epoll_ctl(epfd, EPOLL_CTL_MOD, it->first, &ev);
        }
        if (small_packet && n_copies > 1)
          next_send_id++;
        stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + chunk);
        if (!carriers.empty())
          next_rr = (next_rr + n_copies) % static_cast<unsigned>(carriers.size());
      }
    }

    // Run the sender pump periodically even when STDIN is throttled out of epoll: an
    // arriving ACK can re-open the send window while stdin_buf is full, and only the
    // pump drains the buffer through the window — without this the window opens but no
    // new group is encoded and the link wedges. (Also flushes a held sub-block
    // remainder once its --max-delay elapses; the pump enforces that timing itself.)
    if (!stdin_eof && !stdin_buf.empty() && !carriers.empty())
      pump_stdin_send();

    flush_pending_ack();  // one coalesced cumulative ACK for everything delivered this iteration
    flush_carrier_writes();
    flush_stdout();

    // Try to complete pending SSH carrier connections.
    for (auto it = pending_carrier_paths.begin(); it != pending_carrier_paths.end(); ) {
      std::string prefix = client_dir + "/";
      unsigned slot = (it->size() > prefix.size())
          ? static_cast<unsigned>(std::stoul(it->substr(prefix.size()))) : 0;
      if (!pending_connect_started_ns.count(slot))
        pending_connect_started_ns[slot] = now_ns();
      // If the SSH process for this slot has exited on its own (e.g. auth failure,
      // ExitOnForwardFailure), remove the entry so the slot is freed for relaunch.
      if (auto pit = ssh_idx_to_pid.find(slot); pit != ssh_idx_to_pid.end()) {
        if (waitpid(pit->second, nullptr, WNOHANG) != 0) {
          // Process exited; clean up and let find_free_ssh_index reclaim this slot.
          ssh_idx_to_pid.erase(pit);
          unlink(it->c_str());
          pending_connect_started_ns.erase(slot);
          it = pending_carrier_paths.erase(it);
          continue;
        }
      }
      // Recycle stale pending SSH connects that never produce a local forward socket.
      // Without this, all slots can become permanently occupied during outages.
      {
        const uint64_t now_pc = now_ns();
        uint64_t pending_timeout_ns;
        if (args.config.connect_timeout_sec > 0) {
          uint64_t base = static_cast<uint64_t>(args.config.connect_timeout_sec) * 1000000000ULL;
          pending_timeout_ns = std::min<uint64_t>(120000000000ULL, std::max<uint64_t>(10000000000ULL, base * 2));
        } else {
          pending_timeout_ns = 20000000000ULL;  // 20 s default when ConnectTimeout is unset
        }
        // During total carrier loss, recover aggressively: stale pending connects
        // should be recycled quickly so slots become available for fresh attempts.
        if (carriers.empty())
          pending_timeout_ns = std::min<uint64_t>(pending_timeout_ns, 5000000000ULL);  // 5 s
        const uint64_t started = pending_connect_started_ns[slot];
        if (now_pc > started && now_pc - started > pending_timeout_ns) {
          if (auto pit = ssh_idx_to_pid.find(slot); pit != ssh_idx_to_pid.end()) {
            kill(pit->second, SIGTERM);
            pids_to_reap.push_back(pit->second);
            ssh_idx_to_pid.erase(pit);
          }
          unlink(it->c_str());
          if (dbg) fprintf(dbg, "[pending-connect-timeout t=%llu slot=%u waited_ms=%llu]\n",
                           (unsigned long long)(now_pc/1000000ULL),
                           slot,
                           (unsigned long long)((now_pc - started)/1000000ULL));
          pending_connect_started_ns.erase(slot);
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
          CarrierState& cs = carriers[fd];
          cs.connecting = true;
          if (cs.carrier_id == 0) cs.carrier_id = next_carrier_id_global++;
          if (dbg) fprintf(dbg, "[carrier-add t=%llu fd=%d total=%zu reason=ssh_connect]\n",
                           (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size());
          // Record SSH index for later recycling.
          if (it->size() > prefix.size())
            fd_to_ssh_index[fd] = slot;
        } else {
          close(fd);
        }
        pending_connect_started_ns.erase(slot);
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
      // Send s2c path metrics so server can merge with c2s for dual-direction adapt.
      {
        const uint64_t now = now_ns();
        if (now - last_client_metrics_ns >= client_metrics_interval_ns) {
          last_client_metrics_ns = now;
          // Load-spread: send over the carrier we've sent on least recently.
          int fd = -1; uint64_t oldest = 0;
          for (auto& [cfd, cs] : carriers) {
            if (cs.connecting) continue;
            uint64_t age = now - cs.last_send_ns;
            if (fd < 0 || age > oldest) { fd = cfd; oldest = age; }
          }
          if (fd >= 0) queue_client_metrics_to_carrier(fd);
        }
      }
    } else if (!carriers.empty()) {
      const uint64_t now = now_ns();
      if (now - last_adapt_ns >= adapt_interval_ns
          && s2c_shard_spread_ns.size() >= carrier_adapt::kMinSamplesForAdapt) {
        last_adapt_ns = now;

        auto s2c = carrier_adapt::compute_from_deques(s2c_shard_spread_ns, s2c_gap_final_ns,
                                                     s2c_extra_shard_gap_ns, s2c_small_extra_copy_gap_ns);
        carrier_adapt::PathMetrics c2s;
        c2s.fraction_struggling = carrier_adapt::approximate_fraction_struggling_from_avg_spread(c2s_avg_shard_spread_ns);
        c2s.can_decrease_rs = (c2s_avg_extra_shard_gap_ns > 0
                               && c2s_avg_extra_shard_gap_ns < carrier_adapt::kExtraGapDecreaseThresholdNs);
        c2s.can_decrease_small = false;  // server doesn't report c2s small-packet gap
        bool c2s_fresh = (c2s_avg_shard_spread_ns > 0 || server_rs_pending_count > 0);
        auto merged = carrier_adapt::merge(s2c, c2s, c2s_fresh);  // primary s2c, merge with c2s when fresh

        auto res = carrier_adapt::run_adapt(merged, effective_rs_redundancy,
                                           effective_small_packet_redundancy,
                                           static_cast<unsigned>(carriers.size()));
        effective_rs_redundancy = res.rs_redundancy;
        effective_small_packet_redundancy = res.small_packet_redundancy;
        if (res.clear_spread) {
          s2c_shard_spread_ns.clear();
          s2c_gap_final_ns.clear();
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
      // 500 ms: detect dead carriers promptly so we can reap and open new connections quickly
      // (e.g. after WiFi is turned back on); 1 s added unnecessary delay to recovery.
      if (now_p - last_ping_check_ns >= 500000000ULL) {
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
            pending_connect_started_ns.erase(idx);
          }
        }

        std::vector<carrier_adapt::CarrierInfo> carrier_infos;
        for (auto& [cfd, cs] : carriers) {
          if (cs.connecting) continue;
          carrier_infos.push_back({cfd, cs.last_rtt_ns, cs.last_recv_ns, cs.connect_ns, cs.last_send_ns});
        }
        auto quality = carrier_adapt::assess_carriers(carrier_infos, now_p, scaled_ns);

        // Periodic per-carrier diagnostics (every ~2 s) to debug stuck recovery: shows why
        // carriers are/aren't flagged dead and why the floor/reap cycle does or doesn't run.
        if (dbg) {
          static uint64_t last_carrier_diag_ns = 0;
          if (now_p - last_carrier_diag_ns >= 2000000000ULL) {
            last_carrier_diag_ns = now_p;
            size_t connecting_n = 0;
            for (auto& [cfd, cs] : carriers) if (cs.connecting) connecting_n++;
            // Control-decision inputs, all on one line: carrier-count bounds (floor..max),
            // the load-driven target `desired` and what drives it (s2c stall fraction `s2c_q`
            // and the fleet packet `rate_pps`), the current redundancy the server pushed
            // (`rs`/`copies`), and the RTT + derived stall threshold the late-measurement uses.
            size_t diag_backlog = 0;
            for (const auto& [_, ui] : unacked_sends) diag_backlog += ui.data.size();
            uint64_t diag_rtt = get_effective_rtt_ns();
            fprintf(dbg, "[carriers-diag t=%llu n=%zu connecting=%zu floor=%u max=%u desired=%u "
                         "rate_pps=%.0f s2c_q=%.3f rs=%.2f copies=%u rtt_ms=%llu stall_ms=%llu "
                         "unacked=%zu backlog_b=%zu pending_reap=%zu dead_idle=%zu reap=%zu rtt_outlier=%d]\n",
                    (unsigned long long)(now_p/1000000ULL), carriers.size(), connecting_n,
                    target_carriers, max_connections, desired_carriers_dyn,
                    measured_pkt_rate, (double)s2c_loss_q,
                    (double)effective_rs_redundancy, (unsigned)effective_small_packet_redundancy,
                    (unsigned long long)(diag_rtt/1000000ULL),
                    (unsigned long long)(carrier_adapt::stall_threshold_ns(diag_rtt)/1000000ULL),
                    unacked_sends.size(), diag_backlog, pending_reap.size(),
                    quality.dead_idle_fds.size(), quality.reap_fds.size(), quality.rtt_outlier_fd);
            for (auto& [cfd, cs] : carriers) {
              bool in_reap = std::find(pending_reap.begin(), pending_reap.end(), cfd) != pending_reap.end();
              bool is_dead = std::find(quality.dead_idle_fds.begin(), quality.dead_idle_fds.end(), cfd)
                  != quality.dead_idle_fds.end();
              long long recv_ago = cs.last_recv_ns ? (long long)((now_p - cs.last_recv_ns)/1000000ULL) : -1;
              long long send_ago = cs.last_send_ns ? (long long)((now_p - cs.last_send_ns)/1000000ULL) : -1;
              fprintf(dbg, "  fd=%d age_ms=%llu recv_ago_ms=%lld send_ago_ms=%lld wbuf=%zu connecting=%d dead=%d pending=%d\n",
                      cfd, (unsigned long long)((now_p - cs.connect_ns)/1000000ULL),
                      recv_ago, send_ago, cs.write_buf.size(), (int)cs.connecting, (int)is_dead, (int)in_reap);
            }
          }
        }

        // Group dead-carrier detection (replaces blanket idle pinging, which put a PING on
        // every idle carrier every ~2 s — and a lost PING head-of-line-blocks that carrier's
        // next data shard, self-inflicting the very lateness we measure). A carrier is dead
        // if EITHER direction is dead:
        //   - c2s: the server reported it (CARRIER_STATUS) — already windowed-confirmed on
        //     its side, so act on a fresh report directly.
        //   - s2c: our own receive side is silent while peers deliver (quality.rx_dead_fds) —
        //     confirm with a single targeted ping; if it delivers nothing back before the
        //     confirm timeout it's dead, else it recovered (transient) and we leave it.
        {
          const uint64_t report_fresh_ns = 2500000000ULL;       // server "currently dead"
          const uint64_t confirm_timeout_ns = scaled_ns(8, 2000000000ULL, 30000000000ULL);
          std::set<int> rx_dead(quality.rx_dead_fds.begin(), quality.rx_dead_fds.end());
          // Mass-death fast path: if s2c delivery has stalled (data pending but next_deliver_id
          // not advancing) AND a large subset of carriers just went silent, this is a
          // correlated drop that IS blocking latency — don't wait out the per-carrier confirm
          // ping, batch-reap the silent carriers now so the floor reopens fresh ones. (When
          // delivery is still flowing, redundancy is covering the loss, so a single dead
          // carrier is in no rush and takes the confirm path.)
          size_t n_live = 0;
          for (auto& [f, c] : carriers) if (!c.connecting) ++n_live;
          bool data_pending = !rs_pending.empty() || !reassembly.empty();
          uint64_t stall_ns = scaled_ns(4, 1500000000ULL, 30000000000ULL);
          bool delivery_stalled = data_pending && last_deliver_advance_ns > 0 &&
                                  (now_p - last_deliver_advance_ns > stall_ns);
          bool mass_death = delivery_stalled &&
                            rx_dead.size() >= std::max<size_t>(2, n_live / 4);
          if (mass_death && dbg)
            fprintf(dbg, "[mass-death t=%llu rx_dead=%zu live=%zu stalled_ms=%llu]\n",
                    (unsigned long long)(now_p/1000000ULL), rx_dead.size(), n_live,
                    (unsigned long long)((now_p - last_deliver_advance_ns)/1000000ULL));
          std::vector<std::pair<int,const char*>> to_reap;
          for (auto& [cfd, cs] : carriers) {
            if (cs.connecting) continue;
            // c2s dead per a fresh server report -> reap directly.
            if (cs.shared_carrier_id != 0) {
              auto sr = server_reported_dead_ns.find(cs.shared_carrier_id);
              if (sr != server_reported_dead_ns.end() && now_p - sr->second < report_fresh_ns) {
                to_reap.push_back({cfd, "c2s_dead_server"});
                continue;
              }
            }
            // s2c dead (silent while peers deliver).
            if (rx_dead.count(cfd)) {
              if (mass_death) { to_reap.push_back({cfd, "mass_death"}); continue; }
              // Otherwise confirm with a targeted ping (no rush — redundancy is covering).
              auto cp = confirm_ping_sent_ns.find(cfd);
              if (cp == confirm_ping_sent_ns.end()) {
                packet_io::append_ping(cs.write_buf, next_send_id);
                confirm_ping_sent_ns[cfd] = now_p;
                ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
              } else if (cs.last_recv_ns > cp->second) {
                confirm_ping_sent_ns.erase(cp);          // delivered something -> recovered
              } else if (now_p - cp->second > confirm_timeout_ns) {
                to_reap.push_back({cfd, "s2c_dead_confirmed"});
              }
            }
          }
          for (auto& [cfd, reason] : to_reap) {
            auto itc = carriers.find(cfd);
            if (itc == carriers.end() || itc->second.connecting) continue;
            packet_io::append_suggest_close(itc->second.write_buf);
            ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
            confirm_ping_sent_ns.erase(cfd);
            bool aggressive = (!unacked_sends.empty() && carriers.size() > 1);
            if (carriers.size() > target_carriers || aggressive) remove_carrier(cfd, reason);
            else add_to_pending_reap(cfd, reason);
          }
          // Drop confirm state for carriers no longer suspect (recovered on their own).
          for (auto it = confirm_ping_sent_ns.begin(); it != confirm_ping_sent_ns.end(); ) {
            if (!rx_dead.count(it->first) || !carriers.count(it->first))
              it = confirm_ping_sent_ns.erase(it);
            else ++it;
          }
        }

        // --min-data-per-minute: the link's idle keepalive (on by default). Keep each carrier
        // sending at a slow, *steady* rate so a firewall/NAT never sees a long idle gap and
        // closes the carrier. The per-minute budget is spread over 10-second windows
        // (60s / 10s = 6 windows/min): each window must carry min_bpm/6 bytes, topped up with
        // a small keepalive when real traffic (data, ACKs) falls short. Spreading it — rather
        // than one 60s budget — stops a carrier from satisfying its whole minute quota in an
        // early burst and then going silent for the rest of the minute. A 10s window keeps the
        // default packet rate low (~6/min/carrier) while bounding the idle gap to ~10s. Runs
        // every ping-check tick (~500 ms) so the top-up lands inside the window it counts toward.
        const unsigned min_bpm = args.config.min_data_per_minute;
        if (min_bpm > 0) {
          const uint64_t window_ns = 10000000000ULL;                    // 10 s
          const uint64_t target = std::max<uint64_t>(1, min_bpm / 6);   // bytes per 10s window
          const size_t pkt_max = std::max<size_t>(1, effective_max_packet);
          for (auto& [cfd, cs] : carriers) {
            if (cs.connecting) continue;
            if (now_p - cs.last_window_reset_ns >= window_ns) {
              cs.bytes_sent_this_window = 0;
              cs.last_window_reset_ns = now_p;
            }
            if (cs.bytes_sent_this_window < target && cs.write_buf.empty()) {
              size_t len = std::min<size_t>(target - cs.bytes_sent_this_window, pkt_max);
              std::vector<uint8_t> payload(len);
              std::uniform_int_distribution<int> byte_dist(0, 255);
              for (size_t i = 0; i < len; ++i) payload[i] = static_cast<uint8_t>(byte_dist(keepalive_gen));
              packet_io::append_ping(cs.write_buf, next_send_id, payload.data(), len);
              outstanding_pings[{cfd, next_send_id}] = now_p;
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = cfd;
              epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
            }
          }
        }

        // Prune long-unanswered pings (e.g. a min-data keepalive whose PONG was lost) so
        // outstanding_pings can't grow without bound. We no longer reap on an unanswered
        // ping — a single lost PONG on an otherwise-healthy carrier must not kill it;
        // dead-carrier handling is the group detection above (rx-dead + server report).
        {
          uint64_t ping_stale_ns = scaled_ns(6, 15000000000ULL, 120000000000ULL);
          for (auto it = outstanding_pings.begin(); it != outstanding_pings.end(); ) {
            if (now_p - it->second > ping_stale_ns) it = outstanding_pings.erase(it);
            else ++it;
          }
        }

        size_t dead_reap_added = 0;
        size_t backlog_bytes = 0;
        for (const auto& [_, ui] : unacked_sends) backlog_bytes += ui.data.size();
        const bool heavy_backlog = carrier_adapt::is_heavy_backlog(backlog_bytes, unacked_sends.size());

        // Release excess carriers when the load-driven target (Lever 1) has fallen below the
        // current count: offered load dropped, so the extra carriers aren't needed — shrink
        // back toward the target so the count tracks load instead of ratcheting up. A slow
        // rate (1 per interval) plus the target's own smoothing avoids oscillation. Runs in
        // ALL modes (the dead-idle reap below is gated and skipped in light SSH traffic, which
        // would otherwise leave grown carriers stuck forever).
        if (args.config.auto_adapt && carriers.size() > desired_carriers_dyn && !heavy_backlog
            && now_p - last_excess_release_ns >= excess_release_interval_ns) {
          int to_close = -1;
          for (auto& [cfd, cs] : carriers) {
            if (cs.connecting) continue;
            if (std::find(pending_reap.begin(), pending_reap.end(), cfd) != pending_reap.end()) continue;
            to_close = cfd; break;
          }
          if (to_close >= 0) {
            last_excess_release_ns = now_p;
            packet_io::append_suggest_close(carriers[to_close].write_buf);
            ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = to_close;
            epoll_ctl(epfd, EPOLL_CTL_MOD, to_close, &ev);
            remove_carrier(to_close, "excess_release");
          }
        }

        // In SSH mode, false-positive dead-idle classification can trigger
        // self-inflicted carrier churn. Only run dead-idle reap logic when
        // backlog pressure is genuinely high.
        if (args.unix_socket_connection.empty() && !heavy_backlog) {
          // Skip this cycle; keep carriers and rely on concrete read errors / peer signals.
          continue;
        }
        size_t dead_reap_cap = heavy_backlog
            ? std::max<size_t>(3, target_carriers)
            : std::max<size_t>(1, target_carriers / 5);
        size_t pending_cap = heavy_backlog
            ? std::max<size_t>(6, target_carriers)
            : std::max<size_t>(3, target_carriers / 3);
        for (int cfd : quality.dead_idle_fds) {
          // Avoid mass-close cascades: only schedule a small number of dead-idle
          // carriers per ping cycle, and never let pending_reap grow unbounded.
          if (pending_reap.size() >= pending_cap) break;
          if (dead_reap_added >= dead_reap_cap) break;
          // Tell the server this carrier is about to be closed so it can stop
          // sending on it immediately. We may delay our own close slightly
          // (pending_reap path) to drain any in-flight data, but once the server
          // sees SUGGEST_CLOSE it will close fd on its side.
          if (auto itc = carriers.find(cfd); itc != carriers.end()) {
            packet_io::append_suggest_close(itc->second.write_buf);
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = cfd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
          }
          if (carriers.size() > target_carriers) {
            // Above target and dead: close immediately so floor maintenance can add
            // fresh replacements without waiting for the 60s slow-reduction rate limit.
            // Keeping dead fds in carriers.size() would block new connections for minutes.
            remove_carrier(cfd, "dead_idle");
          } else {
            // At or below target: wait for a replacement to connect before closing,
            // so we don't drop below the carrier floor during reconnection.
            add_to_pending_reap(cfd, "dead_idle");
          }
          dead_reap_added++;
        }

        // When above target: slowly close HEALTHY pending-reap carriers (1 per 60s).
        // Dead carriers above target are handled immediately above; this path only
        // applies to live-but-scheduled-for-replacement carriers (e.g. rtt_outlier).
        if (carriers.size() > target_carriers && !pending_reap.empty()
            && now_p - last_reduction_close_ns >= reduction_close_interval_ns) {
          last_reduction_close_ns = now_p;
          int to_close = pending_reap.front();
          pending_reap.erase(pending_reap.begin());
          remove_carrier(to_close, "slow_reduction");
        }

        for (auto& [cfd, cs] : carriers)
          if (cs.last_recv_ns > last_global_recv_ns) last_global_recv_ns = cs.last_recv_ns;

        // Adaptive default is 12×RTT, clamped [60 s, 300 s]. To survive a longer outage
        // (e.g. a multi-minute VPN/wifi drop) so the logical SSH stream can recover, set
        // --reconnect-timeout (both ends must outlast the outage or they give up before
        // the link returns).
        uint64_t global_idle_ns = (args.config.reconnect_timeout_sec > 0)
            ? (uint64_t)args.config.reconnect_timeout_sec * 1000000000ULL
            : scaled_ns(12, 60000000000ULL, 300000000000ULL);
        if (now_p - last_global_recv_ns > global_idle_ns) {
          if (dbg) fprintf(dbg, "[global-idle-timeout t=%llu last_recv_ms=%llu threshold_ms=%llu]\n",
                           (unsigned long long)(now_p/1000000ULL),
                           (unsigned long long)(last_global_recv_ns/1000000ULL),
                           (unsigned long long)(global_idle_ns/1000000ULL));
          running = false;
        }
      }
    }

    if (args.config.auto_adapt && !carriers.empty()) {
      const uint64_t now = now_ns();

      // Carrier target (Lever 1, primary) = load × loss. Measure the fleet packet rate (c2s
      // shards/copies we send + s2c shards we receive, both incl. redundancy) and cap each
      // carrier's load at ~tau packets per recovery window W (= RTT): n* = ceil(R·W/tau) —
      // BUT only when the link is actually stalling (s2c stall fraction `s2c_loss_q` >= gate).
      // A clean link (no stalls) stays at the floor regardless of throughput, so a fast flood
      // is not over-provisioned; a lossy/overloaded link spreads its load out. A lossy but
      // low-rate (interactive) link also stays near the floor — its carriers aren't overloaded
      // — and lets redundancy cover the loss. Sizing from the rate (not feeding back on n)
      // keeps it stable: a transient stall spike can't ratchet the count up. The c2s direction
      // is covered by the server's redundancy (Lever 2). Redundancy never feeds carrier growth.
      if (load_window_start_ns == 0) load_window_start_ns = now;
      uint64_t load_elapsed = now - load_window_start_ns;
      if (load_elapsed >= 1000000000ULL) {
        double secs = static_cast<double>(load_elapsed) / 1e9;
        double rate = static_cast<double>(c2s_packets_sent_window + s2c_shards_recv_window) / secs;
        measured_pkt_rate = (measured_pkt_rate > 0.0) ? (0.5 * measured_pkt_rate + 0.5 * rate) : rate;
        c2s_packets_sent_window = 0;
        s2c_shards_recv_window = 0;
        load_window_start_ns = now;
        static constexpr double kTargetPktsPerCarrier = 1.5;   // tau
        static constexpr double kStallGate = 0.01;             // below this, treat as clean
        desired_carriers_dyn = carrier_adapt::carrier_target_for_load(
            measured_pkt_rate, get_effective_rtt_ns(), kTargetPktsPerCarrier,
            static_cast<double>(s2c_loss_q), kStallGate, target_carriers, max_connections);
      }

      // Compute per-carrier stats for both carrier-add and reaping decisions.
      size_t total_write = 0;
      std::vector<uint64_t> rtt_samples;
      for (const auto& [cfd, st] : carriers) {
        (void)cfd;
        total_write += st.write_buf.size();
        if (st.last_rtt_ns > 0) rtt_samples.push_back(st.last_rtt_ns);
      }
      // Carrier quality (same logic as server; client does the actual close).
      std::vector<carrier_adapt::CarrierInfo> carrier_infos;
      for (auto& [cfd, st] : carriers) {
        if (st.connecting) continue;
        carrier_infos.push_back({cfd, st.last_rtt_ns, st.last_recv_ns, st.connect_ns, st.last_send_ns});
      }
      auto quality = carrier_adapt::assess_carriers(carrier_infos, now, scaled_ns);
      bool rtt_outlier = (quality.rtt_outlier_fd >= 0);

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

      // Link-stall recovery: the carrier count is steady but nothing is arriving — the
      // existing carriers are most likely dead-but-still-connected (a blackout that blocked
      // traffic without dropping the TCP sockets, so they never error and zombie/rx-dead
      // detection — which needs a live peer or an advancing last_send — can't fire). Open
      // FRESH carriers to bypass them; a new connection re-establishes the path the moment
      // the link returns. This is an explicit, redundancy-independent recovery trigger — it
      // replaces the old behaviour where redundancy_pressure happened to keep adding carriers
      // during an outage. Two ways to detect the stall:
      //   • fast path — we have data outstanding (unacked) and nothing has come back for a
      //     short, RTT-scaled silence (bidirectional / client→server traffic);
      //   • slow path — we have received NOTHING for longer than the keepalive interval, even
      //     though we keep sending min-data keepalives (covers server→client-only traffic,
      //     where unacked_sends is always empty so the fast path can't fire). The threshold
      //     must exceed the ~10 s keepalive so a healthy-but-idle link (whose PONGs keep recv
      //     fresh) is not mistaken for a stall.
      uint64_t stall_recovery_interval_ns = scaled_ns(4, 2000000000ULL, 15000000000ULL);
      uint64_t recv_silence_ns = (last_global_recv_ns > 0) ? (now - last_global_recv_ns) : 0;
      bool stalled_with_pending = !unacked_sends.empty()
                                  && recv_silence_ns > scaled_ns(4, 2000000000ULL, 30000000000ULL);
      bool stalled_silent = recv_silence_ns > scaled_ns(8, 15000000000ULL, 60000000000ULL);
      bool link_stalled = args.config.auto_adapt
                          && last_global_recv_ns > 0
                          && (stalled_with_pending || stalled_silent)
                          && (now - last_stall_recovery_add_ns >= stall_recovery_interval_ns
                              || last_stall_recovery_add_ns == 0);
      if (link_stalled && add_interval > stall_recovery_interval_ns)
        add_interval = stall_recovery_interval_ns;

      if (carriers.size() < max_connections && now - last_add_carrier_ns >= add_interval) {
        // Carrier-add triggers (load and health only — redundancy NO LONGER drives growth):
        //   1. Load pressure: the load-driven target wants more carriers (Lever 1) so each
        //      carrier carries only ~tau packets per recovery window.
        //   2. Write backlog: existing carriers can't drain fast enough (throughput need).
        //   3. RTT outlier: one carrier is clearly stalled vs peers; open a replacement.
        //   4./5. rs_pending pressure: a direction has many RS groups stuck (safety valve on a
        //      very lossy path; with redundancy properly sized this rarely fires).
        //   6. Link stall: pending data + prolonged receive-silence → bypass dead carriers.
        // Redundancy is the server's Lever 2 and is decoupled from carrier count, so a lossy
        // link raises parity (bounded) without dragging the carrier count to max_connections.
        // load_pressure only grows ABOVE the floor — below the floor is the dedicated
        // floor-maintenance block's job, which BURSTS multiple carriers per interval. Both
        // paths share last_add_carrier_ns, and this (earlier) block runs first; if
        // load_pressure fired below the floor it would add a single carrier and starve the
        // burst, slowing the initial ramp to --connections from ~5/100ms to ~1/100ms.
        // Saturated send window => the link is already at capacity and the ACK-clocked
        // window deliberately forbids more bytes in flight: spreading the SAME bounded
        // bytes across more carriers cannot raise throughput, yet the stall fraction
        // stays high on a capacity-limited queue and would otherwise grow the fleet to
        // max_connections (observed: steady growth 8->120 while unacked stayed at the
        // ~5-group window cap). Gate load presses on window headroom: growth under load
        // is only meaningful while the window is open (real packet loss with spare
        // capacity), which is exactly when the flood-latency sim pins the cap closed.
        uint64_t c2s_outstanding_for_gate = 0;
        for (const auto& [uid, ui] : unacked_sends) c2s_outstanding_for_gate += ui.data.size();
        const bool window_saturated = server_s2c_window_saturated
            || (c2s_outstanding_for_gate >= rate_window_cap(c2s_window, get_window_base_rtt_ns()) * 3 / 4);
        bool load_pressure = !window_saturated
                             && (carriers.size() >= target_carriers)
                             && (carriers.size() < desired_carriers_dyn);
        bool need_replacement = !pending_reap.empty() && carriers.size() <= target_carriers;
        bool need_more = load_pressure
                         || (total_write > backpressure_write_threshold)
                         || (rtt_outlier && !unacked_sends.empty())  // no replace-add when idle
                         || any_rs_pending_pressure
                         || link_stalled
                         || need_replacement;
        if (need_more) {
          last_add_carrier_ns = now;
          if (any_rs_pending_pressure)
            last_rs_pending_pressure_add_ns = now;
          if (link_stalled)
            last_stall_recovery_add_ns = now;
          if (!args.unix_socket_connection.empty()) {
            int fd = connect_unix(socket_path);
            if (fd >= 0) {
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
                CarrierState& cs = carriers[fd];
                cs.connecting = true;
                if (cs.carrier_id == 0) cs.carrier_id = next_carrier_id_global++;
                const char* add_reason =
                    (total_write > backpressure_write_threshold) ? "backpressure" :
                    (rtt_outlier && !unacked_sends.empty()) ? "rtt_outlier" :
                    load_pressure ? "load_pressure" :
                    link_stalled ? "link_stall" :
                    any_rs_pending_pressure ? "rs_pending_pressure" :
                    need_replacement ? "need_replacement" : "need_more";
                if (dbg) fprintf(dbg, "[carrier-add t=%llu fd=%d total=%zu reason=%s]\n",
                                 (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size(), add_reason);
              } else
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
                std::vector<const char*> argv_vec;
                argv_vec.push_back("ssh");
                argv_vec.push_back("-n");
                argv_vec.push_back("-N");
                argv_vec.push_back("-o");
                argv_vec.push_back("ExitOnForwardFailure=yes");
                char ct_buf[64];
                if (args.config.connect_timeout_sec > 0) {
                  snprintf(ct_buf, sizeof ct_buf, "ConnectTimeout=%u", args.config.connect_timeout_sec);
                  argv_vec.push_back("-o");
                  argv_vec.push_back(ct_buf);
                }
                argv_vec.push_back("-L");
                argv_vec.push_back(spec.c_str());
                argv_vec.push_back(args.lossy_ssh_host.c_str());
                argv_vec.push_back(nullptr);
                execvp("ssh", const_cast<char* const*>(argv_vec.data()));
                _exit(127);
              }
              if (pid > 0) {
                ssh_idx_to_pid[free_idx] = pid;
                pending_carrier_paths.push_back(path);
                pending_connect_started_ns[free_idx] = now_ns();
                if (free_idx >= next_carrier_index) next_carrier_index = free_idx + 1;
                const char* add_reason =
                    (total_write > backpressure_write_threshold) ? "backpressure" :
                    (rtt_outlier && !unacked_sends.empty()) ? "rtt_outlier" :
                    load_pressure ? "load_pressure" :
                    link_stalled ? "link_stall" :
                    any_rs_pending_pressure ? "rs_pending_pressure" :
                    need_replacement ? "need_replacement" : "need_more";
                if (dbg) fprintf(dbg, "[carrier-add-initiated t=%llu path=%s reason=%s]\n",
                                 (unsigned long long)(now_ns()/1000000ULL), path.c_str(), add_reason);
              }
            }
          }
        }
      }

      // Carrier reaping: add to pending_reap; close only when a replacement has connected.
      // Two criteria (either triggers):
      //   1. RTT outlier: last_rtt_ns > 5× median AND > 3×RTT (stalled on client→server path).
      //   2. Silence: no shard received from server in N×RTT while other carriers are active
      //      (stalled on server→client path).
      // Skip during initial handshake (unacked data + few RTT samples).
      // Skip RTT outlier when idle: a slower carrier still works (PING/PONG keeps it alive).
      const bool early_handshake = (unacked_sends.size() > 0 && rtt_samples.size() < 10);
      const bool idle = unacked_sends.empty();
      if (!early_handshake && now - last_reap_ns >= reap_check_interval_ns) {
        last_reap_ns = now;

        if (!idle && quality.rtt_outlier_fd >= 0)
          add_to_pending_reap(quality.rtt_outlier_fd, "rtt_outlier");

        uint64_t latest_recv = 0;
        for (auto& [fd, st] : carriers)
          if (st.last_recv_ns > latest_recv) latest_recv = st.last_recv_ns;
        uint64_t silence_reap_ns = scaled_ns(4, 20000000000ULL, 60000000000ULL);
        if (latest_recv + 5000000000ULL > now) {
          for (auto& [fd, st] : carriers)
            if (st.last_recv_ns > 0 && st.last_recv_ns + silence_reap_ns < now)
              add_to_pending_reap(fd, "silence_reap");
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
        // 4×RTT, floored at 500 ms (not 2 s). On the test link (50 ms latency, ~100 ms RTT)
        // the old 2 s floor meant a dying carrier caused a 2+ s stall before retransmit.
        // 500 ms is still 5× the one-way latency on that link — conservative enough to
        // avoid duplicate traffic on healthy connections, aggressive enough to recover fast.
        // With ≥2 samples, scale from observed RTT. Before that, honor the --rtt-ms
        // cold-start hint (scaled_ns falls back to it) so high-latency links don't get
        // spuriously retransmitted every 2.5 s before the first ACKs arrive; only use the
        // 2.5 s floor when neither samples nor a hint are available.
        uint64_t retransmit_timeout_ns = (recent_rtt_ns.size() >= 2 || args.config.rtt_hint_ms > 0)
            ? scaled_ns(4, 500000000ULL, 60000000000ULL)
            : 2500000000ULL;  // 2.5 s when no RTT samples and no hint (cold start)
        // Collect all ready (non-connecting) carriers for round-robin retransmit.
        // Spreading shards across multiple carriers means no single carrier failure
        // can wipe out a retransmit attempt.
        std::vector<int> rt_carriers;
        for (auto& [cfd, cs] : carriers)
          if (!cs.connecting) rt_carriers.push_back(cfd);
        if (!rt_carriers.empty()) {
          unsigned rt_idx = 0;
          const unsigned small_rt_copies = std::max(1u, std::min(3u, static_cast<unsigned>(rt_carriers.size())));
          // Bound work per cycle: the receiver delivers in order and is blocked only on the
          // lowest unacked id, so retransmit the lowest N due items (the gap is always
          // covered) rather than the whole backlog, which starves the loop after a long
          // outage. Higher ids are reached on later cycles. (Mirrors the server.)
          const size_t kMaxRetransmitItemsPerCycle = 64;
          size_t rt_items = 0;
          for (auto& [uid, ui] : unacked_sends) {
            if (ui.send_ns == 0 || now_p - ui.send_ns < retransmit_timeout_ns) continue;
            if (rt_items >= kMaxRetransmitItemsPerCycle) break;
            ++rt_items;
            if (ui.is_small) {
              // Choose only carriers that have not yet carried this SMALL packet.
              std::vector<int> candidates;
              for (int cfd : rt_carriers) {
                auto itc = carriers.find(cfd);
                if (itc == carriers.end()) continue;
                uint64_t cid = itc->second.carrier_id;
                if (!ui.small_sent_on.count(cid)) candidates.push_back(cfd);
              }
              // If every live carrier has already carried this SMALL packet, reset
              // the history and allow another round across all carriers so we don't
              // get permanently stuck with an undeliverable id.
              if (candidates.empty()) {
                candidates = rt_carriers;
                ui.small_sent_on.clear();
              }
              if (!candidates.empty()) {
                unsigned copies = std::min(small_rt_copies, static_cast<unsigned>(candidates.size()));
                if (dbg) fprintf(dbg, "[retransmit-small t=%llu uid=%llu age_ms=%llu copies=%u]\n",
                                 (unsigned long long)(now_p/1000000ULL), (unsigned long long)uid,
                                 (unsigned long long)((now_p - ui.send_ns)/1000000ULL), copies);
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
                // For each shard index, avoid retransmitting on carriers that have
                // already carried this shard for this uid.
                auto& sent_set = ui.rs_shard_sent_on[si];
                std::vector<int> shard_candidates;
                for (int cfd : rt_carriers) {
                  auto itc = carriers.find(cfd);
                  if (itc == carriers.end()) continue;
                  uint64_t cid = itc->second.carrier_id;
                  if (!sent_set.count(cid)) shard_candidates.push_back(cfd);
                }
                // If every live carrier has already carried this shard, clear the
                // history and allow another full round on all carriers.
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
              if (dbg && !touched.empty()) fprintf(dbg, "[retransmit-rs t=%llu uid=%llu age_ms=%llu n=%u k=%u carriers=%zu unique_cfds=%zu]\n",
                               (unsigned long long)(now_p/1000000ULL), (unsigned long long)uid,
                               (unsigned long long)((now_p - ui.send_ns)/1000000ULL),
                               ui.n, ui.k, rt_carriers.size(), touched.size());
              for (int cfd : touched) {
                ev.events = EPOLLIN | EPOLLOUT; ev.data.fd = cfd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
              }
              rt_idx += ui.n;
            }
            // Reset send_ns so we don't retransmit this group again for another 3 s.
            ui.send_ns = now_p;
            ui.retransmitted = true;  // Karn: don't time this id's ACK as RTT
          }
        }
      }

      // ── Debug: periodic state dump ────────────────────────────────────────
      if (dbg) {
        size_t unacked_bytes = 0;
        for (const auto& [_, ui] : unacked_sends) unacked_bytes += ui.data.size();
        if (rs_pending.empty()) {
          fprintf(dbg, "[cli] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=0 next_deliver_id=%llu next_send_id=%llu stdout_buf=%zu rs_redundancy=%.2f small_packet_copies=%u server_rs_pending=%u\n",
                  carriers.size(), unacked_sends.size(), unacked_bytes, reassembly.size(),
                  (unsigned long long)next_deliver_id, (unsigned long long)next_send_id, stdout_buf.size(),
                  (double)effective_rs_redundancy, (unsigned)effective_small_packet_redundancy, (unsigned)server_rs_pending_count);
        } else {
          auto it = rs_pending.begin();
          fprintf(dbg, "[cli] carriers=%zu unacked=%zu unacked_bytes=%zu reassembly=%zu rs_pending=%zu next_deliver_id=%llu next_send_id=%llu stdout_buf=%zu rs_redundancy=%.2f small_packet_copies=%u server_rs_pending=%u first_rs_id=%llu shards=%zu k=%u n=%u\n",
                  carriers.size(), unacked_sends.size(), unacked_bytes, reassembly.size(), rs_pending.size(),
                  (unsigned long long)next_deliver_id, (unsigned long long)next_send_id, stdout_buf.size(),
                  (double)effective_rs_redundancy, (unsigned)effective_small_packet_redundancy, (unsigned)server_rs_pending_count,
                  (unsigned long long)it->first, it->second.shards.size(), it->second.k, it->second.n);
        }
        fflush(dbg);
      }

      // RS stale-group drain: evict incomplete groups from memory after 4×RTT (min 10 s).
      // We do NOT jump next_deliver_id here. Jumping would introduce a hole in the SSH
      // byte stream, which SSH detects as a MAC failure and closes the connection — exactly
      // the "stall is the last thing" symptom. Instead we wait for the retransmit path
      // to fill any gap. If the sender is truly dead, global_idle_ns closes the connection.
      if (now_p - last_rs_drain_ns >= 1000000000ULL) {
        last_rs_drain_ns = now_p;
        uint64_t rs_stale_ns = scaled_ns(4, 10000000000ULL, 60000000000ULL);
        // Evict stale incomplete RS groups (memory management only — no gap-jump).
        // When the sender retransmits, fresh shards will repopulate rs_pending and
        // the group will decode normally once k shards accumulate.
        for (auto it = rs_pending.begin(); it != rs_pending.end(); ) {
          if (it->second.first_recv_ns > 0 && now_p - it->second.first_recv_ns > rs_stale_ns) {
            if (dbg) fprintf(dbg, "[rs-stale-evict t=%llu id=%llu age_ms=%llu shards_had=%zu k=%u n=%u]\n",
                             (unsigned long long)(now_p/1000000ULL), (unsigned long long)it->first,
                             (unsigned long long)((now_p - it->second.first_recv_ns)/1000000ULL),
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
            // Gap: ID is absent from both reassembly and rs_pending.
            // Do NOT jump — wait for the retransmit to fill it.
            bool has_higher = !reassembly.empty() || !rs_pending.empty();
            if (!has_higher) { next_deliver_id_stuck_since_ns = 0; break; }
            if (next_deliver_id_stuck_since_ns == 0) {
              next_deliver_id_stuck_since_ns = now_p;
              if (dbg) fprintf(dbg, "[gap-detected t=%llu next_deliver_id=%llu reassembly=%zu rs_pending=%zu]\n",
                               (unsigned long long)(now_p/1000000ULL), (unsigned long long)next_deliver_id,
                               reassembly.size(), rs_pending.size());
            }
            break;
          }
        }
      }
    }

    // ── Unconditional floor maintenance ─────────────────────────────────────
    // Keep at least target_carriers connections. Add replacements when pending_reap
    // non-empty and at or below target. When above target, we don't add—we slowly
    // close from pending (in the ping-check block). When carriers.empty(), the
    // auto_adapt block is skipped, so this path is essential.
    // On mass death (carriers.empty()), burst-add multiple to recover quickly.
    {
      const uint64_t now_f = now_ns();
      const uint64_t floor_interval = carriers.empty()
                                        ? 50000000ULL          // 50 ms when all are gone
                                        : add_carrier_interval_ns;  // 100 ms otherwise
      bool need_replacements = !pending_reap.empty() && carriers.size() <= target_carriers;
      if ((carriers.size() < target_carriers || need_replacements)
          && now_f - last_add_carrier_ns >= floor_interval) {
        last_add_carrier_ns = now_f;
        // When below floor: burst to reach target quickly (e.g. 5→10). Cap at target so we don't overshoot.
        // Count pending SSH connects—they take seconds to establish; without this we'd burst every 100ms
        // and overshoot to 100+ when links are slow.
        size_t in_flight = carriers.size() + pending_carrier_paths.size();
        unsigned to_floor = (in_flight < target_carriers)
            ? static_cast<unsigned>(target_carriers - in_flight) : 0u;
        unsigned add_limit = (to_floor > 0) ? std::min(5u, to_floor) : 1u;
        bool can_add = (add_limit > 1) || pending_carrier_paths.empty();
        if (!can_add) { /* skip */ }
        else if (!args.unix_socket_connection.empty()) {
          if (dbg && carriers.empty())
            fprintf(dbg, "[carrier-add-attempt t=%llu reason=mass_death connecting_to_socket trying=%u]\n",
                    (unsigned long long)(now_ns()/1000000ULL), add_limit);
          for (unsigned j = 0; j < add_limit && carriers.size() < max_connections; ++j) {
            int fd = connect_unix(socket_path);
            if (fd >= 0) {
              ev.events = EPOLLIN | EPOLLOUT;
              ev.data.fd = fd;
              if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
                CarrierState& cs = carriers[fd];
                cs.connecting = true;
                if (cs.carrier_id == 0) cs.carrier_id = next_carrier_id_global++;
                const char* floor_reason = carriers.empty() ? "mass_death" : "below_floor";
                if (dbg) fprintf(dbg, "[carrier-add t=%llu fd=%d total=%zu reason=%s]\n",
                                 (unsigned long long)(now_ns()/1000000ULL), fd, carriers.size(), floor_reason);
              } else
                close(fd);
            }
          }
        } else {
          if (dbg && carriers.empty())
            fprintf(dbg, "[carrier-add-attempt t=%llu reason=mass_death starting_ssh count=%u waiting_for_connect]\n",
                    (unsigned long long)(now_ns()/1000000ULL), add_limit);
          for (unsigned j = 0; j < add_limit; ++j) {
            unsigned free_idx = find_free_ssh_index();
            if (free_idx >= max_connections) break;
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
              std::vector<const char*> argv_vec;
              argv_vec.push_back("ssh");
              argv_vec.push_back("-n");
              argv_vec.push_back("-N");
              argv_vec.push_back("-o");
              argv_vec.push_back("ExitOnForwardFailure=yes");
              char ct_buf[64];
              if (args.config.connect_timeout_sec > 0) {
                snprintf(ct_buf, sizeof ct_buf, "ConnectTimeout=%u", args.config.connect_timeout_sec);
                argv_vec.push_back("-o");
                argv_vec.push_back(ct_buf);
              }
              argv_vec.push_back("-L");
              argv_vec.push_back(spec.c_str());
              argv_vec.push_back(args.lossy_ssh_host.c_str());
              argv_vec.push_back(nullptr);
              execvp("ssh", const_cast<char* const*>(argv_vec.data()));
              _exit(127);
            }
            if (pid > 0) {
              ssh_idx_to_pid[free_idx] = pid;
              pending_carrier_paths.push_back(path);
              pending_connect_started_ns[free_idx] = now_ns();
              if (free_idx >= next_carrier_index) next_carrier_index = free_idx + 1;
              const char* floor_reason = carriers.empty() ? "mass_death" : "below_floor";
              if (dbg) fprintf(dbg, "[carrier-add-initiated t=%llu path=%s reason=%s]\n",
                               (unsigned long long)(now_ns()/1000000ULL), path.c_str(), floor_reason);
            }
          }
        }
      }
    }

    // When recovering from mass death (carriers.empty()), log periodically to debug file.
    if (dbg && carriers.empty()) {
      const uint64_t now_r = now_ns();
      if (now_r - last_recovery_log_ns >= 5000000000ULL) {  // every 5 s
        last_recovery_log_ns = now_r;
        if (!pending_carrier_paths.empty())
          fprintf(dbg, "[carrier-recovery-wait t=%llu pending=%zu waiting_for_ssh_connect]\n",
                  (unsigned long long)(now_r/1000000ULL), pending_carrier_paths.size());
        else if (!args.unix_socket_connection.empty())
          fprintf(dbg, "[carrier-recovery-wait t=%llu retrying_unix_connect]\n",
                  (unsigned long long)(now_r/1000000ULL));
      }
    }

    // ── Re-arm stdin if it was throttled ────────────────────────────────────
    // Re-register STDIN with epoll once stdin_buf has drained below the throttle
    // threshold (purely buffer-driven: with the send-window gate there may be
    // carriers up yet no room to push more data right now).
    if (!stdin_in_epoll && !stdin_eof && stdin_buf.size() < STDIN_THROTTLE_BYTES) {
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
      if (!can_reconnect) {
        if (dbg) fprintf(dbg, "[client-exit-no-reconnect t=%llu carriers=%zu]\n",
                         (unsigned long long)(now_ns()/1000000ULL), carriers.size());
        running = false;
      }
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
