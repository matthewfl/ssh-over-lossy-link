#include "ssholl.h"
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

const size_t MAX_PACKET_PAYLOAD = 65536;
const size_t READ_BUF_SIZE = 65536;

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

struct CarrierState {
  std::vector<uint8_t> read_buf;
  std::vector<uint8_t> write_buf;
  size_t write_pos = 0;
  bool connecting = true;
  uint64_t last_rtt_ns = 0;  // last measured RTT for this link (from ACK)
};

// Per-id state when collecting Reed-Solomon shards.
struct RsPending {
  unsigned n = 0;
  unsigned k = 0;
  size_t block_size = 0;
  std::map<unsigned, std::vector<uint8_t>> shards;
};

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
  unsigned next_carrier = 0;
  const size_t max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));
  auto now_ns = []() {
    return static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  };
  std::map<int, std::deque<std::pair<uint64_t, uint64_t>>> carrier_pending_acks;  // fd -> [(id, time_ns)]

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
    CarrierState& s = it->second;
    PacketHeader h{};
    h.id = next_send_id;
    h.packet_kind = PacketKind::SMALL;
    uint16_t size = static_cast<uint16_t>(len);
    s.write_buf.insert(s.write_buf.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
    s.write_buf.insert(s.write_buf.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof size);
    s.write_buf.insert(s.write_buf.end(), data, data + len);
    if (!same_id)
      next_send_id++;
  };

  // Queue one Reed-Solomon shard to one carrier (same id for all shards in block).
  auto queue_rs_shard_to_carrier = [&](int fd, unsigned n, unsigned k, uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    carrier_pending_acks[fd].emplace_back(next_send_id, now_ns());
    CarrierState& s = it->second;
    PacketHeader h{};
    h.id = next_send_id;
    h.packet_kind = PacketKind::REED_SOLOMON;
    uint16_t size = block_size;
    s.write_buf.insert(s.write_buf.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
    s.write_buf.insert(s.write_buf.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof size);
    s.write_buf.push_back(static_cast<uint8_t>(n));
    s.write_buf.push_back(static_cast<uint8_t>(k));
    s.write_buf.push_back(static_cast<uint8_t>(shard_index));
    s.write_buf.insert(s.write_buf.end(), shard_data, shard_data + block_size);
  };

  auto flush_stdout = [&]() {
    while (!stdout_buf.empty()) {
      ssize_t n = write(STDOUT_FILENO, stdout_buf.data(), stdout_buf.size());
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        break;
      }
      stdout_buf.erase(stdout_buf.begin(), stdout_buf.begin() + n);
    }
  };

  auto deliver_to_stdout = [&]() {
    while (reassembly.count(next_deliver_id)) {
      std::vector<uint8_t>& vec = reassembly[next_deliver_id];
      while (!vec.empty()) {
        if (stdout_buf.empty()) {
          ssize_t n = write(STDOUT_FILENO, vec.data(), vec.size());
          if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              stdout_buf.insert(stdout_buf.end(), vec.begin(), vec.end());
              vec.clear();
              ev.events = EPOLLOUT;
              ev.data.fd = STDOUT_FILENO;
              epoll_ctl(epfd, EPOLL_CTL_ADD, STDOUT_FILENO, &ev);
              reassembly.erase(next_deliver_id);
              next_deliver_id++;
              return;
            }
            break;
          }
          vec.erase(vec.begin(), vec.begin() + n);
        } else {
          flush_stdout();
          if (!stdout_buf.empty()) return;
        }
      }
      if (vec.empty()) {
        reassembly.erase(next_deliver_id);
        next_deliver_id++;
      }
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

    while (s.read_buf.size() >= sizeof(PacketHeader)) {
      const auto* h = reinterpret_cast<const PacketHeader*>(s.read_buf.data());
      if (h->packet_kind == PacketKind::ACK) {
        uint64_t acked_id = h->id;
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
        auto it_p = carrier_pending_acks.find(fd);
        if (it_p != carrier_pending_acks.end()) {
          uint64_t rtt_ns = 0;
          const uint64_t recv_time = now_ns();
          auto& q = it_p->second;
          while (!q.empty() && q.front().first <= acked_id) {
            rtt_ns = recv_time - q.front().second;
            q.pop_front();
          }
          if (rtt_ns != 0)
            s.last_rtt_ns = rtt_ns;
        }
        continue;
      }
      if (h->packet_kind == PacketKind::PONG) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
        continue;
      }
      if (h->packet_kind == PacketKind::SMALL) {
        if (s.read_buf.size() < sizeof(PacketSmall)) break;
        const auto* p = reinterpret_cast<const PacketSmall*>(s.read_buf.data());
        uint16_t size = p->size;
        if (size > MAX_PACKET_PAYLOAD) {
          s.read_buf.clear();
          break;
        }
        size_t total = sizeof(PacketHeader) + sizeof(uint16_t) + size;
        if (s.read_buf.size() < total) break;
        uint64_t id = h->id;
        if (id >= next_deliver_id && !reassembly.count(id))
          reassembly[id].assign(p->data, p->data + size);
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total);
        deliver_to_stdout();
        continue;
      }
      if (h->packet_kind == PacketKind::SET_CONFIG || h->packet_kind == PacketKind::START_CONNECTION) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
        continue;
      }
      if (h->packet_kind == PacketKind::REED_SOLOMON) {
        const size_t rs_fixed = sizeof(PacketHeader) + sizeof(uint16_t) + 3;  // +3 for n, k, shard_index
        if (s.read_buf.size() < rs_fixed) break;
        uint16_t block_sz = *reinterpret_cast<const uint16_t*>(s.read_buf.data() + sizeof(PacketHeader));
        const auto* prs = reinterpret_cast<const PacketReedSolomon*>(s.read_buf.data());
        size_t total_rs = rs_fixed + block_sz;
        if (block_sz == 0 || block_sz > MAX_PACKET_PAYLOAD || s.read_buf.size() < total_rs) break;
        uint64_t id = h->id;
        unsigned n = prs->n, k = prs->k;
        if (id < next_deliver_id) {
          s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
          continue;
        }
        if (n == 0 || k == 0 || k >= n || n > 256) {
          s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
          continue;
        }
        RsPending& rp = rs_pending[id];
        if (rp.k == 0) {
          rp.n = n;
          rp.k = k;
          rp.block_size = block_sz;
        }
        if (rp.n != n || rp.k != k || rp.block_size != block_sz) {
          s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
          continue;
        }
        unsigned idx = prs->shard_index;
        if (idx >= n) {
          s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
          continue;
        }
        if (!rp.shards.count(idx))
          rp.shards[idx].assign(prs->data, prs->data + block_sz);
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        if (rp.shards.size() >= k) {
          std::vector<const uint8_t*> recv_ptrs(k);
          std::vector<unsigned> recv_indices(k);
          unsigned fi = 0;
          for (auto& [shard_idx, vec] : rp.shards) {
            if (fi >= k) break;
            recv_ptrs[fi] = vec.data();
            recv_indices[fi] = shard_idx;
            fi++;
          }
          if (fi < k) continue;
          std::vector<std::vector<uint8_t>> out_shards(k, std::vector<uint8_t>(rp.block_size));
          std::vector<uint8_t*> out_ptrs(k);
          for (unsigned i = 0; i < k; ++i) out_ptrs[i] = out_shards[i].data();
          if (reed_solomon::decode(rp.n, rp.k, recv_ptrs.data(), recv_indices.data(), out_ptrs.data(), rp.block_size)) {
            if (!reassembly.count(id)) {
              reassembly[id].clear();
              for (unsigned i = 0; i < k; ++i)
                reassembly[id].insert(reassembly[id].end(), out_shards[i].begin(), out_shards[i].end());
            }
          }
          rs_pending.erase(id);
          deliver_to_stdout();
        }
        continue;
      }
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
    }
    return true;
  };

  auto flush_carrier_writes = [&]() {
    for (auto it = carriers.begin(); it != carriers.end(); ) {
      int fd = it->first;
      CarrierState& s = it->second;
      if (s.connecting) { ++it; continue; }
      while (s.write_pos < s.write_buf.size()) {
        ssize_t n = write(fd, s.write_buf.data() + s.write_pos, s.write_buf.size() - s.write_pos);
        if (n <= 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = fd;
            epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            break;
          }
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carrier_pending_acks.erase(fd);
          it = carriers.erase(it);
          goto next;
        }
        s.write_pos += n;
      }
      if (s.write_pos >= s.write_buf.size()) {
        s.write_buf.clear();
        s.write_pos = 0;
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
      }
      ++it;
      next:;
    }
  };

  std::vector<struct epoll_event> events(64);
  bool running = true;

  while (running) {
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), -1);
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
            if (nr == 0) stdin_eof = true;
            else if (errno != EAGAIN && errno != EWOULDBLOCK) stdin_eof = true;
            break;
          }
          stdin_buf.insert(stdin_buf.end(), buf, buf + nr);
        }
        while (stdin_buf.size() >= max_packet && !carriers.empty()) {
          const size_t block_size = max_packet;
          unsigned k = static_cast<unsigned>(std::min(stdin_buf.size() / block_size, static_cast<size_t>(255)));
          if (k == 0) break;
          unsigned m = std::max(1u, static_cast<unsigned>(k * args.config.rs_redundancy + 0.5f));
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
          next_send_id++;
          next_carrier += num_shards;
          stdin_buf.erase(stdin_buf.begin(), stdin_buf.begin() + k * block_size);
        }
        // Send any remainder smaller than one block as SMALL so we don't wait for EOF.
        if (!stdin_buf.empty() && stdin_buf.size() < max_packet && !carriers.empty()) {
          size_t chunk = stdin_buf.size();
          const unsigned n_copies = std::max(1u, std::min(static_cast<unsigned>(carriers.size()), args.config.small_packet_redundancy));
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
        if (e & EPOLLOUT) {
          flush_stdout();
          if (stdout_buf.empty()) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, STDOUT_FILENO, nullptr);
          }
        }
        continue;
      }

      auto it = carriers.find(fd);
      if (it != carriers.end()) {
        if (it->second.connecting && (e & EPOLLOUT)) {
          int err = get_so_error(fd);
          if (err == 0)
            it->second.connecting = false;
          else if (err != EINPROGRESS && err != 0) {
            close(fd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            carriers.erase(it);
            continue;
          }
        }
        if (e & EPOLLIN) {
          if (!process_carrier_read(fd, it->second)) {
            close(fd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
            carriers.erase(it);
            carrier_pending_acks.erase(fd);
          }
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
          carrier_pending_acks.erase(fd);
        }
      }
    }

    if (stdin_eof && !stdin_buf.empty() && !carriers.empty()) {
      while (!stdin_buf.empty()) {
        size_t chunk = std::min(stdin_buf.size(), max_packet);
        const bool small_packet = (chunk < max_packet);
        const unsigned n_copies = small_packet
            ? std::max(1u, std::min(static_cast<unsigned>(carriers.size()), args.config.small_packet_redundancy))
            : 1u;
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
    deliver_to_stdout();

    if (stdin_eof && stdin_buf.empty() && reassembly.empty() && stdout_buf.empty() && rs_pending.empty())
      running = false;
    if (carriers.empty() && reassembly.empty() && stdout_buf.empty() && rs_pending.empty())
      running = false;
  }

  for (auto& [fd, _] : carriers)
    close(fd);
  close(epfd);
  if (!args.unix_socket_connection.empty()) {
    // Direct Unix socket mode: no SSH processes or client_dir to clean up
  } else {
    for (pid_t p : ssh_pids)
      kill(p, SIGTERM);
    for (unsigned i = 0; i < N; ++i)
      unlink((client_dir + "/" + std::to_string(i)).c_str());
    rmdir(client_dir.c_str());
  }
  return 0;
}

}  // namespace ssholl
