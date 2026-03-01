#include "ssholl.h"
#include "packet_io.h"
#include "reed_solomon.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <random>
#include <string>
#include <vector>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
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
  // Timer to coalesce backend reads so multiple TCP segments are batched before we
  // process and send to carriers, giving symmetric min latency with client→TCP.
  constexpr long BACKEND_COALESCE_MS = 5;
  constexpr size_t BACKEND_COALESCE_MIN_BYTES = 800;  // wait for more if we have less
  int backend_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (backend_timer_fd < 0) {
    close(epfd);
    unlink(socket_path.c_str());
    return 1;
  }
  ev.events = EPOLLIN;
  ev.data.fd = backend_timer_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, backend_timer_fd, &ev) < 0) {
    close(backend_timer_fd);
    close(epfd);
    unlink(socket_path.c_str());
    return 1;
  }
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
  bool backend_timer_armed = false;
  int backend_coalesce_retries = 0;
  size_t max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));
  float runtime_rs_redundancy = args.config.rs_redundancy;
  unsigned runtime_small_packet_redundancy = args.config.small_packet_redundancy;
  unsigned next_carrier_for_rs = 0;

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
      ev.events = EPOLLIN | EPOLLOUT;
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

  auto queue_data_to_carriers = [&](const uint8_t* data, size_t len) {
    if (len == 0) return;
    for (auto& [fd, state] : carriers) {
      (void)fd;
      packet_io::append_small(state.write_buf, next_send_id, data, len);
    }
    next_send_id++;
  };

  auto queue_rs_shard_to_carrier = [&](int fd, unsigned n, unsigned k, uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_rs_shard(it->second.write_buf, next_send_id, n, k, block_size, shard_index, shard_data);
  };

  auto flush_carrier_writes = [&]() {
    packet_io::flush_carrier_writes(carriers, epfd, ev);
  };

  // Flush until all carrier write_bufs are sent (don't yield with partial data, which
  // would cause two 50ms proxy delays on the server→client link).
  auto flush_carrier_writes_until_done = [&]() {
    flush_carrier_writes();
    for (int round = 0; round < 50; ++round) {
      bool any_pending = false;
      for (const auto& [_, s] : carriers) {
        if (s.write_pos < s.write_buf.size()) { any_pending = true; break; }
      }
      if (!any_pending) break;
      struct epoll_event evs[64];
      int n = epoll_wait(epfd, evs, 64, 100);
      if (n <= 0) break;
      flush_carrier_writes();
    }
  };

  auto queue_ack_to_carrier = [&](int fd, uint64_t acked_id) {
    auto it = carriers.find(fd);
    if (it == carriers.end()) return;
    packet_io::append_ack(it->second.write_buf, acked_id);
  };

  // Delivered data is queued here; we write to backend and ACK when a chunk is fully written.
  std::deque<std::pair<uint64_t, std::vector<uint8_t>>> backend_pending;

  auto flush_backend_pending = [&]() {
    if (backend_fd < 0 || !backend_connected || backend_pending.empty()) return;
    auto& front = backend_pending.front();
    ssize_t n = write(backend_fd, front.second.data(), front.second.size());
    if (n <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = backend_fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
      }
      return;
    }
    front.second.erase(front.second.begin(), front.second.begin() + n);
    if (front.second.empty()) {
      uint64_t acked_id = front.first;
      backend_pending.pop_front();
      for (auto& [cfd, _] : carriers) {
        queue_ack_to_carrier(cfd, acked_id);
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = cfd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
      }
    }
  };

  packet_io::ReceiveCallbacks recv_cb;
  recv_cb.on_deliver = [&](uint64_t id, const uint8_t* data, size_t len) {
    backend_pending.push_back({id, std::vector<uint8_t>(data, data + len)});
    connect_backend();
  };
  recv_cb.on_ping = [&](int fd, uint64_t id) { send_pong(fd, id); };
  recv_cb.on_set_config = [&](const PacketConfig& pc) {
    max_packet = std::min(static_cast<size_t>(pc.packet_size), MAX_PACKET_PAYLOAD);
    if (max_packet == 0) max_packet = 800;
    runtime_small_packet_redundancy = pc.small_packet_redundancy;
    if (runtime_small_packet_redundancy == 0) runtime_small_packet_redundancy = 1;
    runtime_rs_redundancy = pc.reed_solomon_redundancy;
    if (runtime_rs_redundancy < 0.1f) runtime_rs_redundancy = 0.2f;
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
    int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), -1);
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
          const int sndbuf = 65536;
          setsockopt(client, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
          ev.events = EPOLLIN;
          ev.data.fd = client;
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, client, &ev) == 0) {
            carriers[client];  // default CarrierState
            if (backend_fd < 0)
              connect_backend();
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
          while (true) {
            ssize_t nr = read(backend_fd, buf, sizeof buf);
            if (nr <= 0) {
              if (nr == 0) running = false;
              else if (errno != EAGAIN && errno != EWOULDBLOCK) running = false;
              break;
            }
            backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
          }
          // Wait briefly for a following segment so we batch into one send (avoids two
          // 50ms proxy delays on server→client). Poll with 25ms timeout then drain again.
          struct pollfd pfd = { backend_fd, POLLIN, 0 };
          int pr = poll(&pfd, 1, 25);
          if (pr > 0 && (pfd.revents & POLLIN)) {
            while (true) {
              ssize_t nr = read(backend_fd, buf, sizeof buf);
              if (nr <= 0) {
                if (nr == 0) running = false;
                else if (errno != EAGAIN && errno != EWOULDBLOCK) running = false;
                break;
              }
              backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
            }
          }
          // Arm coalesce timer only if not already armed (process once after first segment).
          if (!backend_read_buf.empty() && !backend_timer_armed) {
            backend_timer_armed = true;
            struct itimerspec ts{};
            ts.it_value.tv_sec = 0;
            ts.it_value.tv_nsec = BACKEND_COALESCE_MS * 1000000L;
            ts.it_interval.tv_sec = 0;
            ts.it_interval.tv_nsec = 0;
            timerfd_settime(backend_timer_fd, 0, &ts, nullptr);
          }
        }
        if (e & EPOLLOUT) {
          flush_backend_pending();
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          running = false;
          break;
        }
        continue;
      }

      if (fd == backend_timer_fd) {
        uint64_t count = 0;
        if (read(backend_timer_fd, &count, sizeof count) >= 0) { /* consume */ }
        if (backend_fd >= 0 && backend_connected) {
          uint8_t buf[READ_BUF_SIZE];
          while (true) {
            ssize_t nr = read(backend_fd, buf, sizeof buf);
            if (nr <= 0) {
              if (nr == 0) running = false;
              else if (errno != EAGAIN && errno != EWOULDBLOCK) running = false;
              break;
            }
            backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
          }
        }
        if (backend_read_buf.size() > 0 && backend_read_buf.size() < BACKEND_COALESCE_MIN_BYTES &&
            backend_read_buf.size() >= max_packet && backend_coalesce_retries < 10) {
          backend_timer_armed = true;
          backend_coalesce_retries++;
          struct itimerspec ts{};
          ts.it_value.tv_sec = 0;
          ts.it_value.tv_nsec = 5 * 1000000L;
          ts.it_interval.tv_sec = 0;
          ts.it_interval.tv_nsec = 0;
          timerfd_settime(backend_timer_fd, 0, &ts, nullptr);
          continue;
        }
        backend_timer_armed = false;
        backend_coalesce_retries = 0;
        if (!backend_read_buf.empty() && !carriers.empty()) {
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
              for (auto& [cfd, _] : carriers) carrier_fds.push_back(cfd);
              for (size_t i = 0; i < n; ++i) {
                int cfd = carrier_fds[(next_carrier_for_rs + i) % carrier_fds.size()];
                const uint8_t* shard = (i < k) ? (backend_read_buf.data() + i * block_size) : parity[i - k].data();
                queue_rs_shard_to_carrier(cfd, n, k, static_cast<uint16_t>(block_size), static_cast<unsigned>(i), shard);
                ev.events = EPOLLIN | EPOLLOUT;
                ev.data.fd = cfd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
              }
              next_carrier_for_rs += n;
              next_send_id++;
              backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + k * block_size);
            } else {
              size_t chunk = std::min(backend_read_buf.size(), block_size);
              queue_data_to_carriers(backend_read_buf.data(), chunk);
              backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
            }
          } else {
            size_t chunk = backend_read_buf.size();
            queue_data_to_carriers(backend_read_buf.data(), chunk);
            backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
          }
          flush_carrier_writes_until_done();
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
          }
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
          close(fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
          carriers.erase(it);
        }
      }
    }

    ensure_backend_connected();
    flush_backend_pending();
    flush_carrier_writes();
  }

  for (auto& [fd, _] : carriers)
    close(fd);
  if (backend_fd >= 0) close(backend_fd);
  if (backend_timer_fd >= 0) close(backend_timer_fd);
  close(listen_fd);
  unlink(socket_path.c_str());
  close(epfd);
  return 0;
}

}  // namespace ssholl
