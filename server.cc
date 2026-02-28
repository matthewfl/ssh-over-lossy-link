#include "ssholl.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <csignal>
#include <cstring>
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

const size_t MAX_PACKET_PAYLOAD = 65536;  // cap for size field
const int LISTEN_BACKLOG = 64;
const size_t READ_BUF_SIZE = 65536;

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

// Per-carrier connection state.
struct CarrierState {
  std::vector<uint8_t> read_buf;
  std::vector<uint8_t> write_buf;
  size_t write_pos = 0;  // how much of write_buf we've sent
};

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
  uint64_t next_deliver_id = 0;
  uint64_t next_send_id = 0;
  std::vector<uint8_t> backend_read_buf;
  const size_t max_packet = std::min(args.config.packet_size, static_cast<unsigned>(MAX_PACKET_PAYLOAD));

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
      ev.events = EPOLLIN;
      ev.data.fd = backend_fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
    } else if (err != EINPROGRESS && err != 0) {
      close(backend_fd);
      backend_fd = -1;
    }
  };

  auto send_pong = [&](int fd, uint64_t id) {
    PacketHeader h{};
    h.id = id;
    h.packet_kind = PacketKind::PONG;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&h);
    size_t len = sizeof h;
    while (len > 0) {
      ssize_t n = write(fd, p, len);
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return;
      }
      p += n;
      len -= n;
    }
  };

  auto queue_data_to_carriers = [&](const uint8_t* data, size_t len) {
    if (len == 0) return;
    // One SMALL packet per carrier.
    for (auto& [fd, state] : carriers) {
      (void)fd;
      PacketHeader h{};
      h.id = next_send_id;
      h.packet_kind = PacketKind::SMALL;
      uint16_t size = static_cast<uint16_t>(len);
      state.write_buf.insert(state.write_buf.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
      state.write_buf.insert(state.write_buf.end(), reinterpret_cast<const uint8_t*>(&size), reinterpret_cast<const uint8_t*>(&size) + sizeof size);
      state.write_buf.insert(state.write_buf.end(), data, data + len);
    }
    next_send_id++;
  };

  auto flush_carrier_writes = [&]() {
    for (auto it = carriers.begin(); it != carriers.end(); ) {
      int fd = it->first;
      CarrierState& s = it->second;
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
          it = carriers.erase(it);
          goto next_carrier;
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
      next_carrier:;
    }
  };

  auto deliver_pending_to_backend = [&]() {
    if (backend_fd < 0 || !backend_connected) return;
    while (reassembly.count(next_deliver_id)) {
      std::vector<uint8_t>& vec = reassembly[next_deliver_id];
      while (!vec.empty()) {
        ssize_t n = write(backend_fd, vec.data(), vec.size());
        if (n <= 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) return;
          break;
        }
        vec.erase(vec.begin(), vec.begin() + n);
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
        return false;  // close carrier
      return true;
    }
    s.read_buf.insert(s.read_buf.end(), buf, buf + n);

    while (s.read_buf.size() >= sizeof(PacketHeader)) {
      const auto* h = reinterpret_cast<const PacketHeader*>(s.read_buf.data());
      if (h->packet_kind == PacketKind::PING) {
        send_pong(fd, h->id);
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
        // First copy wins: ignore duplicate small packets (redundancy copies).
        if (!reassembly.count(id)) {
          std::vector<uint8_t> payload(p->data, p->data + size);
          reassembly[id] = std::move(payload);
        }
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total);
        connect_backend();
        deliver_pending_to_backend();
        continue;
      }
      if (h->packet_kind == PacketKind::SET_CONFIG) {
        if (s.read_buf.size() >= sizeof(PacketConfig))
          s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketConfig));
        else
          break;
        continue;
      }
      if (h->packet_kind == PacketKind::START_CONNECTION) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
        continue;
      }
      if (h->packet_kind == PacketKind::PONG) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
        continue;
      }
      if (h->packet_kind == PacketKind::REED_SOLOMON) {
        if (s.read_buf.size() < sizeof(PacketHeader) + sizeof(uint16_t)) break;
        uint16_t rs_size = *reinterpret_cast<const uint16_t*>(s.read_buf.data() + sizeof(PacketHeader));
        size_t total_rs = sizeof(PacketHeader) + sizeof(uint16_t) + 2 + rs_size;  // +2 for n,k
        if (rs_size > MAX_PACKET_PAYLOAD || s.read_buf.size() < total_rs) break;
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        continue;
      }
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
    }
    return true;
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
          ssize_t nr = read(backend_fd, buf, sizeof buf);
          if (nr <= 0) {
            if (nr == 0) running = false;
            break;
          }
          backend_read_buf.insert(backend_read_buf.end(), buf, buf + nr);
        }
        if (e & (EPOLLERR | EPOLLHUP)) {
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
    if (backend_connected && backend_fd >= 0 && !backend_read_buf.empty()) {
      size_t chunk = std::min(backend_read_buf.size(), max_packet);
      queue_data_to_carriers(backend_read_buf.data(), chunk);
      backend_read_buf.erase(backend_read_buf.begin(), backend_read_buf.begin() + chunk);
    }
    deliver_pending_to_backend();
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
