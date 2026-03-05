#include "ssholl.h"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <stdexcept>
#include <sys/file.h>
#include <unistd.h>

namespace ssholl {

namespace {

const struct option LONG_OPTS[] = {
  { "auto",                 no_argument,       nullptr, 'a' },
  { "no-auto",              no_argument,       nullptr, 'A' },
  { "path-on-server",       required_argument, nullptr, 'p' },
  { "connections",         required_argument, nullptr, 'c' },
  { "max-connections",      required_argument, nullptr, 'm' },
  { "packet-size",          required_argument, nullptr, 's' },
  { "small-packet-redundancy", required_argument, nullptr, 'r' },
  { "rs-redundancy",       required_argument, nullptr, 'R' },
  { "max-delay",            required_argument, nullptr, 'd' },
  { "rtt-ms",               required_argument, nullptr, 't' },
  { "connect-timeout",      required_argument, nullptr, 'T' },
  { "min-data-per-minute",  required_argument, nullptr, 'M' },
  { "file-lock",            required_argument, nullptr, 'F' },
  { "server",               no_argument,       nullptr, 'S' },
  { "unix-socket-connection", required_argument, nullptr, 'u' },
  { "debug",                no_argument,       nullptr, 'D' },
  { "help",                 no_argument,       nullptr, 'h' },
  { nullptr, 0, nullptr, 0 },
};

unsigned parse_unsigned(const char* s, const char* opt_name) {
  unsigned long v = 0;
  char* end = nullptr;
  v = std::strtoul(s, &end, 10);
  if (end == s || *end != '\0')
    throw std::runtime_error(std::string(opt_name) + " requires a non-negative integer");
  if (v > 0xffffu)
    throw std::runtime_error(std::string(opt_name) + " out of range");
  return static_cast<unsigned>(v);
}

float parse_float(const char* s, const char* opt_name) {
  char* end = nullptr;
  float v = std::strtof(s, &end);
  if (end == s || *end != '\0')
    throw std::runtime_error(std::string(opt_name) + " requires a number");
  if (v < 0.0f)
    throw std::runtime_error(std::string(opt_name) + " must be non-negative");
  return v;
}

uint16_t parse_port(const char* s) {
  unsigned long v = 0;
  char* end = nullptr;
  v = std::strtoul(s, &end, 10);
  if (end == s || *end != '\0' || v == 0 || v > 65535)
    throw std::runtime_error("remote port must be 1-65535");
  return static_cast<uint16_t>(v);
}

}  // namespace

void usage(const char* program_name) {
  const Config c{};
  std::cerr
    << "Usage: " << program_name << " [options] lossy-ssh-host [hostname-on-remote [remote-port]]\n"
    << "   Or: " << program_name << " [options] --unix-socket-connection PATH  (connect via proxy socket, no SSH)\n"
    << "   Or: " << program_name << " --server [hostname] [port]\n"
    << "\n"
    << "Options:\n"
    << "  --auto / --no-auto            Automatically adapt carrier count and redundancy. Default: "
    << (c.auto_adapt ? "on" : "off") << "\n"
    << "  --path-on-server PATH         Path to ssh-oll on the server. Default: " << c.path_on_server << "\n"
    << "  --connections N               Initial carrier SSH connections. Default: " << c.connections << "\n"
    << "  --max-connections N           Max carrier connections. Default: " << c.max_connections << "\n"
    << "  --packet-size N               Max bytes per packet. Default: " << c.packet_size << "\n"
    << "  --small-packet-redundancy N   Copies for small buffered data (no RS). Default: "
    << c.small_packet_redundancy << "\n"
    << "  --rs-redundancy N             Extra Reed–Solomon packets as fraction. Default: "
    << c.rs_redundancy << "\n"
    << "  --max-delay N                 Max delay (ms) waiting for buffer for RS. Default: "
    << c.max_delay_ms << "\n"
    << "  --rtt-ms N                    Hint RTT (ms) for cold-start timeouts; 0 = auto from link. Default: "
    << c.rtt_hint_ms << "\n"
    << "  --connect-timeout N           SSH ConnectTimeout (seconds); 0 = no limit. Default: "
    << c.connect_timeout_sec << "\n"
    << "  --min-data-per-minute N       Send keepalive data so each carrier sends ≥N bytes/min. Default: "
    << c.min_data_per_minute << "\n"
    << "  --file-lock PATH              Acquire exclusive lock on PATH before client start (15s timeout)\n"
    << "  --server                      Run server mode (connect to hostname:port)\n"
    << "  --unix-socket-connection PATH Connect directly to Unix socket PATH instead of SSH -L\n"
    << "  --debug                       Write verbose debug logs to /tmp/ssh-oll-{client,server}-<pid>.log\n"
    << "  --help                        Show this help\n";
}

bool parse_args(int argc, char* argv[], Args& out) {
  out = Args{};
  int opt;
  while ((opt = getopt_long(argc, argv, "aAp:c:m:s:r:R:d:t:T:M:F:Su:Dh", LONG_OPTS, nullptr)) != -1) {
    try {
      switch (opt) {
        case 'a':
          out.config.auto_adapt = true;
          break;
        case 'A':
          out.config.auto_adapt = false;
          break;
        case 'p':
          out.config.path_on_server = optarg;
          break;
        case 'c':
          out.config.connections = parse_unsigned(optarg, "--connections");
          break;
        case 'm':
          out.config.max_connections = parse_unsigned(optarg, "--max-connections");
          break;
        case 's':
          out.config.packet_size = parse_unsigned(optarg, "--packet-size");
          break;
        case 'r':
          out.config.small_packet_redundancy = parse_unsigned(optarg, "--small-packet-redundancy");
          break;
        case 'R':
          out.config.rs_redundancy = parse_float(optarg, "--rs-redundancy");
          break;
        case 'd':
          out.config.max_delay_ms = parse_float(optarg, "--max-delay");
          break;
        case 't':
          out.config.rtt_hint_ms = parse_unsigned(optarg, "--rtt-ms");
          break;
        case 'T':
          out.config.connect_timeout_sec = parse_unsigned(optarg, "--connect-timeout");
          break;
        case 'M':
          out.config.min_data_per_minute = parse_unsigned(optarg, "--min-data-per-minute");
          break;
        case 'F':
          out.file_lock = optarg;
          break;
        case 'S':
          out.server_mode = true;
          break;
        case 'u':
          out.unix_socket_connection = optarg;
          break;
        case 'D':
          out.debug = true;
          break;
        case 'h':
          usage(argv[0]);
          return false;
        default:
          usage(argv[0]);
          return false;
      }
    } catch (const std::exception& e) {
      std::cerr << "ssh-oll: " << e.what() << "\n";
      usage(argv[0]);
      return false;
    }
  }

  if (out.server_mode) {
    // --server [hostname] [port]
    if (optind < argc)
      out.remote_hostname = argv[optind++];
    if (optind < argc)
      out.remote_port = parse_port(argv[optind++]);
    if (optind < argc) {
      std::cerr << "ssh-oll: unexpected argument after port\n";
      usage(argv[0]);
      return false;
    }
  } else {
    // client: [lossy-ssh-host] [hostname-on-remote] [remote-port]; lossy-ssh-host optional if --unix-socket-connection set
    if (out.unix_socket_connection.empty() && optind >= argc) {
      std::cerr << "ssh-oll: lossy-ssh-host required (or use --unix-socket-connection)\n";
      usage(argv[0]);
      return false;
    }
    if (optind < argc)
      out.lossy_ssh_host = argv[optind++];
    if (optind < argc)
      out.remote_hostname = argv[optind++];
    if (optind < argc)
      out.remote_port = parse_port(argv[optind++]);
    if (optind < argc) {
      std::cerr << "ssh-oll: unexpected argument\n";
      usage(argv[0]);
      return false;
    }
  }

  return true;
}

}  // namespace ssholl

// -----------------------------------------------------------------------------
// Entry point: parse args, then run client or server.
// -----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
  signal(SIGPIPE, SIG_IGN);
  ssholl::Args args;
  if (!ssholl::parse_args(argc, argv, args))
    return 1;
  if (args.server_mode) {
    return ssholl::run_server(args);
  }
  if (!args.file_lock.empty()) {
    int lock_fd = open(args.file_lock.c_str(), O_RDWR | O_CREAT, 0644);
    if (lock_fd < 0) {
      std::cerr << "ssh-oll: cannot open lock file: " << args.file_lock << "\n";
      return 1;
    }
    const int timeout_sec = 15;
    int elapsed = 0;
    while (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        std::cerr << "ssh-oll: flock failed on " << args.file_lock << "\n";
        close(lock_fd);
        return 1;
      }
      if (elapsed >= timeout_sec) {
        std::cerr << "ssh-oll: could not acquire lock on " << args.file_lock
                  << " within " << timeout_sec << " seconds\n";
        close(lock_fd);
        return 1;
      }
      sleep(1);
      elapsed++;
    }
    (void)lock_fd;  // hold lock for process lifetime; released on exit
  }
  return ssholl::run_client(args);
}
