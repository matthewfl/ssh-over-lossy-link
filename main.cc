#include "ssholl.h"
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <stdexcept>

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
  { "server",               no_argument,       nullptr, 'S' },
  { "unix-socket-connection", required_argument, nullptr, 'u' },
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
  std::cerr
    << "Usage: " << program_name << " [options] lossy-ssh-host [hostname-on-remote [remote-port]]\n"
    << "   Or: " << program_name << " [options] --unix-socket-connection PATH  (connect via proxy socket, no SSH)\n"
    << "   Or: " << program_name << " --server [hostname] [port]\n"
    << "\n"
    << "Options:\n"
    << "  --auto / --no-auto            Automatically adapt carrier count and redundancy. Default: on\n"
    << "  --path-on-server PATH         Path to ssh-oll on the server. Default: ssh-oll\n"
    << "  --connections N               Initial carrier SSH connections. Default: 10\n"
    << "  --max-connections N           Max carrier connections. Default: 200\n"
    << "  --packet-size N               Max bytes per packet. Default: 800\n"
    << "  --small-packet-redundancy N   Copies for small buffered data (no RS). Default: 2\n"
    << "  --rs-redundancy N             Extra Reed–Solomon packets as fraction. Default: 0.2\n"
    << "  --max-delay N                 Max delay (ms) waiting for buffer for RS. Default: 1\n"
    << "  --server                      Run server mode (connect to hostname:port)\n"
    << "  --unix-socket-connection PATH Connect directly to Unix socket PATH instead of SSH -L\n"
    << "  --help                        Show this help\n";
}

bool parse_args(int argc, char* argv[], Args& out) {
  out = Args{};
  int opt;
  while ((opt = getopt_long(argc, argv, "aAp:c:m:s:r:R:d:Su:h", LONG_OPTS, nullptr)) != -1) {
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
        case 'S':
          out.server_mode = true;
          break;
        case 'u':
          out.unix_socket_connection = optarg;
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
  ssholl::Args args;
  if (!ssholl::parse_args(argc, argv, args))
    return 1;
  if (args.server_mode)
    return ssholl::run_server(args);
  return ssholl::run_client(args);
}
