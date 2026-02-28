#!/usr/bin/env python3
"""
Test script for ssh-oll development.

- Starts a TCP server that ssh-oll --server connects to as its "backend" (instead of real SSH).
- Starts ssh-oll --server localhost <tcp_port> and captures its Unix socket path.
- Creates a proxy Unix socket that forwards connections to the real server socket,
  with optional latency injection to simulate lossy links.
- Runs ssh-oll client with --unix-socket-connection <proxy> so the client talks via the proxy.
- Measures latency: client stdin -> TCP (and TCP -> client stdout).

Usage:
  ./test_ssh_oll.py [options]

  The script will:
  1. Start TCP server on --tcp-port (default 2222).
  2. Start ssh-oll --server localhost <tcp_port> and read its socket path.
  3. Create proxy socket and relay with optional --latency-ms.
  4. Run ssh-oll --unix-socket-connection <proxy> (with stdin/stdout piped).
  5. Run latency measurements (--iterations) and print results.
"""

import argparse
import os
import random
import select
import socket
import string
import subprocess
import sys
import threading
import time


def random_suffix(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def tcp_server_listen(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    sock.settimeout(300.0)  # long timeout while waiting for server to connect
    return sock


def unix_listen(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(path):
        os.unlink(path)
    sock.bind(path)
    sock.listen(64)
    return sock


def relay_with_latency(sock_from, sock_to, delay_sec, label=""):
    """Read from sock_from, optionally delay, write to sock_to. Stops on EOF/error."""
    try:
        while True:
            data = sock_from.recv(65536)
            if not data:
                break
            if delay_sec > 0:
                time.sleep(delay_sec)
            sock_to.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            sock_to.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def proxy_connection(client_conn, server_socket_path, latency_sec):
    """Connect to server socket and relay client_conn <-> server in both directions with optional latency."""
    try:
        server_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_conn.connect(server_socket_path)
    except Exception:
        client_conn.close()
        return
    t1 = threading.Thread(
        target=relay_with_latency,
        args=(client_conn, server_conn, latency_sec),
        daemon=True,
    )
    t2 = threading.Thread(
        target=relay_with_latency,
        args=(server_conn, client_conn, latency_sec),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_conn.close()
    server_conn.close()


def proxy_accept_loop(proxy_path, server_socket_path, latency_sec, stop_event):
    """Accept on proxy_path, for each connection relay to server_socket_path with latency."""
    listen_sock = unix_listen(proxy_path)
    listen_sock.settimeout(0.5)
    try:
        while not stop_event.is_set():
            try:
                conn, _ = listen_sock.accept()
            except socket.timeout:
                continue
            t = threading.Thread(
                target=proxy_connection,
                args=(conn, server_socket_path, latency_sec),
                daemon=True,
            )
            t.start()
    finally:
        listen_sock.close()
        if os.path.exists(proxy_path):
            os.unlink(proxy_path)


def main():
    parser = argparse.ArgumentParser(
        description="Test ssh-oll: proxy socket, TCP backend, latency measurements."
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=2222,
        help="Port for TCP server (backend for ssh-oll --server). Default 2222",
    )
    parser.add_argument(
        "--ssh-oll-path",
        default="ssh-oll",
        help="Path to ssh-oll binary. Default: ssh-oll",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=5,
        help="Number of carrier connections. Default 5",
    )
    parser.add_argument(
        "--packet-size",
        type=int,
        default=100,
        help="Client --packet-size so payloads are sent in chunks (default 100). Must be <= payload-size.",
    )
    parser.add_argument(
        "--latency-ms",
        type=float,
        default=0.0,
        help="Extra latency in ms to inject in proxy (each direction). Default 0",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of latency measurement iterations per direction. Default 5",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=1000,
        help="Bytes per measurement payload. Default 1000",
    )
    parser.add_argument(
        "--proxy-socket",
        default=None,
        help="Path for proxy Unix socket. Default: /tmp/ssh-oll-test-script.<random>",
    )
    args = parser.parse_args()

    latency_sec = args.latency_ms / 1000.0 if args.latency_ms else 0.0
    proxy_path = args.proxy_socket or f"/tmp/ssh-oll-test-script.{random_suffix()}"

    # 1. Start TCP server (backend for ssh-oll --server)
    tcp_listen = tcp_server_listen(args.tcp_port)
    tcp_conn_holder = {"conn": None, "ready": threading.Event()}

    def accept_tcp():
        conn, _ = tcp_listen.accept()
        tcp_conn_holder["conn"] = conn
        tcp_conn_holder["ready"].set()

    tcp_thread = threading.Thread(target=accept_tcp, daemon=True)
    tcp_thread.start()

    # 2. Start ssh-oll --server; it prints socket path then daemonizes
    server_proc = subprocess.Popen(
        [args.ssh_oll_path, "--server", "127.0.0.1", str(args.tcp_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    server_socket_path = server_proc.stdout.readline().strip()
    server_proc.wait(timeout=5)
    if not server_socket_path or not os.path.exists(server_socket_path):
        print("Failed to get server socket path or server did not create socket.", file=sys.stderr)
        if server_proc.stderr:
            err = server_proc.stderr.read()
            if err:
                print(err, file=sys.stderr)
        tcp_listen.close()
        return 1

    # 3. Start proxy (client -> proxy -> server) with optional latency
    stop_proxy = threading.Event()
    proxy_thread = threading.Thread(
        target=proxy_accept_loop,
        args=(proxy_path, server_socket_path, latency_sec, stop_proxy),
        daemon=True,
    )
    proxy_thread.start()

    # 4. Start client with --unix-socket-connection
    client_proc = subprocess.Popen(
        [
            args.ssh_oll_path,
            "--unix-socket-connection",
            proxy_path,
            "--connections",
            str(args.connections),
            "--packet-size",
            str(min(args.packet_size, args.payload_size)),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for TCP backend connection (server connects when first data flows).
    # Client only sends when buffer >= packet_size, so send enough to trigger.
    trigger_size = max(args.packet_size, 64)
    client_proc.stdin.write(b"\x00" * trigger_size)
    client_proc.stdin.flush()
    if not tcp_conn_holder["ready"].wait(timeout=10.0):
        print("Timeout waiting for ssh-oll server to connect to TCP backend.", file=sys.stderr)
        client_proc.kill()
        stop_proxy.set()
        tcp_listen.close()
        return 1

    tcp_conn = tcp_conn_holder["conn"]
    # Longer timeout when injecting latency (each chunk is delayed)
    recv_timeout = 30.0 + (args.latency_ms * args.payload_size / max(args.packet_size, 1) * 2 / 1000.0)
    tcp_conn.settimeout(max(30.0, recv_timeout))

    # Drain any data that came from the initial burst (so we start clean for measurements)
    try:
        while select.select([tcp_conn], [], [], 0.1)[0]:
            tcp_conn.recv(65536)
    except (socket.timeout, BlockingIOError):
        pass

    latencies_client_to_tcp = []
    latencies_tcp_to_client = []

    for _ in range(args.iterations):
        # Measurement 1: client stdin -> TCP (client sends, we read on TCP)
        payload = os.urandom(args.payload_size)
        t0 = time.perf_counter()
        client_proc.stdin.write(payload)
        client_proc.stdin.flush()
        received = b""
        while len(received) < len(payload):
            chunk = tcp_conn.recv(len(payload) - len(received))
            if not chunk:
                break
            received += chunk
        t1 = time.perf_counter()
        if len(received) >= len(payload):
            latencies_client_to_tcp.append((t1 - t0) * 1000.0)

        # Measurement 2: TCP -> client stdout (we send on TCP, read from client)
        payload = os.urandom(args.payload_size)
        t0 = time.perf_counter()
        tcp_conn.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = client_proc.stdout.read(len(payload) - len(received))
            if not chunk:
                break
            received += chunk
        t1 = time.perf_counter()
        if len(received) >= len(payload):
            latencies_tcp_to_client.append((t1 - t0) * 1000.0)

    # Shut down client (close stdin so client sees EOF)
    try:
        client_proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    try:
        client_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        client_proc.kill()

    stop_proxy.set()
    tcp_conn.close()
    tcp_listen.close()

    # Report
    print("Latency (ms):")
    if latencies_client_to_tcp:
        print(
            f"  client stdin -> TCP:  min={min(latencies_client_to_tcp):.2f}  "
            f"max={max(latencies_client_to_tcp):.2f}  "
            f"avg={sum(latencies_client_to_tcp)/len(latencies_client_to_tcp):.2f}  "
            f"(n={len(latencies_client_to_tcp)})"
        )
    else:
        print("  client stdin -> TCP:  (no successful samples)")
    if latencies_tcp_to_client:
        print(
            f"  TCP -> client stdout: min={min(latencies_tcp_to_client):.2f}  "
            f"max={max(latencies_tcp_to_client):.2f}  "
            f"avg={sum(latencies_tcp_to_client)/len(latencies_tcp_to_client):.2f}  "
            f"(n={len(latencies_tcp_to_client)})"
        )
    else:
        print("  TCP -> client stdout: (no successful samples)")

    if args.latency_ms:
        print(f"  (injected proxy latency: {args.latency_ms} ms per direction)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
