#!/usr/bin/env python3
"""
Proxy between ssh-oll client and ssh-oll server for testing. No SSH, no packet parsing.

- Listens on a TCP port (printed; ssh-oll --server connects here as its "backend").
- Listens on a Unix socket (default /tmp/ssh-oll-test-script; client's carriers connect here).
- Connects to the server's Unix socket N times and forwards bytes between each (client_conn, server_conn)
  pair; can inject latency and drop connections.

Usage:
  1. Run this script; it prints the TCP port and Unix path.
  2. Start server: ./ssh-oll --server 127.0.0.1 <TCP port from step 1>. Note the server socket path it prints.
  3. Run this script with --server-socket <path from step 2>, or paste the path when prompted.
  4. Start client (or use --run-client to have the script spawn it): client connects to the script's Unix path.
"""

import argparse
import os
import random
import select
import socket
import struct
import sys
import threading
import time


def parse_args():
    ap = argparse.ArgumentParser(description="Proxy between ssh-oll client and server for testing")
    ap.add_argument("--server-socket", default=None, help="Path to ssh-oll server's Unix socket (or prompt if omitted)")
    ap.add_argument("--unix-path", default="/tmp/ssh-oll-test-script", help="Unix socket for client carriers")
    ap.add_argument("--connections", type=int, default=4, help="Number of carrier pairs (default 4)")
    ap.add_argument("--latency-ms", type=float, default=0, help="Extra latency per direction in ms (default 0)")
    ap.add_argument("--drop-rate", type=float, default=0, help="Per-connection drop probability 0..1 (default 0)")
    ap.add_argument("--run-client", action="store_true", help="Spawn client, send random data, measure latency")
    ap.add_argument("--client-cmd", default=None, help="Command to run as client (default: ssh-oll with socat)")
    ap.add_argument("--port", type=int, default=0, help="TCP port to listen on (default 0 = random)")
    return ap.parse_args()


def forward_one_way(
    src: socket.socket,
    dst: socket.socket,
    latency_ms: float,
    drop_connection: threading.Event,
) -> None:
    try:
        while not drop_connection.is_set():
            r, _, _ = select.select([src], [], [], 0.5)
            if not r:
                continue
            data = src.recv(65536)
            if not data:
                break
            if latency_ms > 0:
                time.sleep(latency_ms / 1000.0)
            if drop_connection.is_set():
                break
            dst.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        drop_connection.set()
        try:
            src.shutdown(socket.SHUT_RD)
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def run_pair(
    client_conn: socket.socket,
    server_conn: socket.socket,
    latency_ms: float,
    drop_rate: float,
    pair_id: int,
) -> None:
    drop = threading.Event()
    if 0 < drop_rate < 1 and random.random() < drop_rate:
        time.sleep(random.uniform(0.1, 2.0))
        drop.set()
        try:
            client_conn.close()
            server_conn.close()
        except OSError:
            pass
        return

    t1 = threading.Thread(
        target=forward_one_way,
        args=(client_conn, server_conn, latency_ms, drop),
        daemon=True,
    )
    t2 = threading.Thread(
        target=forward_one_way,
        args=(server_conn, client_conn, latency_ms, drop),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        client_conn.close()
        server_conn.close()
    except OSError:
        pass


def listen_tcp(port: int = 0) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    port = sock.getsockname()[1]
    sock.listen(8)
    return sock, port


def listen_unix(path: str) -> socket.socket:
    if os.path.exists(path):
        os.unlink(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    sock.listen(64)
    return sock


def connect_to_server(server_socket_path: str, n: int) -> list[socket.socket]:
    conns = []
    for i in range(n):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(server_socket_path)
            conns.append(s)
        except OSError as e:
            print(f"Connect to server socket {i}: {e}", file=sys.stderr)
    return conns


def main() -> int:
    args = parse_args()

    tcp_listen, tcp_port = listen_tcp(args.port)
    unix_listen = listen_unix(args.unix_path)

    print(f"TCP port: {tcp_port}", file=sys.stderr)
    print(f"Unix socket: {args.unix_path}", file=sys.stderr)
    print(f"Start server with: ./ssh-oll --server 127.0.0.1 {tcp_port}", file=sys.stderr)
    sys.stderr.flush()

    server_socket_path = args.server_socket
    if not server_socket_path:
        print("Paste server socket path (from ssh-oll --server output) and press Enter:", file=sys.stderr)
        sys.stderr.flush()
        server_socket_path = sys.stdin.readline().strip()
    if not server_socket_path:
        print("No server socket path", file=sys.stderr)
        return 1

    # Connect to server's Unix socket (we proxy between client and server)
    for attempt in range(30):
        server_conns = connect_to_server(server_socket_path, args.connections)
        if len(server_conns) >= args.connections:
            break
        time.sleep(0.2)
    else:
        server_conns = connect_to_server(server_socket_path, args.connections)
    if len(server_conns) < args.connections:
        print(f"Warning: only {len(server_conns)}/{args.connections} connections to server", file=sys.stderr)

    # Accept client connections on our Unix socket (start client first if --run-client)
    client_conns = []
    if args.run_client:
        import subprocess
        cmd = args.client_cmd
        if cmd is None:
            ssh_oll = os.environ.get("SSH_OLL", "ssh-oll")
            cmd = [
                ssh_oll,
                "--carrier-cmd", "socat UNIX-LISTEN:$CARRIER_LOCAL,reuseaddr,fork UNIX-CONNECT:$CARRIER_REMOTE",
                "--server-socket", args.unix_path,
                "--connections", str(args.connections),
                "localhost",
            ]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(ssh_oll) or os.getcwd(),
            )
        else:
            env = os.environ.copy()
            env["CARRIER_REMOTE"] = args.unix_path
            proc = subprocess.Popen(["sh", "-c", cmd], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)

    print(f"Waiting for {args.connections} client connection(s) on {args.unix_path} ...", file=sys.stderr)
    while len(client_conns) < args.connections:
        unix_listen.settimeout(15.0)
        try:
            conn, _ = unix_listen.accept()
            client_conns.append(conn)
        except socket.timeout:
            print("Timeout waiting for client connections", file=sys.stderr)
            break
    unix_listen.close()

    if len(client_conns) == 0:
        print("No client connections", file=sys.stderr)
        return 1

    # Pair and forward (same number of server and client conns; pair by index)
    pairs = min(len(server_conns), len(client_conns))
    threads = []
    for i in range(pairs):
        t = threading.Thread(
            target=run_pair,
            args=(
                client_conns[i],
                server_conns[i],
                args.latency_ms,
                args.drop_rate,
                i,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Accept one TCP connection from the server (its "backend")
    tcp_listen.settimeout(60.0)
    try:
        server_tcp, _ = tcp_listen.accept()
    except socket.timeout:
        print("Timeout waiting for server TCP connection", file=sys.stderr)
        return 1
    tcp_listen.close()

    if args.run_client:
        # Send timestamped random data to client stdin; read from TCP and report latency
        chunk_size = 4096
        latencies = []
        sent = 0
        try:
            for _ in range(20):
                payload = os.urandom(chunk_size - 8)
                ts = time.perf_counter_ns()
                header = struct.pack("<Q", ts)
                proc.stdin.write(header + payload)
                proc.stdin.flush()
                sent += 1
                # Read full chunk from TCP so we stay aligned (server writes reassembled stream)
                data = b""
                while len(data) < chunk_size:
                    got = server_tcp.recv(chunk_size - len(data))
                    if not got:
                        break
                    data += got
                if len(data) >= 8:
                    ts_sent_ns = struct.unpack("<Q", data[:8])[0]
                    now_ns = time.perf_counter_ns()
                    lat_ms = (now_ns - ts_sent_ns) / 1e6
                    if 0 <= lat_ms <= 60000:
                        latencies.append(lat_ms)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        for t in threads:
            t.join(timeout=1.0)
        if latencies:
            n = len(latencies)
            print(f"One-way latency (ms): min={min(latencies):.2f} max={max(latencies):.2f} avg={sum(latencies)/n:.2f} (n={n} valid)")
        else:
            print("One-way latency: no valid samples (stream may be reordered or delayed)")
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except NameError:
            pass
    else:
        # Just keep running; TCP connection is open (server attached)
        for t in threads:
            t.join()

    return 0


if __name__ == "__main__":
    sys.exit(main())
