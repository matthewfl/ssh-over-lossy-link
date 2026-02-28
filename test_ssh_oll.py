#!/usr/bin/env python3
"""
Test script for ssh-oll development.

- Starts a TCP server that ssh-oll --server connects to as its "backend" (instead of real SSH).
- Starts ssh-oll --server localhost <tcp_port> and captures its Unix socket path.
- Creates a proxy Unix socket that forwards connections to the real server socket,
  with optional latency injection (--latency-ms or --latency-random) to simulate lossy links.
- With --latency-random: a fraction of chunks get a long delay (e.g. 5%% get 5s, 95%% get 0.1s),
  emulating packet loss where TCP retransmits and eventually gets data through.
- Runs ssh-oll client with --unix-socket-connection <proxy> so the client talks via the proxy.
- Measures latency: client stdin -> TCP (and TCP -> client stdout).

  With --continuous: sends data continuously in both directions with varying payload sizes,
  printing the latency (ms) of each packet. Run until --continuous-duration expires or Ctrl+C.

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
import queue
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


def _relay_reader(sock_from, queue, stop_event):
    """Read from sock_from and put chunks in queue. Runs until EOF or stop_event."""
    try:
        while not stop_event.is_set():
            data = sock_from.recv(65536)
            if not data:
                break
            queue.put((data, None))
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        queue.put((b"", None))  # EOF sentinel


def _relay_sender(sock_to, q, delay_spec, stop_event):
    """Pop chunks from queue, apply delay_spec, send to sock_to. Runs until EOF sentinel."""
    try:
        while not stop_event.is_set():
            try:
                data, _ = q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not data:
                break
            delay = delay_spec() if callable(delay_spec) else delay_spec
            if delay > 0:
                time.sleep(delay)
            sock_to.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            sock_to.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay_zero_latency(sock_from, sock_to):
    """Direct relay with no delay: read from sock_from, write to sock_to. Stops on EOF/error."""
    try:
        while True:
            data = sock_from.recv(65536)
            if not data:
                break
            sock_to.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            sock_to.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_with_latency(sock_from, sock_to, delay_spec):
    """Read from sock_from, optionally delay, write to sock_to. Stops on EOF/error.

    When delay_spec is 0 (constant), uses a direct relay. Otherwise uses a queue and
    sender thread so we keep reading while delaying (avoids blocking the peer).
    delay_spec: float (constant seconds) or callable() -> float per chunk (randomize mode).
    """
    # Zero latency: direct relay, no queue (fast path that matches original working behavior)
    if not callable(delay_spec) and delay_spec == 0:
        _relay_zero_latency(sock_from, sock_to)
        return
    q = queue.Queue()
    stop = threading.Event()
    reader = threading.Thread(target=_relay_reader, args=(sock_from, q, stop), daemon=True)
    sender = threading.Thread(target=_relay_sender, args=(sock_to, q, delay_spec, stop), daemon=True)
    reader.start()
    sender.start()
    reader.join()
    sender.join()


def proxy_connection(client_conn, server_socket_path, delay_spec):
    """Connect to server socket and relay client_conn <-> server in both directions with optional latency."""
    try:
        server_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_conn.connect(server_socket_path)
    except Exception:
        client_conn.close()
        return
    t1 = threading.Thread(
        target=relay_with_latency,
        args=(client_conn, server_conn, delay_spec),
        daemon=True,
    )
    t2 = threading.Thread(
        target=relay_with_latency,
        args=(server_conn, client_conn, delay_spec),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_conn.close()
    server_conn.close()


def _bucket_label(size, bucket_size=500):
    """Return label like '0-500', '500-1000' for the given size."""
    lo = (size // bucket_size) * bucket_size
    hi = lo + bucket_size
    return (lo, hi, f"{lo}-{hi}")


def _print_size_bucket_summary(results, bucket_size=500):
    """Print latency summary grouped by packet size buckets."""
    if not results:
        return
    from collections import defaultdict
    buckets = defaultdict(list)  # (lo, hi) -> [latency_ms, ...]
    for size, lat in results:
        lo, hi, _ = _bucket_label(size, bucket_size)
        buckets[(lo, hi)].append(lat)
    print("\nSummary by packet size (latency ms):")
    for (lo, hi) in sorted(buckets.keys()):
        label = f"{lo}-{hi}"
        L = buckets[(lo, hi)]
        avg = sum(L) / len(L)
        print(f"  {label:>12} bytes: n={len(L):4d}  min={min(L):.2f}  max={max(L):.2f}  avg={avg:.2f}")


def _run_continuous(client_proc, tcp_conn, stop_proxy, tcp_listen, args):
    """Run continuous bidirectional send with varying sizes, print latency per packet."""
    stop_event = threading.Event()
    min_size = max(args.continuous_min_size, 1)
    max_size = max(args.continuous_max_size, min_size)
    # Short timeout so recv() returns periodically and threads can check stop_event
    tcp_conn.settimeout(1.0)

    results = []
    results_lock = threading.Lock()

    def client_to_tcp():
        while not stop_event.is_set():
            size = random.randint(min_size, max_size)
            payload = os.urandom(size)
            try:
                t0 = time.perf_counter()
                client_proc.stdin.write(payload)
                client_proc.stdin.flush()
                received = b""
                while len(received) < len(payload) and not stop_event.is_set():
                    try:
                        chunk = tcp_conn.recv(len(payload) - len(received))
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    received += chunk
                t1 = time.perf_counter()
                if len(received) >= len(payload):
                    lat_ms = 1000.0 * (t1 - t0)
                    with results_lock:
                        results.append((size, lat_ms))
                    print(f"client→TCP   size={size:5d}   latency_ms={lat_ms:.2f}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

    def tcp_to_client():
        while not stop_event.is_set():
            size = random.randint(min_size, max_size)
            payload = os.urandom(size)
            try:
                t0 = time.perf_counter()
                tcp_conn.sendall(payload)
                received = b""
                while len(received) < len(payload) and not stop_event.is_set():
                    chunk = client_proc.stdout.read(len(payload) - len(received))
                    if not chunk:
                        break
                    received += chunk
                t1 = time.perf_counter()
                if len(received) >= len(payload):
                    lat_ms = 1000.0 * (t1 - t0)
                    with results_lock:
                        results.append((size, lat_ms))
                    print(f"TCP→client   size={size:5d}   latency_ms={lat_ms:.2f}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

    t1 = threading.Thread(target=client_to_tcp, daemon=True)
    t2 = threading.Thread(target=tcp_to_client, daemon=True)
    t1.start()
    t2.start()

    try:
        if args.continuous_duration is not None:
            time.sleep(args.continuous_duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    stop_event.set()

    t1.join(timeout=2.0)
    t2.join(timeout=2.0)

    _print_size_bucket_summary(results)

    try:
        client_proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    try:
        client_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        client_proc.kill()

    stop_proxy.set()
    try:
        tcp_conn.close()
    except OSError:
        pass
    try:
        tcp_listen.close()
    except OSError:
        pass


def proxy_accept_loop(proxy_path, server_socket_path, delay_spec, stop_event):
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
                args=(conn, server_socket_path, delay_spec),
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
        "--latency-random",
        action="store_true",
        help="Randomize latency: --latency-random-pct of chunks get --latency-random-high-ms, rest get --latency-random-low-ms (emulates packet loss / retransmit)",
    )
    parser.add_argument(
        "--latency-random-pct",
        type=float,
        default=5.0,
        help="When --latency-random: percent of chunks that get the high delay. Default 5",
    )
    parser.add_argument(
        "--latency-random-high-ms",
        type=float,
        default=5000.0,
        help="When --latency-random: high delay in ms (emulates drop/retransmit). Default 5000",
    )
    parser.add_argument(
        "--latency-random-low-ms",
        type=float,
        default=100.0,
        help="When --latency-random: normal delay in ms. Default 100",
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
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Continuous mode: send data in both directions with varying sizes, print latency per packet. Stop with Ctrl+C or --continuous-duration.",
    )
    parser.add_argument(
        "--continuous-duration",
        type=float,
        default=None,
        metavar="SECONDS",
        help="In --continuous mode, run for this many seconds then exit. Default: run until Ctrl+C.",
    )
    parser.add_argument(
        "--continuous-min-size",
        type=int,
        default=64,
        help="In --continuous mode, minimum payload size in bytes. Default 64",
    )
    parser.add_argument(
        "--continuous-max-size",
        type=int,
        default=4096,
        help="In --continuous mode, maximum payload size in bytes. Default 4096",
    )
    args = parser.parse_args()

    # Build delay spec: constant seconds or callable() -> seconds for randomize mode
    if args.latency_random:
        low_sec = args.latency_random_low_ms / 1000.0
        high_sec = args.latency_random_high_ms / 1000.0
        pct_high = max(0.0, min(100.0, args.latency_random_pct)) / 100.0
        # Per-chunk random delay: pct_high of the time use high_sec, else low_sec
        def delay_spec():
            return random.choices(
                [low_sec, high_sec], weights=[1.0 - pct_high, pct_high], k=1
            )[0]
    else:
        latency_sec = args.latency_ms / 1000.0 if args.latency_ms else 0.0
        delay_spec = latency_sec
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
        args=(proxy_path, server_socket_path, delay_spec, stop_proxy),
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
    if args.latency_random:
        # Worst case: every chunk gets high delay
        chunks_per_iter = (args.payload_size + args.packet_size - 1) // max(args.packet_size, 1)
        recv_timeout = 60.0 + args.iterations * 2 * chunks_per_iter * (args.latency_random_high_ms / 1000.0)
    else:
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

    # Warmup: one full round-trip each direction so the first timed iteration
    # doesn't pay for cold caches / scheduler; reduces stdin->TCP latency variance.
    _warm = os.urandom(args.payload_size)
    client_proc.stdin.write(_warm)
    client_proc.stdin.flush()
    _got = b""
    while len(_got) < len(_warm):
        _got += tcp_conn.recv(len(_warm) - len(_got))
    _warm = os.urandom(args.payload_size)
    tcp_conn.sendall(_warm)
    _got = b""
    while len(_got) < len(_warm):
        _got += client_proc.stdout.read(len(_warm) - len(_got))

    if args.continuous:
        _run_continuous(
            client_proc,
            tcp_conn,
            stop_proxy,
            tcp_listen,
            args,
        )
        return 0

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

    if args.latency_random:
        print(
            f"  (random latency: {args.latency_random_pct}% of chunks "
            f"{args.latency_random_high_ms} ms, rest {args.latency_random_low_ms} ms)"
        )
    elif args.latency_ms:
        print(f"  (injected proxy latency: {args.latency_ms} ms per direction)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
