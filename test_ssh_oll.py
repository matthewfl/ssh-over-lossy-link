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


def _relay_reader(sock_from, queue, stop_event, debug_label=None):
    """Read from sock_from and put chunks in queue. Runs until EOF or stop_event."""
    try:
        while not stop_event.is_set():
            data = sock_from.recv(65536)
            if not data:
                break
            ts = time.perf_counter()
            queue.put((data, ts))
            if debug_label:
                import sys
                print(f"[proxy-debug] {debug_label} read {len(data)} bytes at {ts:.4f}", file=sys.stderr, flush=True)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        queue.put((b"", None))  # EOF sentinel


def _relay_sender(sock_to, q, delay_spec, stop_event, death_probability=0.0, kill_callback=None, debug_label=None):
    """Pop chunks from queue, apply delay_spec, send to sock_to. Runs until EOF sentinel.
    If death_probability > 0 and kill_callback is set, each chunk has that probability of killing the connection.

    Delay is applied relative to each chunk's arrival time (read_ts), not relative to when it is
    dequeued. This prevents head-of-line blocking: a tiny ACK packet that arrives just before a
    large RS-shard burst will not cause the shards to wait an extra full delay period.
    """
    try:
        while not stop_event.is_set():
            try:
                data, read_ts = q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not data:
                break
            if death_probability > 0 and kill_callback is not None and random.random() < death_probability:
                kill_callback()
                return
            delay = delay_spec() if callable(delay_spec) else delay_spec
            if delay > 0:
                if read_ts is not None:
                    # Schedule delivery at arrival_time + delay; any queue-wait time is already
                    # "used up", so we only sleep for the remainder.
                    sleep_for = (read_ts + delay) - time.perf_counter()
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                else:
                    time.sleep(delay)
            if debug_label and read_ts is not None:
                import sys
                actual_delay = time.perf_counter() - read_ts
                print(f"[proxy-debug] {debug_label} sending {len(data)} bytes actual_delay={actual_delay*1000:.1f}ms", file=sys.stderr, flush=True)
            sock_to.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            sock_to.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay_zero_latency(sock_from, sock_to, death_probability=0.0, kill_callback=None):
    """Direct relay with no delay: read from sock_from, write to sock_to. Stops on EOF/error.
    If death_probability > 0 and kill_callback is set, each chunk has that probability of killing the connection.
    """
    try:
        while True:
            data = sock_from.recv(65536)
            if not data:
                break
            if death_probability > 0 and kill_callback is not None and random.random() < death_probability:
                kill_callback()
                return
            sock_to.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            sock_to.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_with_latency(sock_from, sock_to, delay_spec, death_probability=0.0, kill_callback=None, debug_label=None):
    """Read from sock_from, optionally delay, write to sock_to. Stops on EOF/error.

    When delay_spec is 0 (constant), uses a direct relay. Otherwise uses a queue and
    sender thread so we keep reading while delaying (avoids blocking the peer).
    delay_spec: float (constant seconds) or callable() -> float per chunk (randomize mode).
    death_probability: per-chunk probability of killing the connection (0 = disabled).
    kill_callback: called when connection is killed (should close both sockets).
    """
    # Zero latency: direct relay, no queue (fast path that matches original working behavior)
    if not callable(delay_spec) and delay_spec == 0:
        _relay_zero_latency(sock_from, sock_to, death_probability, kill_callback)
        return
    q = queue.Queue()
    stop = threading.Event()
    reader = threading.Thread(target=_relay_reader, args=(sock_from, q, stop), kwargs={"debug_label": debug_label}, daemon=True)
    sender = threading.Thread(
        target=_relay_sender,
        args=(sock_to, q, delay_spec, stop),
        kwargs={"death_probability": death_probability, "kill_callback": kill_callback, "debug_label": debug_label},
        daemon=True,
    )
    reader.start()
    sender.start()
    reader.join()
    sender.join()


def proxy_connection(client_conn, server_socket_path, delay_spec, on_close=None, initial_connection_latency_sec=0.0, connection_death_probability=0.0):
    """Connect to server socket and relay client_conn <-> server in both directions with optional latency."""
    try:
        server_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_conn.connect(server_socket_path)
    except Exception:
        client_conn.close()
        if on_close:
            on_close()
        return
    if initial_connection_latency_sec > 0:
        time.sleep(initial_connection_latency_sec)

    def kill_connection():
        try:
            client_conn.close()
        except OSError:
            pass
        try:
            server_conn.close()
        except OSError:
            pass

    import threading as _threading
    _conn_id = getattr(_threading.current_thread(), '_proxy_conn_id', None)
    if _conn_id is None:
        import itertools as _it
        _counter = getattr(proxy_connection, '_counter', None)
        if _counter is None:
            proxy_connection._counter = _it.count()
        _conn_id = next(proxy_connection._counter)
        _threading.current_thread()._proxy_conn_id = _conn_id
    relay_kw = {"death_probability": connection_death_probability, "kill_callback": kill_connection}
    debug_s2c = f"s→c conn#{_conn_id}" if _conn_id == 0 else None
    try:
        t1 = threading.Thread(
            target=relay_with_latency,
            args=(client_conn, server_conn, delay_spec),
            kwargs=relay_kw,
            daemon=True,
        )
        t2 = threading.Thread(
            target=relay_with_latency,
            args=(server_conn, client_conn, delay_spec),
            kwargs={**relay_kw, "debug_label": debug_s2c},
            daemon=True,
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    finally:
        try:
            client_conn.close()
            server_conn.close()
        except OSError:
            pass
        if on_close:
            on_close()


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
    continuous_errors = []
    errors_lock = threading.Lock()

    # Stall tracking: per-direction "in-flight since" timestamps and stall event log.
    # A stall is any single send that takes longer than STALL_THRESHOLD_S to complete.
    STALL_THRESHOLD_S = 3.0
    _inflight_lock = threading.Lock()
    _inflight_c2t = [None]   # perf_counter start of current c2t send, or None
    _inflight_t2c = [None]   # perf_counter start of current t2c send, or None
    _stall_events = []        # list of (direction, duration_s)
    _stall_lock = threading.Lock()

    def _record_stall(direction, duration_s):
        with _stall_lock:
            _stall_events.append((direction, duration_s))

    def _watchdog():
        """Print a line whenever a direction has been blocked longer than STALL_THRESHOLD_S."""
        while not stop_event.is_set():
            time.sleep(1.0)
            now = time.perf_counter()
            with _inflight_lock:
                t_c2t = _inflight_c2t[0]
                t_t2c = _inflight_t2c[0]
            parts = []
            if t_c2t is not None:
                elapsed = now - t_c2t
                if elapsed >= STALL_THRESHOLD_S:
                    parts.append(f"client→TCP stalled {elapsed:.1f}s")
            if t_t2c is not None:
                elapsed = now - t_t2c
                if elapsed >= STALL_THRESHOLD_S:
                    parts.append(f"TCP→client stalled {elapsed:.1f}s")
            if parts:
                print(f"[stall] {', '.join(parts)}", flush=True)

    threading.Thread(target=_watchdog, daemon=True).start()

    def client_to_tcp():
        while not stop_event.is_set():
            size = random.randint(min_size, max_size)
            payload = os.urandom(size)
            try:
                t0 = time.perf_counter()
                with _inflight_lock:
                    _inflight_c2t[0] = t0
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
                with _inflight_lock:
                    _inflight_c2t[0] = None
                if len(received) >= len(payload):
                    recv_exact = received[:len(payload)]
                    if len(recv_exact) != len(payload) or recv_exact != payload:
                        with errors_lock:
                            continuous_errors.append(
                                ("client→TCP", size, "length mismatch" if len(recv_exact) != len(payload) else "content mismatch")
                            )
                        print(f"client→TCP   size={size:5d}   VALIDATION FAILED", flush=True)
                    else:
                        lat_ms = 1000.0 * (t1 - t0)
                        with results_lock:
                            results.append((size, lat_ms))
                        print(f"client→TCP   size={size:5d}   latency_ms={lat_ms:.2f}")
                        if t1 - t0 >= STALL_THRESHOLD_S:
                            _record_stall("client→TCP", t1 - t0)
            except (BrokenPipeError, ConnectionResetError, OSError):
                with _inflight_lock:
                    _inflight_c2t[0] = None
                break

    def tcp_to_client():
        while not stop_event.is_set():
            size = random.randint(min_size, max_size)
            payload = os.urandom(size)
            try:
                t0 = time.perf_counter()
                with _inflight_lock:
                    _inflight_t2c[0] = t0
                tcp_conn.sendall(payload)
                received = b""
                while len(received) < len(payload) and not stop_event.is_set():
                    chunk = client_proc.stdout.read(len(payload) - len(received))
                    if not chunk:
                        break
                    received += chunk
                t1 = time.perf_counter()
                with _inflight_lock:
                    _inflight_t2c[0] = None
                if len(received) >= len(payload):
                    recv_exact = received[:len(payload)]
                    if len(recv_exact) != len(payload) or recv_exact != payload:
                        with errors_lock:
                            continuous_errors.append(
                                ("TCP→client", size, "length mismatch" if len(recv_exact) != len(payload) else "content mismatch")
                            )
                        print(f"TCP→client   size={size:5d}   VALIDATION FAILED", flush=True)
                    else:
                        lat_ms = 1000.0 * (t1 - t0)
                        with results_lock:
                            results.append((size, lat_ms))
                        print(f"TCP→client   size={size:5d}   latency_ms={lat_ms:.2f}")
                        if t1 - t0 >= STALL_THRESHOLD_S:
                            _record_stall("TCP→client", t1 - t0)
            except (BrokenPipeError, ConnectionResetError, OSError):
                with _inflight_lock:
                    _inflight_t2c[0] = None
                break

    run_c2t = not getattr(args, 'continuous_tcp_to_client_only', False)
    run_t2c = not getattr(args, 'continuous_client_to_tcp_only', False)
    t1 = threading.Thread(target=client_to_tcp, daemon=True)
    t2 = threading.Thread(target=tcp_to_client, daemon=True)
    if run_c2t:
        t1.start()
    if run_t2c:
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

    if continuous_errors:
        print(f"\nPayload validation: {len(continuous_errors)} mismatch(es)", file=sys.stderr)
        for direction, size, kind in continuous_errors[:20]:
            print(f"  {direction} size={size}: {kind}", file=sys.stderr)
        if len(continuous_errors) > 20:
            print(f"  ... and {len(continuous_errors) - 20} more", file=sys.stderr)
    else:
        print("\nPayload validation: all transmitted data received correctly.")

    _print_size_bucket_summary(results)

    # Stall summary
    with _stall_lock:
        stall_snapshot = list(_stall_events)
    if stall_snapshot:
        max_stall_s = max(d for _, d in stall_snapshot)
        c2t_stalls = [(d, ) for dir_, d in stall_snapshot if dir_ == "client→TCP"]
        t2c_stalls = [(d, ) for dir_, d in stall_snapshot if dir_ == "TCP→client"]
        print(f"\nStall events (>{STALL_THRESHOLD_S:.0f}s latency): {len(stall_snapshot)} total, "
              f"max={max_stall_s:.1f}s")
        if c2t_stalls:
            print(f"  client→TCP: {len(c2t_stalls)} stall(s), "
                  f"max={max(d[0] for d in c2t_stalls):.1f}s")
        if t2c_stalls:
            print(f"  TCP→client: {len(t2c_stalls)} stall(s), "
                  f"max={max(d[0] for d in t2c_stalls):.1f}s")
    else:
        print(f"\nNo stall events (threshold: >{STALL_THRESHOLD_S:.0f}s).")

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

    return 1 if continuous_errors else 0


def proxy_accept_loop(proxy_path, server_socket_path, delay_spec, stop_event, connection_callback=None, initial_connection_latency_sec=0.0, connection_death_probability=0.0):
    """Accept on proxy_path, for each connection relay to server_socket_path with latency.

    If connection_callback is not None, it is called with "opened" when a new connection
    is accepted and with "closed" when a connection ends (so the script can print connection events).
    initial_connection_latency_sec: delay before relaying any data on a new connection (e.g. to simulate SSH auth).
    connection_death_probability: per-packet probability (0–1) that a connection is killed (stops relaying, simulates dead link).
    """
    listen_sock = unix_listen(proxy_path)
    listen_sock.settimeout(0.5)
    try:
        while not stop_event.is_set():
            try:
                conn, _ = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError as _e:
                import sys as _sys
                print(f"[proxy_accept_loop] accept() raised: {_e}", file=_sys.stderr, flush=True)
                continue
            if connection_callback:
                connection_callback("opened")
            on_close = (lambda: connection_callback("closed")) if connection_callback else None
            t = threading.Thread(
                target=proxy_connection,
                args=(
                    conn,
                    server_socket_path,
                    delay_spec,
                    on_close,
                    initial_connection_latency_sec,
                    connection_death_probability,
                ),
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
        "--initial-connection-latency",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Delay in seconds before any data can be sent on a new carrier connection (simulates SSH auth; e.g. 2 for ~2s). Default 0",
    )
    parser.add_argument(
        "--connection-death-probability",
        type=float,
        default=0.0,
        metavar="P",
        help="Per-packet probability (0–1) that a carrier connection is killed (stops relaying; simulates link dying before failure is detected). Default 0. E.g. 0.01 for 1%%",
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
        "--extra-client-args",
        nargs=argparse.REMAINDER,
        default=[],
        help="Extra arguments passed directly to the ssh-oll client process",
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
    parser.add_argument(
        "--continuous-tcp-to-client-only",
        action="store_true",
        default=False,
        help="In --continuous mode, only run the TCP→client direction (suppress client→TCP)",
    )
    parser.add_argument(
        "--continuous-client-to-tcp-only",
        action="store_true",
        default=False,
        help="In --continuous mode, only run the client→TCP direction (suppress TCP→client)",
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
    connection_callback = None
    if args.continuous:
        connection_count = [0]
        connection_lock = threading.Lock()

        def connection_callback(event):
            with connection_lock:
                if event == "opened":
                    connection_count[0] += 1
                else:
                    connection_count[0] -= 1
                n = connection_count[0]
            if event == "opened":
                print(f"Connection opened (total {n})", flush=True)
            else:
                print(f"Connection closed (total {n})", flush=True)

    initial_latency_sec = max(0.0, args.initial_connection_latency)
    death_prob = max(0.0, min(1.0, args.connection_death_probability))
    proxy_thread = threading.Thread(
        target=proxy_accept_loop,
        args=(
            proxy_path,
            server_socket_path,
            delay_spec,
            stop_proxy,
            connection_callback,
            initial_latency_sec,
            death_prob,
        ),
        daemon=True,
    )
    proxy_thread.start()

    # 4. Start client with --unix-socket-connection
    client_cmd = [
        args.ssh_oll_path,
        "--unix-socket-connection",
        proxy_path,
        "--connections",
        str(args.connections),
        "--packet-size",
        str(min(args.packet_size, args.payload_size)),
    ]
    if args.extra_client_args:
        client_cmd += args.extra_client_args
    client_proc = subprocess.Popen(
        client_cmd,
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

    # Drain any data that came from the initial burst (so we start clean for measurements).
    # Must receive at least trigger_size bytes so trigger is fully consumed before we send warmup.
    drained = 0
    drain_deadline = time.monotonic() + 15.0
    while drained < trigger_size and time.monotonic() < drain_deadline:
        ready, _, _ = select.select([tcp_conn], [], [], 0.1)
        if ready:
            chunk = tcp_conn.recv(65536)
            if not chunk:
                break
            drained += len(chunk)
    while select.select([tcp_conn], [], [], 0.0)[0]:
        tcp_conn.recv(65536)

    latencies_client_to_tcp = []
    latencies_tcp_to_client = []
    payload_errors = []  # list of (direction, iteration, message) for validation failures

    def validate_payload(received, payload, direction, iteration=None):
        """Check received bytes match payload. Appends to payload_errors on failure. Returns True if valid."""
        if len(received) != len(payload):
            payload_errors.append((direction, iteration, f"length mismatch: sent {len(payload)}, got {len(received)}"))
            return False
        if received != payload:
            payload_errors.append((direction, iteration, "payload content mismatch (data corrupted in transit)"))
            return False
        return True

    # Warmup: one full round-trip each direction so the first timed iteration
    # doesn't pay for cold caches / scheduler; reduces stdin->TCP latency variance.
    _warm = os.urandom(args.payload_size)
    client_proc.stdin.write(_warm)
    client_proc.stdin.flush()
    _got = b""
    while len(_got) < len(_warm):
        _got += tcp_conn.recv(len(_warm) - len(_got))
    if not validate_payload(_got, _warm, "client→TCP (warmup)", None):
        print("Warmup client→TCP payload validation failed.", file=sys.stderr)
    _warm = os.urandom(args.payload_size)
    tcp_conn.sendall(_warm)
    _got = b""
    while len(_got) < len(_warm):
        _got += client_proc.stdout.read(len(_warm) - len(_got))
    if not validate_payload(_got, _warm, "TCP→client (warmup)", None):
        print("Warmup TCP→client payload validation failed.", file=sys.stderr)

    if args.continuous:
        return _run_continuous(
            client_proc,
            tcp_conn,
            stop_proxy,
            tcp_listen,
            args,
        )

    for i in range(args.iterations):
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
            received_exact = received[:len(payload)]
            if validate_payload(received_exact, payload, "client→TCP", i):
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
            received_exact = received[:len(payload)]
            if validate_payload(received_exact, payload, "TCP→client", i):
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

    # Report payload validation
    if payload_errors:
        print("Payload validation FAILED:", file=sys.stderr)
        for direction, iteration, msg in payload_errors:
            print(f"  {direction} iteration={iteration}: {msg}", file=sys.stderr)
        return 1
    print("Payload validation: all transmitted data received correctly.")

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
