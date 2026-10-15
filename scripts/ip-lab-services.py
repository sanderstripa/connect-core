#!/usr/bin/env python3
"""Disposable lab fixtures. No external resolution or third-party dependencies."""
import concurrent.futures
import hashlib
import http.server
import json
import socket
import socketserver
import statistics
import struct
import sys
import threading
import time
import urllib.request

HOST = "10.232.0.1"
CANARY = b"CONNECT-IP-LAB-PRIVATE-CANARY-2026"

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = CANARY + b"\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)

class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128  # Python <=3.14 defaults to 5; the lab tests 32 peers.

class HTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer's default bind calls getfqdn(), which tries external reverse
        # DNS. This fixture must start in a namespace without any DNS/default route.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "connect-ip-lab"
        self.server_port = self.server_address[1]

def udp_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        while True:
            data, addr = sock.recvfrom(4096)
            if port == 53:
                if len(data) < 17:
                    continue
                # Parse exactly one bounded question, ignoring EDNS/additional
                # records rather than accidentally placing them before the answer.
                if struct.unpack("!H", data[4:6])[0] != 1:
                    continue
                pos, labels = 12, []
                while pos < len(data) and data[pos] != 0:
                    size = data[pos]
                    if size > 63 or pos + 1 + size >= len(data):
                        break
                    labels.append(data[pos+1:pos+1+size].lower())
                    pos += 1 + size
                else:
                    if pos + 5 <= len(data):
                        end = pos + 5
                        kind, cls = struct.unpack("!HH", data[pos+1:end])
                        question = data[12:end]
                        allowed = labels and labels[-1] == b"test" and cls == 1
                        answer = b""
                        if allowed and kind == 1:
                            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(HOST)
                        flags = 0x8180 if allowed else 0x8183
                        data = data[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0) + question + answer
                        sock.sendto(data, addr)
                    continue
                continue
            sock.sendto(data, addr)

def serve():
    for port in (53, 18082):
        threading.Thread(target=udp_server, args=(port,), daemon=True).start()
    tcp = TCP((HOST, 18083), Echo)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    http_server = HTTPServer((HOST, 18080), HTTP)
    print("lab services ready", flush=True)
    http_server.serve_forever()

def exchange(port, data, host=HOST, barrier=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        if barrier is not None:
            sock.bind(('0.0.0.0', 0))
            barrier.wait(timeout=10)
        sock.sendto(data, (host, port))
        return sock.recv(4096)

def tcp_echo(size, host=HOST, port=18083, barrier=None, timeout=10):
    data = bytes(range(256)) * (size // 256)
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        if barrier is not None:
            barrier.wait(timeout=10)  # All N established sockets overlap.
        # Read while sending. Writing a large payload before reading its echo
        # can deadlock when both peers' socket buffers fill.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            sender = pool.submit(sock.sendall, data)
            try:
                out = bytearray()
                while len(out) < len(data):
                    chunk = sock.recv(65536)
                    assert chunk, "premature TCP EOF"
                    out.extend(chunk)
                sender.result(timeout=timeout)
            except BaseException:
                sock.close()  # Unblock sender before the executor joins it.
                raise
        sock.shutdown(socket.SHUT_WR)
        assert sock.recv(1) == b"", "half-close did not finish"
    assert hashlib.sha256(out).digest() == hashlib.sha256(data).digest()
    return time.perf_counter() - start

def check():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    assert opener.open(f"http://{HOST}:18080/", timeout=5).read() == CANARY + b"\n"
    samples = []
    for n in range(100):
        payload = CANARY + bytes([n]) + bytes(range(256)) * 3
        start = time.perf_counter()
        assert exchange(18082, payload) == payload
        samples.append((time.perf_counter() - start) * 1000)
    query = b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + b"\x07example\x04test\x00\x00\x01\x00\x01"
    answer = exchange(53, query)
    assert answer[:2] == query[:2] and answer[-4:] == socket.inet_aton(HOST)
    connection_results = {}
    for count in (1, 8, 32):
        print(f"checking {count} concurrent TCP/UDP connections", file=sys.stderr, flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            tcp_gate, udp_gate = threading.Barrier(count), threading.Barrier(count)
            durations = list(pool.map(lambda _: tcp_echo(16384, barrier=tcp_gate), range(count)))
            echoes = list(pool.map(lambda n: exchange(18082, CANARY + bytes([n]), barrier=udp_gate), range(count)))
        assert echoes == [CANARY + bytes([n]) for n in range(count)]
        connection_results[str(count)] = {"tcp": "pass", "udp": "pass", "overlap_barrier": True, "tcp_seconds_max": max(durations)}
    # Separate sequential measurement: useful one-way payload, includes connect,
    # echo and teardown. It is not a one-way link throughput benchmark.
    elapsed = tcp_echo(1048576)
    samples.sort()
    print(json.dumps({"http": "pass", "udp_100": "pass", "dns": "pass", "connections": connection_results, "tcp_half_close": "pass", "udp_rtt_ms": {"p50": statistics.median(samples), "p95": samples[94], "p99": samples[98]}, "tcp_1MiB_echo_seconds": elapsed, "tcp_useful_MiB_per_second": 1 / elapsed}, indent=2), flush=True)


def throughput():
    # The same real TCP echo fixture is used on Windows and Linux. This is
    # simultaneous upload/download, not a public one-way speedtest or IPC test.
    streams, size = 4, 8 * 1024 * 1024
    gate = threading.Barrier(streams)
    samples, stop = [], threading.Event()
    probe_losses = 0
    def latency():
        nonlocal probe_losses
        while not stop.is_set():
            started=time.perf_counter()
            try:
                if exchange(18082, CANARY) != CANARY: raise AssertionError('latency probe corrupted')
            except socket.timeout:
                # UDP delivery is not guaranteed. Report censored samples and
                # loss explicitly instead of hiding loss or aborting the baseline.
                probe_losses += 1
                continue
            samples.append((time.perf_counter()-started)*1000)
            stop.wait(.05)
    started=time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=streams+1) as pool:
        probe=pool.submit(latency)
        try:
            durations=list(pool.map(lambda _: tcp_echo(size,barrier=gate,timeout=30),range(streams)))
        finally:
            stop.set()
        probe.result()
    elapsed=time.perf_counter()-started
    if not samples: raise AssertionError('No loaded latency measurements')
    samples.sort()
    print(json.dumps({'scope':'real TCP duplex through OS TUN, not public Internet', 'streams':streams,
        'bytes_per_direction':streams*size,'seconds':elapsed,'useful_mbps_per_direction':streams*size*8/elapsed/1e6,
        'max_stream_seconds':max(durations),'udp_loaded_rtt_ms':{'samples':len(samples),'lost':probe_losses,'timeout_ms':2000,'p50':statistics.median(samples),'p95':samples[min(len(samples)-1,int(len(samples)*.95))],'max':max(samples)}},indent=2),flush=True)

def ready():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 5
    while True:
        try:
            assert opener.open(f"http://{HOST}:18080/", timeout=0.5).read() == CANARY + b"\n"
            assert exchange(18082, CANARY) == CANARY
            print("fixture listeners ready", flush=True)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)

def failure():
    for port in (53, 18082):
        try:
            exchange(port, CANARY)
        except OSError:
            continue
        raise AssertionError(f"direct fallback on UDP/{port}")
    try:
        with socket.create_connection((HOST, 18083), timeout=2):
            pass
    except OSError:
        print("endpoint failure: TCP/UDP/DNS fail closed", flush=True)
        return
    raise AssertionError("direct TCP fallback")

def denied():
    try:
        exchange(18082, CANARY, "10.232.0.9")
    except OSError:
        print("unallowlisted destination denied", flush=True)
        return
    raise AssertionError("destination policy bypass")

def self_check():
    # Real sockets, ephemeral loopback port; catches fixture deadlocks without
    # creating TUN/routes or relying on any DNS/Internet/service ports.
    with TCP(("127.0.0.1", 0), Echo) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            tcp_echo(1048576, "127.0.0.1", server.server_address[1])
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda _: tcp_echo(65536, "127.0.0.1", server.server_address[1]), range(8)))
        finally:
            server.shutdown()
            worker.join()
    print("fixture binary TCP/duplex/half-close self-check passed", flush=True)

if __name__ == "__main__":
    {"serve": serve, "ready": ready, "check": check, "throughput": throughput, "failure": failure, "denied": denied, "self-check": self_check}[sys.argv[1]]()
