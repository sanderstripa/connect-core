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

def udp_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        while True:
            data, addr = sock.recvfrom(4096)
            if port == 53:
                if len(data) < 17:
                    continue
                # One fixed authoritative A answer; explicitly not a resolver.
                data = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + data[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(HOST)
            sock.sendto(data, addr)

def serve():
    for port in (53, 18082):
        threading.Thread(target=udp_server, args=(port,), daemon=True).start()
    tcp = TCP((HOST, 18083), Echo)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    http_server = http.server.ThreadingHTTPServer((HOST, 18080), HTTP)
    print("lab services ready", flush=True)
    http_server.serve_forever()

def exchange(port, data, host=HOST):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(data, (host, port))
        return sock.recv(4096)

def tcp_echo(size):
    data = bytes(range(256)) * (size // 256)
    start = time.perf_counter()
    with socket.create_connection((HOST, 18083), timeout=10) as sock:
        # Avoid simultaneous large blocking send/echo writes.
        sock.sendall(data)
        out = bytearray()
        while len(out) < len(data):
            chunk = sock.recv(65536)
            assert chunk, "premature TCP EOF"
            out.extend(chunk)
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        durations = list(pool.map(tcp_echo, [65536] * 8))
    # Separate sequential measurement: useful one-way payload, includes connect,
    # echo and teardown. It is not a one-way link throughput benchmark.
    elapsed = tcp_echo(1048576)
    samples.sort()
    print(json.dumps({"http": "pass", "udp_100": "pass", "dns": "pass", "tcp_binary_8": "pass", "tcp_half_close": "pass", "udp_rtt_ms": {"p50": statistics.median(samples), "p95": samples[94], "p99": samples[98]}, "tcp_1MiB_echo_seconds": elapsed, "tcp_useful_MiB_per_second": 1 / elapsed, "concurrent_tcp_seconds_max": max(durations)}, indent=2), flush=True)

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

if __name__ == "__main__":
    {"serve": serve, "ready": ready, "check": check, "failure": failure, "denied": denied}[sys.argv[1]]()
