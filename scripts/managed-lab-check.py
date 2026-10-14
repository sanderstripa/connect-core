"""Checks the actual panel and managed TUN server inside the disposable edge namespace."""
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

origin = "http://127.0.0.1:17890"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""

def request(path, data=None):
    headers = {"Origin": origin, "X-Connect-UI": "1", "X-CSRF-Token": csrf, "Content-Type": "application/json"}
    req = urllib.request.Request(origin + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
    with opener.open(req, timeout=15) as response:
        return json.load(response)

for attempt in range(100):
    try:
        login = request("/auth/login", {"username": "admin", "password": "isolated-ci-only-password"})
        csrf = login["csrf"]
        status = request("/api/status")
        break
    except (OSError, urllib.error.URLError):
        time.sleep(.05)
else:
    raise AssertionError("panel/control not ready")

mode = sys.argv[1]
if mode == "start":
    assert status["status"] == "stopped", status
    status = request("/api/server", {"action": "start"})
    assert status["status"] == "running"
elif mode == "revoke":
    assert status["status"] == "running"
    assert status["active_sessions"] == 1
    assert status["received_bytes"] > 0 and status["sent_bytes"] > 0
    assert status["metrics"]["ram_total_bytes"] > 0
    device = status["devices"][0]
    request("/api/device", {"id": device["id"], "action": "revoke", "confirm": True})
    for attempt in range(100):
        current = request("/api/status")
        if current["active_sessions"] == 0:
            break
        time.sleep(.05)
    assert current["active_sessions"] == 0
    assert current["devices"][0]["access"] == "revoked"
    print(json.dumps({"real_tun_received_bytes": status["received_bytes"], "real_tun_sent_bytes": status["sent_bytes"], "active_revocation": "passed"}))
elif mode == "persisted":
    assert status["status"] == "stopped"
    assert status["devices"][0]["access"] == "revoked"
    assert request("/api/server", {"action": "start"})["status"] == "running"
else:
    raise AssertionError("unknown mode")
