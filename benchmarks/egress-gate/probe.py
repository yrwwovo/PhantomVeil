"""Run only in the front-only Docker container; no real targets are contacted."""
import http.client
import socket

GATE = ("gate", 8787)
TARGET = "http://fixture:8000"


def through_gate(method, url, expected_status, expected_attempts):
    connection = http.client.HTTPConnection(*GATE, timeout=6)
    connection.request(method, url)
    response = connection.getresponse()
    response.read()
    actual = (response.status, int(response.getheader("x-pveil-network-attempts")))
    connection.close()
    assert actual == (expected_status, expected_attempts), (method, url, actual)
    print(f"{method} {url}: {actual}")


through_gate("GET", TARGET + "/ok", 200, 1)
through_gate("GET", "http://burpsuite/", 403, 1)
through_gate("GET", TARGET + "/forbidden", 403, 1)
through_gate("GET", "http://fixture:8001/outside", 403, 1)
through_gate("GET", TARGET + "/redirect-allowed", 200, 3)
through_gate("GET", TARGET + "/redirect-denied", 403, 4)
through_gate("GET", TARGET + "/ok", 429, 4)
through_gate("POST", TARGET + "/ok", 405, 4)

connection = http.client.HTTPConnection(*GATE, timeout=6)
connection.request("CONNECT", "fixture:8000")
response = connection.getresponse()
response.read()
assert response.status == 405, response.status
connection.close()
print("CONNECT: 405")

try:
    with socket.create_connection(("172.30.90.10", 8000), timeout=2):
        raise AssertionError("candidate reached fixture directly")
except (OSError, TimeoutError) as exc:
    print(f"direct fixture connection blocked: {type(exc).__name__}")

print("GATE_PROBE_PASSED")
