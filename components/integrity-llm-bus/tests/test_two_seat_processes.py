"""Two OS processes share one core and produce one claim winner."""
import json
import subprocess
import sys
import textwrap
from urllib.request import Request, urlopen

from integrity_llm_bus.bus_server import BusCore, BusSeat, serve
from integrity_llm_bus.schema import body_sha256


CLIENT = textwrap.dedent(
    """
    import json, sys
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen
    url, token, op = sys.argv[1:4]
    payload = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    method = "GET" if data is None else "POST"
    request = Request(
        url + op,
        data=data,
        headers={"Content-Type": "application/json", "X-Integrity-Seat-Token": token},
        method=method,
    )
    try:
        with urlopen(request) as response:
            print(response.status)
            print(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(exc.code)
        print(exc.read().decode("utf-8"))
    """
)


def _post(url, token, op, payload):
    request = Request(
        url + op,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Integrity-Seat-Token": token},
        method="POST",
    )
    with urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def test_two_processes_claim_once_and_reject_a_stale_fence(tmp_path):
    seats = {
        "token-alice": BusSeat("alice", "host-a", frozenset({"read", "write"}), ("team/*", "seat/alice/*")),
        "token-bob": BusSeat("bob", "host-b", frozenset({"read", "write"}), ("team/*", "seat/bob/*")),
    }
    core = BusCore(tmp_path / "bus.sqlite3", lambda token: seats[token])
    for seat in seats.values():
        core.register_agent(seat, seat.seat_id)
    server = serve(core)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _post(url, "token-alice", "/v1/mesh/open", {"work_id": "work-1", "title": "shared"})
        script = tmp_path / "client.py"
        script.write_text(CLIENT, encoding="utf-8")
        commands = [
            [sys.executable, str(script), url, token, "/v1/mesh/claim", json.dumps({"work_id": "work-1", "ttl": 30})]
            for token in ("token-alice", "token-bob")
        ]
        processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for command in commands]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            status, body = stdout.splitlines()
            assert status == "200"
            results.append(json.loads(body))
        winners = [item for item in results if item["status"] == "acquired"]
        rejected = [item for item in results if item["status"] == "rejected"]
        assert len(winners) == 1 and len(rejected) == 1
        fence = winners[0]["fence"]
        stale = subprocess.run(
            [sys.executable, str(script), url, "token-alice", "/v1/mesh/progress",
             json.dumps({"work_id": "work-1", "fence": fence + 9, "note": "stale"})],
            check=True, capture_output=True, text=True, timeout=20,
        )
        stale_status, stale_body = stale.stdout.splitlines()
        assert stale_status == "409"
        assert "stale fencing token" in stale_body
        body = "hello from alice"
        posted = _post(url, "token-alice", "/v1/messages", {
            "id": "m1", "from": "alice", "to": "bob", "k": "note", "th": "t1",
            "body": body, "body_sha256": body_sha256(body),
        })
        assert posted["delivered"] is False and posted["delivery"] == "steer"
        secret = "secret-from-alice"
        private = _post(url, "token-alice", "/v1/messages", {
            "id": "m2", "from": "alice", "to": "bob", "k": "private", "th": "t2",
            "body": secret, "body_sha256": body_sha256(secret),
        })
        denied = subprocess.run(
            [sys.executable, str(script), url, "token-bob", "/v1/messages/" + private["id"]],
            check=True, capture_output=True, text=True, timeout=20,
        )
        assert denied.stdout.splitlines()[0] == "403"
        assert secret not in denied.stdout
    finally:
        server.shutdown()
        core.close()
