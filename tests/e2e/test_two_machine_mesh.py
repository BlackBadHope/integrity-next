"""Two processes enroll, claim one work item, drop a link, and reject a stale fence."""
import json
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

import pytest

from integrity_home.host_enrollment import HostDirectory
from integrity_home.seat_registry import SeatRegistryError
from integrity_llm_bus.bus_server import BusCore, BusSeat, serve
from integrity_llm_bus.schema import body_sha256


CLIENT = textwrap.dedent(
    """
    import json, sys
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen
    url, token, op, payload = sys.argv[1:5]
    request = Request(
        url + op,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Integrity-Seat-Token": token},
        method="POST",
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
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Integrity-Seat-Token": token},
        method="POST",
    )
    with urlopen(request) as response:
        return json.loads(response.read().decode())


def test_two_machines_enroll_claim_drop_and_reject_stale_fence(tmp_path):
    directory = HostDirectory(tmp_path / "hosts.sqlite3")
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alice_token = directory.create_token("alice", "host-a", "ssh_stdio", future)
    bob_token = directory.create_token("bob", "host-b", "webhook", future)
    alice = directory.join(alice_token, tmp_path / "alice-keys", ttl_seconds=30)
    bob = directory.join(bob_token, tmp_path / "bob-keys", ttl_seconds=30)
    assert (tmp_path / "alice-keys" / "host.key").stat().st_mode & 0o077 == 0
    assert (tmp_path / "bob-keys" / "peer.key").stat().st_mode & 0o077 == 0
    assert {item["host_id"] for item in directory.active()} == {"host-a", "host-b"}
    with pytest.raises(SeatRegistryError):
        directory.join(alice_token, tmp_path / "replay")

    seats = {
        "seat-alice": BusSeat("alice", "host-a", frozenset({"read", "write"}), ("team/*", "seat/alice/*")),
        "seat-bob": BusSeat("bob", "host-b", frozenset({"read", "write"}), ("team/*", "seat/bob/*")),
    }
    core = BusCore(tmp_path / "bus.sqlite3", lambda token: seats[token])
    for seat in seats.values():
        core.register_agent(seat, seat.seat_id)
    server = serve(core)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    script = tmp_path / "client.py"
    script.write_text(CLIENT, encoding="utf-8")
    try:
        _post(url, "seat-alice", "/v1/presence", {})
        _post(url, "seat-bob", "/v1/presence", {})
        _post(url, "seat-alice", "/v1/mesh/open", {"work_id": "job-1", "title": "mesh"})
        processes = [
            subprocess.Popen(
                [sys.executable, str(script), url, token, "/v1/mesh/claim",
                 json.dumps({"work_id": "job-1", "ttl": 1})],
                stdout=subprocess.PIPE, text=True,
            )
            for token in ("seat-alice", "seat-bob")
        ]
        bodies = []
        for process in processes:
            stdout, _stderr = process.communicate(timeout=20)
            status, body = stdout.splitlines()
            assert status == "200"
            bodies.append(json.loads(body))
        winners = [item for item in bodies if item["status"] == "acquired"]
        assert len(winners) == 1
        fence = winners[0]["fence"]
        directory.drop_link("host-a")
        assert {item["host_id"] for item in directory.active()} == {"host-b"}
        time.sleep(1.3)
        takeover = subprocess.run(
            [sys.executable, str(script), url, "seat-bob", "/v1/mesh/claim",
             json.dumps({"work_id": "job-1", "ttl": 30})],
            check=True, capture_output=True, text=True, timeout=20,
        )
        takeover_body = json.loads(takeover.stdout.splitlines()[1])
        assert takeover_body["status"] == "acquired"
        assert takeover_body["fence"] != fence
        directory.revoke("host-b")
        assert directory.active() == []
        stale = subprocess.run(
            [sys.executable, str(script), url, "seat-alice", "/v1/mesh/progress",
             json.dumps({"work_id": "job-1", "fence": fence + 3, "note": "late"})],
            check=True, capture_output=True, text=True, timeout=20,
        )
        assert stale.stdout.splitlines()[0] == "409"
        ping = _post(url, "seat-bob", "/v1/messages", {
            "id": "ping-1", "from": "bob", "to": "alice", "k": "note", "th": "t",
            "body": "ping", "body_sha256": body_sha256("ping"),
        })
        assert ping["from"] == "bob"
        assert alice["host_id"] == "host-a" and bob["transport"] == "webhook"
    finally:
        server.shutdown()
        core.close()
