"""One claim winner, a new fence on assign, and a recorded stale-fence reject."""
from datetime import datetime, timedelta, timezone

import pytest

from integrity_llm_bus.mesh import Mesh, StaleFencingTokenError


def _now(offset=0):
    return datetime.now(timezone.utc) + timedelta(seconds=offset)


def test_concurrent_claims_have_one_winner_and_stale_fence_is_rejected(tmp_path):
    mesh = Mesh(tmp_path / "mesh.sqlite3")
    now = _now()
    mesh.open("alice", "work-1", "shared", "team/work", now=now)
    first = mesh.claim("alice", "work-1", ttl_seconds=30, now=now)
    second = mesh.claim("bob", "work-1", ttl_seconds=30, now=now)
    assert first["status"] == "acquired"
    assert second["status"] == "rejected"
    with pytest.raises(StaleFencingTokenError) as stale:
        mesh.progress("alice", "work-1", first["fence"] + 1, "nope", now=now)
    assert stale.value.record["kind"] == "reject"
    assigned = mesh.assign("alice", "work-1", first["fence"], "bob", ttl_seconds=30, now=now)
    assert assigned["fence"] != first["fence"]
    with pytest.raises(StaleFencingTokenError):
        mesh.done("alice", "work-1", first["fence"], now=now)
    mesh.done("bob", "work-1", assigned["fence"], now=now)
    kinds = [event["kind"] for event in mesh.events("work-1")]
    assert "reject" in kinds and kinds[-1] == "done"
    mesh.close()


def test_expired_lease_rejects_progress(tmp_path):
    mesh = Mesh(tmp_path / "mesh.sqlite3")
    now = _now()
    mesh.open("alice", "work-2", "lease", "team/work", now=now)
    claimed = mesh.claim("alice", "work-2", ttl_seconds=5, now=now)
    with pytest.raises(StaleFencingTokenError):
        mesh.progress("alice", "work-2", claimed["fence"], "late", now=_now(30))
    mesh.close()
