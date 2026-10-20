import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from integrity_client_memory.operation_ledger import OperationLedger, Conflict, Pending, LedgerError

OWNER = "sha256:" + "a" * 64
ARGS = {"context_admission_id": "sha256:" + "b" * 64, "event_uid": "client:stand-ledger-0001", "kind": "thought", "summary": "synthetic"}
KEY = "append:" + ARGS["event_uid"]


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "private.sqlite3"
        self.ledger = OperationLedger(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def prepared(self):
        return self.ledger.prepare(OWNER, KEY, "integrity_append_event", ARGS)

    def test_original_bytes_survive_restart_before_send(self):
        first = self.prepared()
        reopened = OperationLedger(self.path).get(OWNER, KEY)
        self.assertEqual(first, reopened)
        self.assertEqual(json.loads(reopened["request_bytes"])["arguments"], ARGS)
        self.assertEqual(reopened["attempts"], 0)

    def test_conflicting_uid_never_replaces_original(self):
        self.prepared()
        with self.assertRaises(Conflict):
            self.ledger.prepare(OWNER, KEY, "integrity_append_event", {**ARGS, "summary": "changed"})
        self.assertEqual(self.ledger.get(OWNER, KEY)["arguments"], ARGS)

    def test_concurrent_claim_one_sender(self):
        self.prepared()
        def claim(_):
            try: return OperationLedger(self.path).claim_send(OWNER, KEY)["attempts"]
            except Pending: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(claim, range(8)))
        self.assertEqual(values.count(1), 1)
        self.assertEqual(values.count(None), 7)

    def test_crash_after_claim_stays_unknown_to_caller(self):
        self.prepared(); self.ledger.claim_send(OWNER, KEY)
        reopened = OperationLedger(self.path)
        self.assertEqual(reopened.recover_inflight()[0]["state"], "sending")
        with self.assertRaises(Pending): reopened.claim_send(OWNER, KEY)
        reopened.mark(OWNER, KEY, "unknown", expected_state="sending")
        with self.assertRaises(Pending): reopened.claim_send(OWNER, KEY)

    def test_known_unsent_retry_budget_persists(self):
        self.prepared(); self.ledger.claim_send(OWNER, KEY)
        self.ledger.mark(OWNER, KEY, "known-unsent")
        self.assertEqual(OperationLedger(self.path).claim_send(OWNER, KEY)["attempts"], 2)
        self.ledger.mark(OWNER, KEY, "known-unsent")
        with self.assertRaises(Pending): OperationLedger(self.path).claim_send(OWNER, KEY)

    def test_unknown_requires_explicit_reconciliation_transition(self):
        self.prepared(); self.ledger.claim_send(OWNER, KEY)
        self.ledger.mark(OWNER, KEY, "unknown")
        with self.assertRaises(Pending): self.ledger.mark(OWNER, KEY, "known-unsent")
        self.ledger.mark(OWNER, KEY, "reconciled-absent", expected_state="unknown")
        self.assertEqual(self.ledger.claim_send(OWNER, KEY)["attempts"], 2)

    def test_committed_receipt_is_immutable(self):
        self.prepared(); self.ledger.claim_send(OWNER, KEY)
        receipt = {"receipt": {"event_id": 1, "event_uid": ARGS["event_uid"]}}
        self.ledger.mark(OWNER, KEY, "committed", receipt=receipt)
        self.assertEqual(self.ledger.mark(OWNER, KEY, "committed", receipt=receipt)["receipt"], receipt)
        with self.assertRaises(Conflict): self.ledger.mark(OWNER, KEY, "committed", receipt={"changed": True})
        with self.assertRaises(Pending): self.ledger.claim_send(OWNER, KEY)

    def test_close_semantic_key_and_owner_are_bound(self):
        with self.assertRaises(Conflict):
            self.ledger.prepare(OWNER, "close:"+OWNER, "integrity_turn_memory_close", {"registration_id":"sha256:"+"f"*64,"outcome":"no-event","no_event_reason":"read-only"})
        close = self.ledger.prepare(OWNER, "close:"+OWNER, "integrity_turn_memory_close", {"registration_id":OWNER,"outcome":"events","events":[{"event_id":1,"event_uid":ARGS["event_uid"],"request_sha256":"d"*64}]})
        with self.assertRaises(Conflict):
            self.ledger.prepare(OWNER, "close:"+OWNER, "integrity_turn_memory_close", {"registration_id":OWNER,"outcome":"no-event","no_event_reason":"read-only"})
        self.assertEqual(close["arguments"]["outcome"], "events")

    def test_stored_request_tampering_is_detected(self):
        self.prepared()
        db = sqlite3.connect(self.path)
        try:
            with db: db.execute("UPDATE operations SET request_bytes=?", (b'{}',))
        finally: db.close()
        with self.assertRaises(Conflict): self.ledger.get(OWNER, KEY)

    def test_quota_denies_without_deleting_pending(self):
        limited = OperationLedger(self.path, max_records=1)
        limited.prepare(OWNER, KEY, "integrity_append_event", ARGS)
        args = {**ARGS, "event_uid": "client:stand-ledger-0002"}
        with self.assertRaises(LedgerError): limited.prepare(OWNER, "append:"+args["event_uid"], "integrity_append_event", args)
        self.assertIsNotNone(limited.get(OWNER, KEY))

    def test_finite_json_numbers_preserved_and_nonfinite_rejected(self):
        args = {**ARGS, "details": {"synthetic_ratio": 1.25}}
        record = self.ledger.prepare(OWNER, KEY, "integrity_append_event", args)
        self.assertEqual(record["arguments"]["details"]["synthetic_ratio"], 1.25)
        with self.assertRaises(LedgerError):
            self.ledger.prepare(OWNER, KEY, "integrity_append_event", {**ARGS, "details": {"bad": float('nan')}})

    def test_global_uid_cannot_be_reserved_by_a_foreign_registration(self):
        self.prepared()
        with self.assertRaises(Conflict):
            self.ledger.prepare("sha256:"+"f"*64, KEY, "integrity_append_event", ARGS)

    def test_completed_payload_gc_preserves_uid_owner_tombstone(self):
        limited=OperationLedger(self.path,max_records=1,retention_seconds=1)
        limited.prepare(OWNER,KEY,"integrity_append_event",ARGS)
        limited.mark(OWNER,KEY,"committed",receipt={"synthetic":True})
        db=sqlite3.connect(self.path)
        try:
            with db: db.execute("UPDATE operations SET updated_ns=0")
        finally: db.close()
        args={**ARGS,"event_uid":"client:stand-ledger-0002"}
        limited.prepare(OWNER,"append:"+args["event_uid"],"integrity_append_event",args)
        old=limited.get(OWNER,KEY)
        self.assertEqual(old["state"],"archived")
        self.assertEqual(old["request_bytes"],b"")
        with self.assertRaises(Conflict): limited.prepare("sha256:"+"f"*64,KEY,"integrity_append_event",ARGS)
        with self.assertRaises(Pending): limited.prepare(OWNER,KEY,"integrity_append_event",ARGS)


if __name__ == "__main__": unittest.main()
