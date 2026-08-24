from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import room_auditor as auditor


DID = "did:key:z6Mk" + "1" * 44


def message(seq=10, writer=DID, nonce=123, text="hello"):
    result = {
        "seq": seq,
        "ts": "2026-08-24T18:00:00.000000Z",
        "from": writer,
        "text": text,
    }
    if nonce is not None:
        result["nonce"] = nonce
    return result


def snapshot(messages):
    return {
        "room": "technocore",
        "count": len(messages),
        "first_seq": messages[0]["seq"] if messages else 0,
        "last_seq": messages[-1]["seq"] if messages else 0,
        "messages": messages,
    }


class RoomAuditorTests(unittest.TestCase):
    def test_clean_signed_and_unsigned_records_pass(self):
        unsigned = message(seq=11, writer="human", nonce=None, text="hello")
        report = auditor.audit_snapshot(snapshot([message(), unsigned]))
        self.assertEqual(report["status"], "pass")

    def test_sequence_gap_is_reported(self):
        report = auditor.audit_snapshot(snapshot([message(10), message(12)]))
        self.assertIn("sequence-gap", [item["code"] for item in report["findings"]])

    def test_count_and_cursors_are_checked(self):
        payload = snapshot([message(10)])
        payload.update({"count": 2, "first_seq": 9, "last_seq": 11})
        codes = [item["code"] for item in auditor.audit_snapshot(payload)["findings"]]
        self.assertIn("count-mismatch", codes)
        self.assertIn("first-seq-mismatch", codes)
        self.assertIn("last-seq-mismatch", codes)

    def test_malformed_did_and_nonce_are_reported(self):
        report = auditor.audit_snapshot(snapshot([message(writer="did:key:bad", nonce="abc")]))
        codes = [item["code"] for item in report["findings"]]
        self.assertIn("invalid-did", codes)
        self.assertIn("invalid-nonce", codes)

    def test_unsigned_nonce_is_reported(self):
        report = auditor.audit_snapshot(snapshot([message(writer="human", nonce=123)]))
        self.assertIn("unsigned-nonce", [item["code"] for item in report["findings"]])

    def test_invalid_timestamp_is_reported(self):
        payload = snapshot([message()])
        payload["messages"][0]["ts"] = "yesterday"
        self.assertIn(
            "invalid-timestamp",
            [item["code"] for item in auditor.audit_snapshot(payload)["findings"]],
        )

    def test_invisible_and_surrounding_whitespace_are_reported(self):
        report = auditor.audit_snapshot(snapshot([message(text=" hello\u200d ")]))
        codes = [item["code"] for item in report["findings"]]
        self.assertIn("unswept-invisible", codes)
        self.assertIn("unswept-whitespace", codes)

    def test_invalid_top_level_shape_is_rejected(self):
        with self.assertRaises(auditor.SnapshotError):
            auditor.audit_snapshot({"room": "Bad Room", "messages": []})

    def test_oversized_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "large.json")
            path.write_bytes(b" " * (auditor.MAX_SNAPSHOT_BYTES + 1))
            with self.assertRaisesRegex(auditor.SnapshotError, "5 MiB"):
                auditor.load_snapshot(path)


if __name__ == "__main__":
    unittest.main()
