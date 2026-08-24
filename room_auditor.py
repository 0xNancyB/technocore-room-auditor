#!/usr/bin/env python3
"""Audit a saved Technocore room JSON response offline."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
MAX_MESSAGE_CHARS = 4096
ROOM_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DID_PATTERN = re.compile(rf"did:key:z6Mk[{re.escape(BASE58BTC)}]{{44}}")
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


class SnapshotError(ValueError):
    """The snapshot cannot be safely parsed or audited."""


def nonnegative_integer(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def positive_integer(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def finding(code: str, detail: str, sequence: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "detail": detail}
    if positive_integer(sequence):
        result["seq"] = sequence
    return result


def validate_top_level(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SnapshotError("snapshot JSON must contain an object")
    room = payload.get("room")
    if not isinstance(room, str) or ROOM_PATTERN.fullmatch(room) is None:
        raise SnapshotError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    messages = payload.get("messages")
    if not isinstance(messages, list) or any(not isinstance(item, dict) for item in messages):
        raise SnapshotError("messages must be a list of JSON objects")
    if not nonnegative_integer(payload.get("count")):
        raise SnapshotError("count must be a non-negative integer")
    if not nonnegative_integer(payload.get("last_seq")):
        raise SnapshotError("last_seq must be a non-negative integer")
    first_seq = payload.get("first_seq")
    if first_seq is not None and not nonnegative_integer(first_seq):
        raise SnapshotError("first_seq must be a non-negative integer when present")
    return payload


def audit_snapshot(payload: Any) -> dict[str, Any]:
    snapshot = validate_top_level(payload)
    messages = snapshot["messages"]
    findings: list[dict[str, Any]] = []

    if snapshot["count"] != len(messages):
        findings.append(
            finding(
                "count-mismatch",
                f"count is {snapshot['count']} but messages contains {len(messages)} records",
            )
        )

    sequences: list[int] = []
    for index, message in enumerate(messages):
        sequence = message.get("seq")
        if not positive_integer(sequence):
            findings.append(finding("invalid-sequence", f"message index {index} has invalid seq"))
            continue
        sequences.append(sequence)

        if not valid_timestamp(message.get("ts")):
            findings.append(finding("invalid-timestamp", "ts must be ISO-8601 UTC ending in Z", sequence))

        writer = message.get("from")
        if not isinstance(writer, str) or not writer:
            findings.append(finding("invalid-writer", "from must be a non-empty string", sequence))
            signed = False
        else:
            signed = writer.startswith("did:key:")
            if signed and DID_PATTERN.fullmatch(writer) is None:
                findings.append(finding("invalid-did", "signed writer is not canonical Ed25519 did:key", sequence))

        nonce = message.get("nonce")
        if signed:
            nonce_text = str(nonce)
            if isinstance(nonce, bool) or NONCE_PATTERN.fullmatch(nonce_text) is None:
                findings.append(finding("invalid-nonce", "signed message nonce must contain 1-19 digits", sequence))
        elif "nonce" in message:
            findings.append(finding("unsigned-nonce", "unsigned message unexpectedly contains nonce", sequence))

        text = message.get("text")
        if not isinstance(text, str):
            findings.append(finding("invalid-text", "text must be a string", sequence))
        else:
            if not text or len(text) > MAX_MESSAGE_CHARS:
                findings.append(
                    finding("invalid-text-length", f"text length is {len(text)}; expected 1-{MAX_MESSAGE_CHARS}", sequence)
                )
            if text != text.strip():
                findings.append(finding("unswept-whitespace", "stored text has leading or trailing whitespace", sequence))
            invisible = [
                f"U+{ord(character):04X}"
                for character in text
                if unicodedata.category(character) in INVISIBLE_CATEGORIES
            ]
            if invisible:
                findings.append(
                    finding(
                        "unswept-invisible",
                        "stored text contains invisible characters: " + ", ".join(invisible[:8]),
                        sequence,
                    )
                )

    for previous, current in zip(sequences, sequences[1:]):
        if current <= previous:
            findings.append(finding("sequence-order", f"sequence {current} follows {previous}", current))
        elif current > previous + 1:
            findings.append(finding("sequence-gap", f"missing sequences {previous + 1}-{current - 1}", current))

    if sequences:
        if snapshot.get("first_seq") != sequences[0]:
            findings.append(
                finding("first-seq-mismatch", f"first_seq does not match first returned sequence {sequences[0]}")
            )
        if snapshot["last_seq"] != sequences[-1]:
            findings.append(
                finding("last-seq-mismatch", f"last_seq does not match last returned sequence {sequences[-1]}")
            )

    return {
        "status": "pass" if not findings else "fail",
        "room": snapshot["room"],
        "messages_audited": len(messages),
        "finding_count": len(findings),
        "findings": findings,
    }


def load_snapshot(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    try:
        raw = resolved.read_bytes()
    except OSError as error:
        raise SnapshotError(f"cannot read snapshot: {error}") from error
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("snapshot exceeds the 5 MiB safety limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SnapshotError("snapshot is not valid UTF-8 JSON") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_snapshot(load_snapshot(args.snapshot))
    except SnapshotError as error:
        print(json.dumps({"status": "error", "detail": str(error)}, indent=2))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
