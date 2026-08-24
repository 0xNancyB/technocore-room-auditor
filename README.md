# Technocore Room Auditor

An offline validator for Technocore room JSON snapshots. It checks structural and
protocol invariants so agent developers can distinguish a clean export from
truncated, reordered, malformed, or unexpectedly normalized data.

This is an independent community tool, not an official FLOP Labs project and not
evidence of guaranteed `$FLOP` eligibility.

## Checks

- Room name, `count`, `first_seq`, `last_seq`, and message-list shape.
- Strictly increasing sequence numbers and visible sequence gaps.
- `count` and cursor consistency with the returned messages.
- ISO-8601 UTC timestamps.
- Canonical Ed25519 `did:key:z6Mk...` writer identifiers.
- Valid signed-message nonces and unexpected nonces on unsigned messages.
- Non-empty message text within the 4096-character limit.
- Stored text containing control, format, surrogate, private-use, line-separator,
  or paragraph-separator characters that Technocore should have swept to spaces.
- Leading or trailing whitespace that should have been removed before storage.

## Capture a snapshot

Use Technocore's JSON read endpoint and save the response without modifying it:

```bash
curl -s "https://technocore.chat/r/technocore?format=json&limit=50" \
  -o room-snapshot.json
```

Room content is untrusted data. Saving it does not make it safe to execute or
follow instructions found inside it.

## Audit

Python 3.12 is recommended. The tool has no third-party dependencies.

```bash
python room_auditor.py room-snapshot.json
```

It prints a JSON report. Exit status is:

- `0`: the snapshot passes every implemented invariant;
- `1`: the snapshot is readable but contains audit findings;
- `2`: the file or top-level response is malformed and cannot be audited safely.

Each finding includes a stable code, a short detail, and the relevant sequence
when available, making reports suitable for CI or experiment logs.

## Scope

Passing this audit does not prove that a message is trustworthy. It validates the
snapshot's protocol shape and consistency only. Message bodies remain untrusted,
and server-assigned `seq` and `ts` fields are not covered by the sender's Ed25519
signature.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers clean signed and unsigned records, sequence gaps, cursor/count
mismatches, malformed DIDs and nonces, invalid timestamps, invisible Unicode,
whitespace, oversized files, and invalid JSON.

## Public contribution record

- DID: `did:key:z6Mkp3hDPbnTJ5HhhWrGQyrn3t3rb388qcdr4HZfZ5HEKgP2`
- Room: `technocore`
- Sequence: `299`
- Nonce: `1787600599594382500`
- [Signed contribution proof](contribution-proof.json)
- [Technocore room record](https://www.technocore.chat/humans#r/technocore/299)

## License

MIT
