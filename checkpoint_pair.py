"""Staging-only verification for paired ledger/role-queue backup receipts.

This module does not upload, restore, acknowledge a ledger, or open production
state. ExpectedPair must be pinned from independently validated local snapshots
and exact tool-returned Library identities before the round trip. File hashes
establish byte integrity, not the provenance of a caller-supplied tool receipt.
Existing ledger checkpoint-ack remains responsible for ledger archive semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import stat
from typing import Mapping, Any


class PairBlocked(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PairBlocked(message)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise PairBlocked("Manifest is not canonical JSON data") from exc


def _digest(value: Any, label: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"Invalid {label}")
    return value


def _text(value: Any, label: str) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 512 and "\x00" not in value, f"Invalid {label}")
    return value


def _int(value: Any, label: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"Invalid {label}")
    return value


def _file_hash(path: Any) -> str:
    p = Path(_text(path, "downloaded archive path"))
    _require(p.is_absolute(), "Archive path must be absolute")
    try:
        before = p.lstat()
        _require(stat.S_ISREG(before.st_mode) and not p.is_symlink(), "Archive must be a regular non-symlink file")
        h = sha256()
        with p.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), "Archive identity changed before read")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
            after_fd = os.fstat(stream.fileno())
        after = p.lstat()
    except OSError as exc:
        raise PairBlocked(f"Archive unavailable: {type(exc).__name__}") from exc
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    _require(identity(before) == identity(opened) == identity(after_fd) == identity(after), "Archive changed during verification")
    return h.hexdigest()


@dataclass(frozen=True)
class ExpectedPair:
    account: str
    ledger_db_id: str
    queue_db_id: str
    checkpoint_id: str
    checkpoint_sequence: int
    result_digest: str
    registry_revision: int
    ledger_checkpoint_hash: str
    ledger_archive_sha256: str
    queue_archive_sha256: str
    ledger_library_file_id: str
    ledger_library_version: str
    ledger_previous_version: str
    queue_library_file_id: str
    queue_library_version: str
    queue_previous_version: str
    ledger_downloaded_archive: str
    queue_downloaded_archive: str
    ledger_schema_version: int = 2
    queue_schema_version: int = 1

    def validate(self) -> None:
        for name in ("account", "ledger_db_id", "queue_db_id", "checkpoint_id", "ledger_library_file_id", "ledger_library_version", "queue_library_file_id", "queue_library_version"):
            _text(getattr(self, name), name)
        for name in ("result_digest", "ledger_checkpoint_hash", "ledger_archive_sha256", "queue_archive_sha256"):
            _digest(getattr(self, name), name)
        for name in ("checkpoint_sequence", "registry_revision", "ledger_schema_version", "queue_schema_version"):
            _int(getattr(self, name), name, 1)
        _require(self.ledger_schema_version == 2 and self.queue_schema_version == 1, "Unsupported paired schema version")
        _require(self.ledger_library_file_id != self.queue_library_file_id, "Ledger and queue need separate pinned Library identities")
        for name in ("ledger_previous_version", "queue_previous_version"):
            value = getattr(self, name)
            _require(isinstance(value, str) and len(value) <= 512, f"Invalid {name}")
        _require(self.queue_library_version != self.queue_previous_version,
                 "Queue Library version must advance")
        for name in ("ledger_downloaded_archive", "queue_downloaded_archive"):
            _require(Path(_text(getattr(self, name), name)).is_absolute(), "Pin exact absolute paths returned by materialization")


@dataclass(frozen=True)
class VerifiedPair:
    expected: ExpectedPair
    manifest_sha256: str
    verified_at: int
    ledger_transport_reference: str
    queue_transport_reference: str

    def checkpoint_proof_fields(self) -> dict[str, Any]:
        e = self.expected
        return {"account": e.account, "ledger_db_id": e.ledger_db_id,
                "checkpoint_id": e.checkpoint_id, "checkpoint_sequence": e.checkpoint_sequence,
                "checkpoint_hash": e.ledger_checkpoint_hash, "archive_sha256": e.ledger_archive_sha256, "result_digest": e.result_digest,
                "library_file_id": e.ledger_library_file_id, "library_version": e.ledger_library_version,
                "queue_db_id": e.queue_db_id, "queue_archive_sha256": e.queue_archive_sha256,
                "queue_library_file_id": e.queue_library_file_id, "queue_library_version": e.queue_library_version,
                "queue_previous_version": e.queue_previous_version,
                "registry_revision": e.registry_revision, "pair_manifest_sha256": self.manifest_sha256}


def verify_pair(manifest: Mapping[str, Any], expected: ExpectedPair, *, now: int, max_age: int = 300) -> VerifiedPair:
    """Verify exact pair metadata and actual downloaded bytes; never clear gates.

The caller must also require a fresh successful ledger status with matching
checkpoint sequence/hash/Library identity, no writer, no STOP, no unresolved
action and checkpoint_pending=false. A VerifiedPair alone is not dispatch
permission and does not prove that any upload or remote acknowledgement ran.
"""
    expected.validate()
    _int(now, "now")
    _int(max_age, "max_age", 1)
    _require(max_age <= 300, "Pair freshness cannot exceed the five-minute safety bound")
    _require(isinstance(manifest, Mapping), "Pair manifest is missing")
    expected_meta = asdict(expected)
    keys = {"schema", "expected", "ledger_receipt", "queue_receipt", "verified_at"}
    _require(set(manifest) == keys, "Unexpected or missing pair manifest fields")
    _require(manifest["schema"] == "role-queue-checkpoint-pair-v1", "Wrong pair manifest schema")
    _require(isinstance(manifest["expected"], Mapping) and _canonical(dict(manifest["expected"])) == _canonical(expected_meta), "Paired identities, versions, hashes or checkpoint boundary mismatch")
    at = _int(manifest["verified_at"], "verified_at")
    _require(now - max_age <= at <= now, "Pair verification is stale or future-dated")
    refs = {}
    paths = []
    receipt_keys = {"archive_sha256", "downloaded_archive", "library_file_id", "library_version", "previous_version", "transport_reference", "verified_at"}
    for kind in ("ledger", "queue"):
        receipt = manifest[f"{kind}_receipt"]
        _require(isinstance(receipt, Mapping) and set(receipt) == receipt_keys, f"Invalid {kind} receipt fields")
        for key in ("archive_sha256", "library_file_id", "library_version", "previous_version", "downloaded_archive"):
            _require(receipt[key] == getattr(expected, f"{kind}_{key}"), f"{kind} receipt {key} mismatch")
        stamp = _int(receipt["verified_at"], f"{kind} receipt time")
        _require(now - max_age <= stamp <= at, f"{kind} receipt stale or after pair verification")
        refs[kind] = _text(receipt["transport_reference"], f"{kind} transport reference")
        _require(_file_hash(receipt["downloaded_archive"]) == receipt["archive_sha256"], f"{kind} downloaded bytes mismatch")
        paths.append(Path(receipt["downloaded_archive"]).resolve())
    _require(paths[0] != paths[1] and not paths[0].samefile(paths[1]), "Ledger and queue downloads must be distinct artifacts")
    digest = sha256(_canonical(dict(manifest))).hexdigest()
    return VerifiedPair(expected, digest, at, refs["ledger"], refs["queue"])
