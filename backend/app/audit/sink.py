"""Audit trail.

Every tool call, policy decision, approval, execution and verification writes an
`AuditRecord`. Records are hash-chained: each entry carries the SHA-256 of the
previous entry, so a deleted or edited line is detectable. Correlation ids tie a
whole incident together across the log.

`FileAuditSink` is the local/default implementation. In Azure, point
`AUDIT_SINK` at an append-only Blob container with an immutability policy, or
forward the same JSON to Log Analytics - the record shape does not change.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from abc import ABC, abstractmethod
from pathlib import Path

from ..logging_config import get_logger, redact
from ..models import AuditRecord

logger = get_logger(__name__)

GENESIS_HASH = "0" * 64


class IAuditSink(ABC):
    @abstractmethod
    async def write(self, record: AuditRecord) -> None: ...

    @abstractmethod
    async def read(
        self, *, incident_id: str | None = None, limit: int = 200
    ) -> list[dict[str, object]]: ...


def _entry(record: AuditRecord, previous_hash: str) -> dict[str, object]:
    payload = json.loads(record.model_dump_json())
    payload["detail"] = redact(payload.get("detail", {}))
    payload["previous_hash"] = previous_hash
    payload["hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    return payload


class InMemoryAuditSink(IAuditSink):
    """Used by tests and by any deployment that ships audit elsewhere."""

    def __init__(self) -> None:
        self._entries: list[dict[str, object]] = []
        self._lock = asyncio.Lock()

    async def write(self, record: AuditRecord) -> None:
        async with self._lock:
            previous = str(self._entries[-1]["hash"]) if self._entries else GENESIS_HASH
            self._entries.append(_entry(record, previous))

    async def read(
        self, *, incident_id: str | None = None, limit: int = 200
    ) -> list[dict[str, object]]:
        entries = [
            e
            for e in self._entries
            if incident_id is None or e.get("incident_id") == incident_id
        ]
        return entries[-limit:]

    def verify_chain(self) -> bool:
        previous = GENESIS_HASH
        for entry in self._entries:
            if entry["previous_hash"] != previous:
                return False
            previous = str(entry["hash"])
        return True


class FileAuditSink(IAuditSink):
    """Append-only JSON Lines on disk."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self._path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return last

    async def write(self, record: AuditRecord) -> None:
        async with self._lock:
            entry = _entry(record, self._last_hash)
            await asyncio.to_thread(self._append, entry)
            self._last_hash = str(entry["hash"])
        logger.info(
            "audit_written",
            event_type=record.event_type.value,
            incident_id=record.incident_id,
            actor=record.actor,
            outcome=record.outcome,
        )

    def _append(self, entry: dict[str, object]) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")

    async def read(
        self, *, incident_id: str | None = None, limit: int = 200
    ) -> list[dict[str, object]]:
        if not self._path.exists():
            return []

        def _load() -> list[dict[str, object]]:
            entries: list[dict[str, object]] = []
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if incident_id is None or entry.get("incident_id") == incident_id:
                        entries.append(entry)
            return entries[-limit:]

        return await asyncio.to_thread(_load)


def build_audit_sink(sink: str, path: Path) -> IAuditSink:
    if sink == "memory":
        return InMemoryAuditSink()
    return FileAuditSink(path)
