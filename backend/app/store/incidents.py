"""Incident and incident-memory storage.

`InMemoryIncidentStore` backs the live workflow. `IncidentMemoryStore` keeps the
compact record of resolved incidents used for retrieval on future incidents
(spec section 16) - it informs ranking and is shown to the engineer as history;
it is never applied as an automatic fix.

Both are simple by design. Swap in Azure Table/Cosmos behind the same two
interfaces when the MVP needs durability across replicas.
"""

from __future__ import annotations

import asyncio
import json
from abc import ABC, abstractmethod
from pathlib import Path

from ..logging_config import get_logger
from ..models import Incident, ResolvedIncidentMemory, Scenario

logger = get_logger(__name__)


class IIncidentStore(ABC):
    @abstractmethod
    async def save(self, incident: Incident) -> None: ...

    @abstractmethod
    async def get(self, incident_id: str) -> Incident | None: ...

    @abstractmethod
    async def list(self, limit: int = 50) -> list[Incident]: ...


class InMemoryIncidentStore(IIncidentStore):
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._lock = asyncio.Lock()

    async def save(self, incident: Incident) -> None:
        async with self._lock:
            self._incidents[incident.id] = incident

    async def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    async def list(self, limit: int = 50) -> list[Incident]:
        ordered = sorted(self._incidents.values(), key=lambda i: i.created_at, reverse=True)
        return ordered[:limit]


class IncidentMemoryStore:
    """Durable, compact history of resolved incidents."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._records: list[ResolvedIncidentMemory] = []
        self._lock = asyncio.Lock()
        if path and path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                self._records.append(ResolvedIncidentMemory.model_validate_json(line))
            except Exception:  # noqa: BLE001 - a corrupt line must not stop startup
                logger.warning("incident_memory_line_skipped")

    async def remember(self, record: ResolvedIncidentMemory) -> None:
        async with self._lock:
            self._records.append(record)
            if self._path:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                await asyncio.to_thread(
                    self._append, record.model_dump_json()
                )
        logger.info(
            "incident_remembered",
            incident_id=record.incident_id,
            scenario=record.scenario.value,
            root_cause=record.root_cause_id,
        )

    def _append(self, line: str) -> None:
        assert self._path is not None
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def similar(
        self, *, scenario: Scenario, signals: list[str], limit: int = 3
    ) -> list[ResolvedIncidentMemory]:
        """Rank history by scenario match plus overlapping signals.

        Deliberately simple lexical matching: the result is presented as prior
        art for the engineer and as a ranking hint, never as an answer.
        """
        signal_set = {s.lower() for s in signals}
        scored: list[tuple[float, ResolvedIncidentMemory]] = []
        for record in self._records:
            score = 1.0 if record.scenario is scenario else 0.0
            overlap = sum(
                1 for key in record.key_signals if key.lower() in signal_set
            )
            score += overlap * 0.5
            if score > 0:
                scored.append((score, record))
        scored.sort(key=lambda pair: (pair[0], pair[1].resolved_at), reverse=True)
        return [record for _, record in scored[:limit]]

    def all(self) -> list[ResolvedIncidentMemory]:
        return list(self._records)

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self._records:
            key = record.root_cause_id or "unknown"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))

    def export(self) -> str:
        return json.dumps([json.loads(r.model_dump_json()) for r in self._records], indent=2)
