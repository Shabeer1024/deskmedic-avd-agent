"""Knowledge retrieval (spec section 15).

Documents live in /knowledge as Markdown with YAML-ish front matter declaring a
`source`. Retrieved text is ALWAYS treated as untrusted: it is scanned for
injection, fenced before it reaches the model, and labelled with its provenance
so the engineer can tell Microsoft documentation from internal SOP from AI
inference.

Retrieval is lexical (tag + term overlap). That is a deliberate MVP choice: it
is inspectable, has no embedding infrastructure, and returns citable documents.
Swapping in Azure AI Search behind `IKnowledgeRetriever` changes nothing above.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..logging_config import get_logger
from ..models import EvidenceSource
from ..security.injection import DIRECTIVE_KINDS, scan_for_injection

logger = get_logger(__name__)

KNOWLEDGE_ROOT = Path(__file__).resolve().parents[3] / "knowledge"
_WORD = re.compile(r"[a-z0-9][a-z0-9._-]{2,}")
_STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "that", "this", "from", "when", "not", "are", "was",
        "has", "have", "its", "into", "than", "then", "but", "can", "cannot", "does",
        "avd", "azure", "user", "users", "host", "issue", "problem",
    }
)


@dataclass(frozen=True)
class KnowledgeDoc:
    doc_id: str
    title: str
    source: EvidenceSource
    reference: str
    tags: frozenset[str]
    body: str
    terms: frozenset[str]


@dataclass(frozen=True)
class KnowledgeHit:
    doc: KnowledgeDoc
    score: float
    excerpt: str
    injection_flagged: bool

    def citation(self) -> str:
        return f"{self.doc.title} [{self.doc.source.value}] ({self.doc.reference})"


class IKnowledgeRetriever(ABC):
    @abstractmethod
    def search(self, query: str, *, tags: list[str] | None = None, limit: int = 3) -> list[KnowledgeHit]: ...


def _tokenise(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS}


def _parse_front_matter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---"):
        return {}, raw
    end = raw.find("\n---", 3)
    if end == -1:
        return {}, raw
    header, body = raw[3:end], raw[end + 4 :]
    meta: dict[str, str] = {}
    for line in header.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        meta[key.strip().lower()] = value.strip()
    return meta, body.strip()


_SOURCE_MAP = {
    "microsoft_doc": EvidenceSource.MICROSOFT_DOC,
    "internal_sop": EvidenceSource.INTERNAL_SOP,
    "incident_history": EvidenceSource.INCIDENT_HISTORY,
}


class FileKnowledgeRetriever(IKnowledgeRetriever):
    def __init__(self, root: Path | None = None) -> None:
        self._root = root or KNOWLEDGE_ROOT
        self._docs: list[KnowledgeDoc] = []
        self.reload()

    def reload(self) -> None:
        self._docs = []
        if not self._root.exists():
            logger.warning("knowledge_root_missing", path=str(self._root))
            return
        for path in sorted(self._root.rglob("*.md")):
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError:
                continue
            meta, body = _parse_front_matter(raw)
            tags = frozenset(
                t.strip().lower()
                for t in meta.get("tags", "").strip("[]").split(",")
                if t.strip()
            )
            self._docs.append(
                KnowledgeDoc(
                    doc_id=str(path.relative_to(self._root)),
                    title=meta.get("title", path.stem.replace("-", " ").title()),
                    source=_SOURCE_MAP.get(meta.get("source", ""), EvidenceSource.MICROSOFT_DOC),
                    reference=meta.get("reference", str(path.relative_to(self._root))),
                    tags=tags,
                    body=body,
                    terms=frozenset(_tokenise(f"{meta.get('title', '')} {body}") | tags),
                )
            )
        logger.info("knowledge_loaded", documents=len(self._docs), root=str(self._root))

    def search(
        self, query: str, *, tags: list[str] | None = None, limit: int = 3
    ) -> list[KnowledgeHit]:
        query_terms = _tokenise(query)
        wanted_tags = {t.lower() for t in (tags or [])}
        hits: list[KnowledgeHit] = []

        for doc in self._docs:
            overlap = query_terms & doc.terms
            tag_bonus = len(wanted_tags & doc.tags) * 2.0
            if not overlap and not tag_bonus:
                continue
            score = len(overlap) / (len(query_terms) or 1) + tag_bonus
            findings = scan_for_injection(
                doc.body, origin=f"knowledge:{doc.doc_id}", kinds=DIRECTIVE_KINDS
            )
            if findings:
                logger.warning(
                    "knowledge_injection_flagged",
                    document=doc.doc_id,
                    kinds=[f.kind for f in findings],
                )
            hits.append(
                KnowledgeHit(
                    doc=doc,
                    score=round(score, 3),
                    excerpt=self._excerpt(doc.body, overlap),
                    injection_flagged=bool(findings),
                )
            )

        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:limit]

    @staticmethod
    def _excerpt(body: str, terms: set[str], width: int = 320) -> str:
        lowered = body.lower()
        for term in sorted(terms, key=len, reverse=True):
            index = lowered.find(term)
            if index != -1:
                start = max(index - width // 3, 0)
                return body[start : start + width].strip().replace("\n", " ")
        return body[:width].strip().replace("\n", " ")


_TAG_HINTS: dict[str, list[str]] = {
    "avd_agent_unhealthy": ["agent", "rdagentbootloader", "unavailable"],
    "session_host_unavailable": ["session host", "unavailable", "heartbeat"],
    "fslogix_temp_profile": ["fslogix", "temp profile", "vhdx"],
    "storage_connectivity": ["azure files", "smb", "private endpoint"],
    "user_cannot_connect": ["connection failed", "host pool", "drain mode"],
    "black_screen": ["black screen", "appreadiness", "explorer", "group policy"],
    "stuck_session": ["disconnected session", "logoff", "orphaned session"],
    "host_not_registering": ["registration token", "invalid_registration_token", "re-register"],
    "pending_reboot": ["pending reboot", "windows update", "restart"],
    "time_sync": ["time sync", "clock skew", "kerberos", "w32time"],
    "slow_logon": ["slow logon", "loadprofile", "group policy", "profile size"],
    "session_disconnects": ["disconnect", "heartbeat", "shortpath", "idle"],
    "scaling_plan": ["scaling plan", "power on off contributor", "autoscale"],
    "profile_disk_full": ["profile disk full", "sizeinmbs", "compaction"],
    "domain_trust": ["secure channel", "trust relationship", "domain controller"],
    "remoteapp": ["remoteapp", "file path", "application group"],
    "app_attach": ["app attach", "msix"],
    "teams_optimization": ["teams", "webrtc", "iswvdenvironment"],
    "device_redirection": ["redirection", "rdp properties", "clipboard", "printer"],
    "performance": ["cpu", "memory", "host density", "drain"],
    "network_endpoints": ["required url", "proxy", "private dns zone"],
    "sso_authentication": ["sso", "conditional access", "mfa", "entra"],
    "client_side": ["windows app", "reset", "feed", "subscribe"],
    "thin_client": ["thin client", "thinos", "firmware"],
}


def tags_for_scenario(scenario: str) -> list[str]:
    return _TAG_HINTS.get(scenario, [])
