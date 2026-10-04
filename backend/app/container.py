"""Composition root.

One place decides which implementation of every interface is used, driven only
by configuration. `mock` wires the simulated estate; `azure` wires the real
providers. Nothing else in the codebase branches on the run mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agent import (
    AgentOrchestrator,
    ChatService,
    DiagnosisEngine,
    ILlmClient,
    PolicyEngine,
    RemediationPlanner,
    TriageService,
    build_llm_client,
)
from .approval import ApprovalService
from .audit import IAuditSink, build_audit_sink
from .config import RunMode, Settings, get_settings
from .knowledge import FileKnowledgeRetriever, IKnowledgeRetriever
from .logging_config import get_logger
from .providers.interfaces import IDiagnosticProvider, IExecutionProvider
from .store import IncidentMemoryStore, InMemoryIncidentStore
from .tools.base import ToolRegistry
from .tools.diagnostics import build_diagnostic_tools
from .tools.remediation import build_remediation_tools
from .verification import VerificationService

logger = get_logger(__name__)


@dataclass
class Container:
    settings: Settings
    audit: IAuditSink
    registry: ToolRegistry
    diagnostics: IDiagnosticProvider
    executor: IExecutionProvider
    llm: ILlmClient
    approvals: ApprovalService
    verification: VerificationService
    store: InMemoryIncidentStore
    memory: IncidentMemoryStore
    knowledge: IKnowledgeRetriever
    orchestrator: AgentOrchestrator
    chat: ChatService

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "config": self.settings.redacted(),
            "diagnostics_provider": self.diagnostics.name,
            "execution_provider": self.executor.name,
            "llm_client": self.llm.name,
            "tools": len(self.registry.names()),
        }


def _build_providers(settings: Settings) -> tuple[IDiagnosticProvider, IExecutionProvider]:
    if settings.avd_agent_mode is RunMode.AZURE:
        from .providers.azure.diagnostics import AzureDiagnosticProvider
        from .providers.azure.execution import AzureAutomationExecutionProvider

        logger.info("providers_selected", mode="azure")
        return AzureDiagnosticProvider(settings), AzureAutomationExecutionProvider(settings)

    from .providers.mock.diagnostics import MockDiagnosticProvider
    from .providers.mock.estate import get_estate
    from .providers.mock.execution import MockExecutionProvider

    estate = get_estate()
    logger.info("providers_selected", mode="mock", session_hosts=len(estate.session_hosts))
    return MockDiagnosticProvider(estate), MockExecutionProvider(estate)


def build_container(settings: Settings | None = None) -> Container:
    settings = settings or get_settings()

    audit = build_audit_sink(settings.audit_sink, settings.audit_file_path)
    diagnostics, executor = _build_providers(settings)

    registry = ToolRegistry(audit_sink=audit)
    registry.register_all(build_diagnostic_tools(diagnostics))
    # Writes go through the same gate as reads: permission -> validation ->
    # execute -> audit. They additionally require an approval token, enforced
    # by the orchestrator before it ever reaches the registry.
    registry.register_all(build_remediation_tools(executor))

    llm = build_llm_client(settings)
    approvals = ApprovalService(settings, audit)
    verification = VerificationService(registry, audit)
    store = InMemoryIncidentStore()
    memory = IncidentMemoryStore(settings.data_dir / "incident_memory.jsonl")
    knowledge = FileKnowledgeRetriever()

    orchestrator = AgentOrchestrator(
        settings=settings,
        registry=registry,
        triage=TriageService(llm),
        diagnosis=DiagnosisEngine(llm),
        planner=RemediationPlanner(),
        policy=PolicyEngine(settings),
        approvals=approvals,
        verification=verification,
        executor=executor,
        store=store,
        memory=memory,
        knowledge=knowledge,
        audit=audit,
    )

    chat = ChatService(llm, registry, estate_source=diagnostics)

    return Container(
        settings=settings,
        audit=audit,
        registry=registry,
        diagnostics=diagnostics,
        executor=executor,
        llm=llm,
        approvals=approvals,
        verification=verification,
        store=store,
        memory=memory,
        knowledge=knowledge,
        orchestrator=orchestrator,
        chat=chat,
    )
