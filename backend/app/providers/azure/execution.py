"""AzureAutomationExecutionProvider - the controlled execution layer.

Design rules (spec sections 6, 7, 17):

* Only runbooks **already published** to the Automation account may be started.
  The provider passes a runbook *name*, never script text, so a model-generated
  script can never reach a production host without a human first publishing it
  through the normal change process.
* Parameters have already passed `security.validators` and the policy engine.
* The job runs under the Automation account's own Managed Identity, which holds
  the remediation RBAC. The agent's identity does not hold that RBAC, so the
  agent cannot bypass this provider to make a change.
* The job is polled with a hard timeout, and its full output is captured for
  the audit record.

RBAC required (remediation identity, separate from the diagnostics identity):
  * Automation Job Operator     on the Automation account (to start jobs)
  * The Automation account's Managed Identity holds:
      - Virtual Machine Contributor  scoped to the session-host resource group
      - Desktop Virtualization Contributor scoped to the host pools
    ...and nothing else.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from ... import progress
from ...config import Settings
from ...logging_config import get_logger
from ..interfaces import IExecutionProvider
from . import enum_text

logger = get_logger(__name__)

_TERMINAL_STATES = {"Completed", "Failed", "Stopped", "Suspended"}
_POLL_INTERVAL_S = 3


class AutomationNotConfigured(RuntimeError):
    pass


class AzureAutomationExecutionProvider(IExecutionProvider):
    name = "azure_automation"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Any = None
        self._credential: Any = None
        if not (settings.automation_account_name and settings.automation_resource_group):
            raise AutomationNotConfigured(
                "AUTOMATION_ACCOUNT_NAME and AUTOMATION_RESOURCE_GROUP must be set"
            )

    @property
    def client(self) -> Any:
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.automation import AutomationClient

            self._credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=True
            )
            self._client = AutomationClient(
                self._credential, self._settings.azure_subscription_id
            )
        return self._client

    async def execute_runbook(
        self,
        runbook_name: str,
        parameters: dict[str, Any],
        *,
        target: dict[str, Any],
        correlation_id: str,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        rg = self._settings.automation_resource_group
        account = self._settings.automation_account_name
        job_name = f"avd-agent-{correlation_id}"
        started = datetime.now(UTC)
        output: list[str] = []

        # Refuse to start anything that is not published to the account. This is
        # the guarantee that only reviewed scripts run in production.
        published = await asyncio.to_thread(self._published_runbooks, rg, account)
        if runbook_name not in published:
            message = (
                f"runbook '{runbook_name}' is not published to Automation account "
                f"'{account}'. Publish it through change control before it can run."
            )
            logger.error("runbook_not_published", runbook=runbook_name, account=account)
            return self._result(job_name, 127, [f"ERROR: {message}"], started, message)

        # Automation runbook parameters must be strings.
        job_parameters = {k: str(v) for k, v in parameters.items()}
        if self._settings.automation_hybrid_worker_group:
            job_parameters.setdefault("_hybridWorkerGroup", "")

        def _start() -> Any:
            return self.client.job.create(
                resource_group_name=rg,
                automation_account_name=account,
                job_name=job_name,
                parameters={
                    "properties": {
                        "runbook": {"name": runbook_name},
                        "parameters": job_parameters,
                        "run_on": self._settings.automation_hybrid_worker_group or None,
                    }
                },
            )

        try:
            await asyncio.to_thread(_start)
        except Exception as exc:  # noqa: BLE001
            logger.exception("automation_job_start_failed", runbook=runbook_name)
            return self._result(job_name, 1, [f"ERROR: {exc}"], started, str(exc))

        logger.info(
            "automation_job_started",
            runbook=runbook_name,
            job=job_name,
            target=target.get("resource_name"),
        )
        output.append(f"Automation job '{job_name}' started for runbook '{runbook_name}'.")

        status = await self._poll(rg, account, job_name, timeout_seconds, output)
        job_output = await asyncio.to_thread(self._job_output, rg, account, job_name)
        output.extend(line for line in job_output.splitlines() if line.strip())

        succeeded = status == "Completed"
        exit_code = 0 if succeeded else (124 if status == "Timeout" else 1)
        error = None if succeeded else f"Automation job ended in state '{status}'"
        return self._result(job_name, exit_code, output, started, error)

    # ---- helpers -----------------------------------------------------------
    def _published_runbooks(self, rg: str, account: str) -> set[str]:
        return {
            rb.name
            for rb in self.client.runbook.list_by_automation_account(rg, account)
            if enum_text(getattr(rb, "state", None)).lower() == "published"
        }

    async def _poll(
        self, rg: str, account: str, job_name: str, timeout_seconds: int, output: list[str]
    ) -> str:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        last = ""
        while asyncio.get_running_loop().time() < deadline:
            job = await asyncio.to_thread(self.client.job.get, rg, account, job_name)
            status = enum_text(job.status)
            if status != last:
                output.append(f"Job status: {status}")
                progress.emit("job", f"Automation job {status}",
                              "healthy" if status == "Completed" else
                              "unhealthy" if status in ("Failed", "Stopped", "Suspended") else "running")
                last = status
            if status in _TERMINAL_STATES:
                return status
            await asyncio.sleep(_POLL_INTERVAL_S)
        output.append(f"ERROR: job did not reach a terminal state within {timeout_seconds}s")
        return "Timeout"

    def _job_output(self, rg: str, account: str, job_name: str) -> str:
        try:
            return self.client.job.get_output(rg, account, job_name) or ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("automation_job_output_unavailable", job=job_name, error=str(exc))
            return ""

    @staticmethod
    def _result(
        job_id: str, exit_code: int, output: list[str], started: datetime, error: str | None
    ) -> dict[str, Any]:
        completed = datetime.now(UTC)
        return {
            "job_id": job_id,
            "exit_code": exit_code,
            "succeeded": exit_code == 0,
            "output": output,
            "error": error,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "provider": "azure_automation",
            "duration_ms": int((completed - started).total_seconds() * 1000),
        }
