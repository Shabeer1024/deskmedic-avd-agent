"""Run Command batching in the Azure provider.

A VM runs one Run Command at a time and each takes ~20-40s, so concurrent
in-guest reads for one VM are merged into a single call. These tests fake the
Azure call and count round trips."""

from __future__ import annotations

import asyncio
import json

from app.config import Settings
from app.providers.azure.diagnostics import AzureDiagnosticProvider


def _provider() -> tuple[AzureDiagnosticProvider, list[str]]:
    provider = AzureDiagnosticProvider(Settings(azure_subscription_id="00000000-0000-0000-0000-000000000001"))
    calls: list[str] = []

    async def fake_run_raw(rg: str, vm: str, script: str) -> str:
        calls.append(script)
        await asyncio.sleep(0.01)
        if script.startswith("$__results"):
            # Pretend each merged block printed its own JSON.
            blocks = [line for line in script.splitlines() if line.startswith("try { $__results['k")]
            return json.dumps({f"k{i}": json.dumps({"block": i}) for i in range(len(blocks))})
        return json.dumps({"single": True})

    provider._run_raw = fake_run_raw  # type: ignore[method-assign]
    return provider, calls


async def test_concurrent_reads_for_one_vm_become_one_run_command() -> None:
    provider, calls = _provider()
    scripts = [f"Write-Output 'check {n}' | ConvertTo-Json" for n in range(4)]
    results = await asyncio.gather(*(provider._run_command("vm1", "rg1", sc) for sc in scripts))
    assert len(calls) == 1
    assert sorted(r["block"] for r in results) == [0, 1, 2, 3]


async def test_identical_scripts_run_once() -> None:
    provider, calls = _provider()
    results = await asyncio.gather(*(provider._run_command("vm1", "rg1", "same") for _ in range(3)))
    assert len(calls) == 1
    assert all(r == {"single": True} for r in results)


async def test_different_vms_are_not_merged() -> None:
    provider, calls = _provider()
    await asyncio.gather(provider._run_command("vm1", "rg1", "a"), provider._run_command("vm2", "rg1", "b"))
    assert len(calls) == 2


async def test_event_log_reads_run_alone() -> None:
    provider, calls = _provider()
    events = "$e = Get-WinEvent -LogName 'System' -MaxEvents 25"
    await asyncio.gather(
        provider._run_command("vm1", "rg1", "check-a"),
        provider._run_command("vm1", "rg1", "check-b"),
        provider._run_command("vm1", "rg1", events),
    )
    assert events in calls  # dispatched on its own
    assert len(calls) == 2  # one merged call + the event read


async def test_merge_failure_falls_back_to_individual_calls() -> None:
    provider, calls = _provider()
    original = provider._run_raw

    async def broken_merge(rg: str, vm: str, script: str) -> str:
        if script.startswith("$__results"):
            calls.append(script)
            return "x" * 4096  # truncated, not JSON
        return await original(rg, vm, script)

    provider._run_raw = broken_merge  # type: ignore[method-assign]
    results = await asyncio.gather(provider._run_command("vm1", "rg1", "a"), provider._run_command("vm1", "rg1", "b"))
    assert results == [{"single": True}, {"single": True}]
    assert len(calls) == 3  # failed merge, then one call each


async def test_merged_script_is_powershell_51_safe() -> None:
    provider, calls = _provider()
    await asyncio.gather(provider._run_command("vm1", "rg1", "if ($x) { 'a'; exit 0 }"),
                         provider._run_command("vm1", "rg1", "'b'"))
    merged = calls[0]
    assert "= try" not in merged          # try is a statement in Windows PowerShell 5.1
    assert "exit 0" not in merged         # would end the whole merged script
    assert "return" in merged


async def test_busy_vm_conflict_is_retried(monkeypatch) -> None:  # noqa: ANN001
    import app.providers.azure.diagnostics as diag

    monkeypatch.setattr(diag, "RUN_COMMAND_CONFLICT_BACKOFF_SECONDS", 0)
    provider = AzureDiagnosticProvider(Settings(azure_subscription_id="00000000-0000-0000-0000-000000000001"))
    attempts = []

    async def flaky(rg: str, vm: str, script: str) -> str:
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("(Conflict) Run command extension execution is in progress.")
        return '{"ok": true}'

    provider._run_raw_once = flaky  # type: ignore[method-assign]
    assert await provider._run_command("vm1", "rg1", "x") == {"ok": True}
    assert len(attempts) == 3


async def test_other_errors_are_not_retried(monkeypatch) -> None:  # noqa: ANN001
    import pytest

    provider = AzureDiagnosticProvider(Settings(azure_subscription_id="00000000-0000-0000-0000-000000000001"))

    async def denied(rg: str, vm: str, script: str) -> str:
        raise RuntimeError("AuthorizationFailed")

    provider._run_raw_once = denied  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="AuthorizationFailed"):
        await provider._run_command("vm1", "rg1", "x")


def test_enum_text_handles_sdk_enums() -> None:
    from app.providers.azure import enum_text
    from azure.mgmt.automation.models import JobStatus, RunbookState

    assert str(RunbookState.PUBLISHED) != "Published"  # the trap
    assert enum_text(RunbookState.PUBLISHED) == "Published"
    assert enum_text(JobStatus.COMPLETED) == "Completed"
    assert enum_text("Available") == "Available"
    assert enum_text(None) == ""
