"""Static safety validation for any PowerShell the agent will show or run.

Applied to *both* approved runbooks (as a regression guard) and to model-
generated scripts (as an admission gate). A script with any BLOCKING finding
can never be executed, regardless of who approves it.

This is a defence in depth, not the primary control. The primary control is
that production execution only ever starts a runbook already published to the
Automation account (`AzureAutomationExecutionProvider`).
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    BLOCKING = "blocking"
    WARNING = "warning"


class Finding(BaseModel):
    rule: str
    severity: Severity
    message: str
    line: int | None = None
    excerpt: str = ""


class ValidationReport(BaseModel):
    passed: bool
    findings: list[Finding] = Field(default_factory=list)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.BLOCKING]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    def messages(self) -> list[str]:
        return [f"[{f.severity.value}] {f.rule}: {f.message}" for f in self.findings]


# (rule, pattern, severity, message)
_RULES: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
    # --- arbitrary code execution -----------------------------------------
    ("dynamic_execution", re.compile(r"\b(Invoke-Expression|iex)\b", re.I), Severity.BLOCKING,
     "Invoke-Expression executes arbitrary strings as code."),
    ("script_block_create", re.compile(r"\[scriptblock\]::Create", re.I), Severity.BLOCKING,
     "ScriptBlock::Create builds code at runtime, defeating review."),
    ("encoded_command", re.compile(r"-Enc(odedCommand)?\b|FromBase64String", re.I), Severity.BLOCKING,
     "Base64/encoded command payloads hide what will run."),
    ("remote_download", re.compile(r"(DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|curl\s|wget\s)", re.I),
     Severity.BLOCKING, "Fetching and running remote content is not permitted in a runbook."),
    ("native_shell", re.compile(r"\b(cmd\.exe|/c\s|Start-Process\s+-FilePath\s+['\"]?(cmd|powershell))", re.I),
     Severity.BLOCKING, "Spawning a native shell escapes the reviewed script surface."),

    # --- destructive ------------------------------------------------------
    ("recursive_delete", re.compile(r"Remove-Item[^\n]*-Recurse", re.I), Severity.BLOCKING,
     "Recursive deletion is never an approved AVD remediation."),
    ("profile_deletion", re.compile(r"Remove-Item[^\n]*\.vhdx?|Remove-AzStorageFile|Remove-AzStorageShare", re.I),
     Severity.BLOCKING, "Deleting profile containers or shares destroys user data."),
    # Remove-AzWvdUserSession is the one exception: it signs a user out (the
    # portal's "Log off") and deletes no resource or data.
    ("resource_deletion", re.compile(r"\bRemove-Az(?!WvdUserSession\b)[A-Za-z]+\b", re.I), Severity.BLOCKING,
     "Deleting Azure resources is out of scope for automated remediation."),
    ("disk_format", re.compile(r"\b(Format-Volume|Clear-Disk|Initialize-Disk|diskpart)\b", re.I),
     Severity.BLOCKING, "Disk operations destroy data."),
    ("shadow_copy_delete", re.compile(r"vssadmin[^\n]*delete", re.I), Severity.BLOCKING,
     "Deleting shadow copies destroys the recovery path."),
    ("account_change", re.compile(r"\b(Remove-LocalUser|Set-LocalUser|net\s+user|Remove-ADUser|Set-ADAccountPassword)\b", re.I),
     Severity.BLOCKING, "Identity changes are not remediation actions."),

    # --- privilege / policy -----------------------------------------------
    ("role_assignment", re.compile(r"\b(New|Set)-AzRoleAssignment\b|Add-AzADGroupMember", re.I),
     Severity.BLOCKING, "The agent must never grant or change permissions."),
    ("execution_policy", re.compile(r"Set-ExecutionPolicy", re.I), Severity.BLOCKING,
     "Changing the execution policy weakens the host's security posture."),
    ("defender_change", re.compile(r"Set-MpPreference|Remove-MpPreference|Uninstall-WindowsFeature", re.I),
     Severity.BLOCKING, "Disabling or reconfiguring endpoint protection is prohibited."),
    ("firewall_disable", re.compile(r"(Set-NetFirewallProfile[^\n]*-Enabled\s+False|netsh[^\n]*firewall[^\n]*off)", re.I),
     Severity.BLOCKING, "Disabling the host firewall is prohibited."),
    ("log_clearing", re.compile(r"(wevtutil\s+cl|Clear-EventLog|Remove-EventLog)", re.I), Severity.BLOCKING,
     "Clearing event logs destroys the evidence trail."),
    ("audit_tamper", re.compile(r"(auditpol\s+/clear|Set-AzDiagnosticSetting[^\n]*-Enabled\s+\$false)", re.I),
     Severity.BLOCKING, "Tampering with auditing is prohibited."),

    # --- secrets ----------------------------------------------------------
    ("plaintext_secret", re.compile(r"ConvertTo-SecureString[^\n]*-AsPlainText", re.I), Severity.BLOCKING,
     "Plaintext credentials must never appear in a script; use Managed Identity."),
    ("hardcoded_credential", re.compile(r"(?i)\b(password|pwd|secret|apikey|api_key|accountkey|clientsecret)\s*=\s*['\"][^'\"]{6,}"),
     Severity.BLOCKING, "Hard-coded credential detected."),
    ("sas_token", re.compile(r"[?&]sig=[A-Za-z0-9%+/=]{20,}"), Severity.BLOCKING,
     "Hard-coded SAS token detected."),
    ("connection_string", re.compile(r"DefaultEndpointsProtocol=.*AccountKey=", re.I), Severity.BLOCKING,
     "Hard-coded storage connection string detected."),
    ("hardcoded_subscription", re.compile(r"['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
     Severity.WARNING, "Hard-coded GUID: subscriptions and tenants must come from parameters."),

    # --- scope ------------------------------------------------------------
    ("wildcard_target", re.compile(r"Get-Az(VM|WvdSessionHost)\b(?![^\n]*-(Name|ResourceGroupName))", re.I),
     Severity.WARNING, "Enumerating resources without a name/RG filter risks acting outside the target."),
    ("shutdown_all", re.compile(r"\b(Stop-AzVM|Stop-Computer|Restart-Computer)\b(?![^\n]*-Name)", re.I),
     Severity.BLOCKING, "A power operation without an explicit target could hit the wrong host."),
)

_REQUIRED: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("missing_param_block", re.compile(r"^\s*param\s*\(", re.I | re.M),
     "Script must declare a param() block - no hard-coded targets."),
    ("missing_error_handling", re.compile(r"\btry\s*\{", re.I),
     "Script must wrap its work in try/catch."),
    ("missing_catch", re.compile(r"\bcatch\s*\{", re.I),
     "Script must handle failures in a catch block."),
    ("missing_error_preference", re.compile(r"\$ErrorActionPreference\s*=\s*'?\"?Stop", re.I),
     "Script must set $ErrorActionPreference = 'Stop'."),
)


def validate_script(
    script: str, *, require_structure: bool = True, generated: bool = False
) -> ValidationReport:
    """Static-analyse a PowerShell script.

    `generated=True` applies the stricter posture used for model-authored
    scripts: structural requirements become blocking rather than advisory.
    """
    findings: list[Finding] = []
    lines = script.splitlines()

    for rule, pattern, severity, message in _RULES:
        for index, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#"):
                continue  # comments and doc blocks are not executable
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        rule=rule,
                        severity=severity,
                        message=message,
                        line=index,
                        excerpt=line.strip()[:160],
                    )
                )
                break

    if require_structure:
        for rule, pattern, message in _REQUIRED:
            if not pattern.search(script):
                findings.append(
                    Finding(
                        rule=rule,
                        severity=Severity.BLOCKING if generated else Severity.WARNING,
                        message=message,
                    )
                )

    if generated and len(script) > 20_000:
        findings.append(
            Finding(
                rule="script_too_large",
                severity=Severity.BLOCKING,
                message="A generated remediation longer than 20k characters is not reviewable.",
            )
        )

    passed = not any(f.severity is Severity.BLOCKING for f in findings)
    return ValidationReport(passed=passed, findings=findings)
