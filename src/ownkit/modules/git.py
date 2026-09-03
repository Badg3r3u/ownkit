from __future__ import annotations

from pathlib import Path
import re
import subprocess

from ownkit.finding import Finding, Severity, redact_secret
from ownkit.modules.secrets import PATTERNS

URL_CREDS = re.compile(r"(?i)https?://[^/\s:@]+:([^/\s:@]+)@")


def _git(root: Path, *args: str, timeout: int = 20) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _scan_remote_urls(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    proc = _git(root, "config", "--get-regexp", r"^remote\..*\.url$")
    if proc is None or proc.returncode != 0:
        return findings
    for lineno, line in enumerate(proc.stdout.splitlines(), 1):
        match = URL_CREDS.search(line)
        if not match:
            continue
        secret = match.group(1)
        findings.append(
            Finding(
                id="git.remote_url_credentials",
                module="git",
                severity=Severity.critical,
                path=".git/config",
                title="Git remote URL embeds a password or token",
                evidence=redact_secret(secret),
                remediation="Rotate the token, rewrite the remote to use SSH or a credential helper, and never store passwords in remote URLs.",
                line=lineno,
            )
        )
    return findings


def scan(root: Path, max_commits: int = 50) -> tuple[list[Finding], list[str]]:
    git_dir = root / ".git"
    if not git_dir.exists():
        # Allow scanning a worktree subdirectory.
        probed = _git(root, "rev-parse", "--is-inside-work-tree")
        if probed is None or probed.returncode != 0 or probed.stdout.strip() != "true":
            return [], ["not a git repository; skipped git history scan"]

    findings = _scan_remote_urls(root)

    proc = _git(root, "log", f"-n{max_commits}", "-p", "--pretty=format:")
    if proc is None:
        return findings, ["git history scan skipped (git unavailable or timed out)"]
    if proc.returncode != 0:
        note = proc.stderr.strip() or "git log failed"
        return findings, [f"git history scan skipped: {note}"]

    seen: set[str] = set()
    blob = proc.stdout
    for rule_id, pattern, severity, remediation in PATTERNS:
        match = pattern.search(blob)
        if not match or rule_id in seen:
            continue
        seen.add(rule_id)
        evidence = match.group(0)
        if len(evidence) > 12:
            evidence = evidence[:8] + "..."
        findings.append(
            Finding(
                id=f"git.{rule_id.split('.', 1)[-1]}",
                module="git",
                severity=severity,
                path=".git",
                title="Possible secret in recent git history",
                evidence=evidence,
                remediation=remediation + " Also rewrite or filter the affected commits if the secret was pushed.",
            )
        )
    return findings, []
