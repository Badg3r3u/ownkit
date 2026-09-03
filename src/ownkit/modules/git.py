from __future__ import annotations

from pathlib import Path
import subprocess

from ownkit.finding import Finding
from ownkit.modules.secrets import PATTERNS


def scan(root: Path, max_commits: int = 50) -> tuple[list[Finding], list[str]]:
    git_dir = root / ".git"
    if not git_dir.exists():
        return [], ["not a git repository; skipped git history scan"]
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", f"-n{max_commits}", "-p", "--pretty=format:"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], ["git history scan skipped (git unavailable or timed out)"]
    if proc.returncode != 0:
        return [], [f"git history scan skipped: {proc.stderr.strip() or 'git log failed'}"]

    findings: list[Finding] = []
    seen: set[str] = set()
    blob = proc.stdout
    for rule_id, pattern, severity, remediation in PATTERNS:
        match = pattern.search(blob)
        if not match or rule_id in seen:
            continue
        seen.add(rule_id)
        evidence = match.group(0)
        if len(evidence) > 12:
            evidence = evidence[:8] + "…"
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
