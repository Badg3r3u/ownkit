from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity

PR_TARGET = re.compile(r"(?im)^\s*pull_request_target\s*:")
ECHO_SECRET = re.compile(r"(?i)(echo|print|printf).{0,40}secrets\.")
CURL_SECRET = re.compile(r"(?i)curl.{0,80}secrets\.")


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = list((root / ".github" / "workflows").glob("*.yml"))
    workflows += list((root / ".github" / "workflows").glob("*.yaml"))
    for path in workflows:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = _rel(path, root)
        if PR_TARGET.search(text):
            findings.append(
                Finding(
                    id="ci.pull_request_target",
                    module="ci",
                    severity=Severity.high,
                    path=rel,
                    title="Workflow uses pull_request_target",
                    evidence="pull_request_target:",
                    remediation="Prefer `pull_request` for untrusted forks. If you need `pull_request_target`, do not check out PR code with secrets in the same job.",
                )
            )
        if ECHO_SECRET.search(text) or CURL_SECRET.search(text):
            findings.append(
                Finding(
                    id="ci.secret_in_logs",
                    module="ci",
                    severity=Severity.high,
                    path=rel,
                    title="Workflow may print or send a GitHub secret",
                    evidence="secrets. referenced in echo/curl",
                    remediation="Never echo secrets. Pass them as env vars to a trusted action and rely on GitHub's masking, not log output.",
                )
            )
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
