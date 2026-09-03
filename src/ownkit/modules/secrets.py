from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", "dist", "build"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".whl", ".so", ".pyc"}
MAX_BYTES = 1_000_000

# Patterns are detection-only. Tests use clearly fake fixture values.
PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "secrets.aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.critical,
        "Rotate the key in IAM, remove it from the repo, and load secrets from a secret manager or env vars that are not committed.",
    ),
    (
        "secrets.github_pat",
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        Severity.critical,
        "Revoke the token in GitHub settings, remove it from git history if committed, and use a secret store.",
    ),
    (
        "secrets.private_key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
        Severity.critical,
        "Remove the private key from the tree, rotate the key pair, and keep keys in a secrets store with 0600 perms.",
    ),
    (
        "secrets.generic_assignment",
        re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        Severity.high,
        "Replace hardcoded credentials with environment variables or a secret manager and scrub the committed copy.",
    ),
]


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(path)
    return files


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        for rule_id, pattern, severity, remediation in PATTERNS:
            for match in pattern.finditer(text):
                key = (rule_id, rel)
                if key in seen:
                    continue
                seen.add(key)
                evidence = match.group(0)
                if len(evidence) > 12:
                    evidence = evidence[:8] + "…"
                findings.append(
                    Finding(
                        id=rule_id,
                        module="secrets",
                        severity=severity,
                        path=rel,
                        title="Possible secret in source tree",
                        evidence=evidence,
                        remediation=remediation,
                    )
                )
    return findings
