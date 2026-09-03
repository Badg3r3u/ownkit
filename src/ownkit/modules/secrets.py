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
    if root.is_file():
        return [root]
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(path)
    return files


def scan(root: Path) -> list[Finding]:
    from ownkit.finding import redact_evidence

    root = Path(root)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    display_root = root if root.is_dir() else root.parent
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:8192]:
            continue
        try:
            rel = path.relative_to(display_root).as_posix()
        except ValueError:
            rel = path.as_posix()
        body = data.decode("utf-8", errors="ignore")
        for lineno, line in enumerate(body.splitlines(), 1):
            for rule_id, pattern, severity, remediation in PATTERNS:
                for match in pattern.finditer(line):
                    key = (rule_id, rel, lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            id=rule_id,
                            module="secrets",
                            severity=severity,
                            path=rel,
                            title="Possible secret in source tree",
                            evidence=redact_evidence(line, match.group(0)),
                            remediation=remediation,
                            line=lineno,
                        )
                    )
    return findings
