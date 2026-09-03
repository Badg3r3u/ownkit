from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

from ownkit.finding import Finding, Severity

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
REQ_NAME = re.compile(r"^[A-Za-z0-9_.-]+")


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _is_pinned(spec: str) -> bool:
    stripped = spec.strip()
    if not stripped:
        return False
    if stripped.startswith("==") or stripped.startswith("==="):
        return True
    if re.fullmatch(r"\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?", stripped):
        return True
    return False


def _scan_requirement_line(raw: str, rel: str, lineno: int) -> Finding | None:
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    match = REQ_NAME.match(line)
    if not match:
        return None
    name = match.group(0)
    rest = line[len(name):]
    if rest.startswith("["):
        end = rest.find("]")
        rest = rest[end + 1 :] if end != -1 else rest
    rest = rest.strip()
    if _is_pinned(rest):
        return None
    severity = Severity.high if rest in {"", "*", "latest"} or rest.startswith(">") else Severity.medium
    return Finding(
        id="deps.unpinned",
        module="deps",
        severity=severity,
        path=rel,
        title=f"Unpinned dependency: {name}",
        evidence=line[:120],
        remediation="Pin a reviewed version (for example package==1.2.3) and install from a lockfile so builds stay reproducible.",
        line=lineno,
    )


def _scan_requirements(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings
    rel = _rel(path, root)
    for lineno, raw in enumerate(lines, 1):
        item = _scan_requirement_line(raw, rel, lineno)
        if item is not None:
            findings.append(item)
    return findings


def scan(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    if root.is_file():
        name = root.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            return _scan_requirements(root, root.parent)
        return []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or _skip(path):
            continue
        name = path.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            findings.extend(_scan_requirements(path, root))
    return findings
