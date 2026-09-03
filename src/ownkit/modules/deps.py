from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for req in list(root.glob("requirements*.txt")) + list(root.glob("**/requirements*.txt")):
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in req.parts):
            continue
        try:
            lines = req.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            raw = line.split("#", 1)[0].strip()
            if not raw or raw.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[]", raw, maxsplit=1)[0].strip()
            if not name:
                continue
            pinned = "==" in raw or "@" in raw
            if not pinned:
                findings.append(
                    Finding(
                        id="deps.unpinned",
                        module="deps",
                        severity=Severity.medium,
                        path=_rel(req, root),
                        title=f"Unpinned dependency: {name}",
                        evidence=raw,
                        remediation="Pin a reviewed version (for example `package==1.2.3`) and re-install from a lockfile so builds stay reproducible.",
                    )
                )

    pkg = root / "package.json"
    if pkg.is_file():
        text = pkg.read_text(encoding="utf-8", errors="ignore")
        if '"*"' in text:
            findings.append(
                Finding(
                    id="deps.wildcard",
                    module="deps",
                    severity=Severity.medium,
                    path="package.json",
                    title="Wildcard dependency version",
                    evidence='version "*"',
                    remediation="Replace `*` with a pinned version range you have reviewed.",
                )
            )
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
