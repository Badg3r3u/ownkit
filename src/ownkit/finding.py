"""Shared finding model and text/JSON reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
import json
from typing import Iterable


class Severity(IntEnum):
    low = 1
    medium = 2
    high = 3
    critical = 4

    def __str__(self) -> str:
        return self.name


SEVERITY_NAMES = {s.name: s for s in Severity}


def redact_secret(value: str, keep: int = 4) -> str:
    """Mask the middle of a credential so reports are safer to paste."""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return f"{value[:1]}***"
    return f"{value[:keep]}…{value[-keep:]}"


def redact_evidence(value: str, match: str | None = None) -> str:
    stripped = value.strip()
    if match and match in stripped:
        stripped = stripped.replace(match, redact_secret(match), 1)
    if len(stripped) > 140:
        return stripped[:140] + "…"
    return stripped


@dataclass(frozen=True)
class Finding:
    """One defensive finding on a path the operator owns."""

    id: str
    module: str
    severity: Severity
    path: str
    title: str
    evidence: str
    remediation: str
    line: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    path: str = ""
    modules: list[str] = field(default_factory=list)

    def extend(self, items: Iterable[Finding]) -> None:
        self.findings.extend(items)

    def above(self, fail_on: Severity | None) -> list[Finding]:
        if fail_on is None:
            return []
        return [item for item in self.findings if item.severity >= fail_on]

    def summary(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in self.findings:
            counts[item.severity.name] += 1
        counts["total"] = len(self.findings)
        return counts

    def to_json(self) -> str:
        payload = {
            "tool": "ownkit",
            "path": self.path,
            "modules": self.modules,
            "findings": [item.to_dict() for item in self.findings],
            "notes": self.notes,
            "count": len(self.findings),
            "summary": self.summary(),
        }
        return json.dumps(payload, indent=2) + "\n"

    def to_text(self) -> str:
        header = "ownkit"
        if self.path:
            header += f"  path={self.path}"
        if self.modules:
            header += f"  checks={','.join(self.modules)}"
        lines: list[str] = [header]
        if not self.findings:
            lines.append("No findings.")
            for note in self.notes:
                lines.append(f"note: {note}")
            return "\n".join(lines) + "\n"
        lines.append("")
        ordered = sorted(
            self.findings,
            key=lambda item: (-int(item.severity), item.path, item.line, item.id),
        )
        for item in ordered:
            loc = f"{item.path}:{item.line}" if item.line else item.path
            lines.append(f"[{item.severity.name.upper()}] {item.id}  {loc}")
            lines.append(f"  {item.title}")
            if item.evidence:
                lines.append(f"  evidence: {item.evidence}")
            lines.append(f"  fix: {item.remediation}")
            lines.append("")
        counts = self.summary()
        parts = [
            f"{counts[name]} {name}"
            for name in ("critical", "high", "medium", "low")
            if counts[name]
        ]
        lines.append(f"Summary: {counts['total']} finding(s) ({', '.join(parts)})")
        for note in self.notes:
            lines.append(f"note: {note}")
        return "\n".join(lines).rstrip() + "\n"
