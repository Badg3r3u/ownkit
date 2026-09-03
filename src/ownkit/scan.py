from __future__ import annotations

from pathlib import Path

from ownkit.finding import Report, Severity
from ownkit.modules import config, deps, git, perms, secrets


def run_modules(root: Path, names: list[str]) -> Report:
    report = Report()
    mapping = {
        "secrets": lambda: secrets.scan(root),
        "config": lambda: config.scan(root),
        "deps": lambda: deps.scan(root),
        "perms": lambda: perms.scan(root),
    }
    for name in names:
        if name == "git":
            items, notes = git.scan(root)
            report.extend(items)
            report.notes.extend(notes)
        elif name in mapping:
            report.extend(mapping[name]())
        else:
            report.notes.append(f"unknown module: {name}")
    return report


DEFAULT_MODULES = ["secrets", "config", "perms", "git"]


def fail_on_from_name(name: str) -> Severity | None:
    if name == "never":
        return None
    return Severity[name]
