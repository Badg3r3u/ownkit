from __future__ import annotations

from pathlib import Path

from ownkit.finding import Report, Severity
from ownkit.modules import ci, config, deps, docker, git, perms, secrets

DEFAULT_MODULES = ["secrets", "config", "deps", "docker", "ci", "git", "perms"]

_RUNNERS = {
    "secrets": secrets.scan,
    "config": config.scan,
    "deps": deps.scan,
    "perms": perms.scan,
    "docker": docker.scan,
    "ci": ci.scan,
}


def run_modules(root: Path, names: list[str]) -> Report:
    report = Report(path=str(root), modules=list(names))
    for name in names:
        if name == "git":
            items, notes = git.scan(root)
            report.extend(items)
            report.notes.extend(notes)
        elif name in _RUNNERS:
            report.extend(_RUNNERS[name](root))
        else:
            report.notes.append(f"unknown module: {name}")
    return report


def fail_on_from_name(name: str) -> Severity | None:
    if name == "never":
        return None
    return Severity[name]
