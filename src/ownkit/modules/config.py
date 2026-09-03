from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity

DEBUG_RE = re.compile(r"(?i)(debug|DEBUG)\s*[:=]\s*(true|1|yes)\b")


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    env = root / ".env"
    gitignore = root / ".gitignore"
    env_example = root / ".env.example"

    if env.is_file():
        findings.append(
            Finding(
                id="config.committed_env",
                module="config",
                severity=Severity.high,
                path=".env",
                title="`.env` file present in the scanned tree",
                evidence=str(env),
                remediation="Keep `.env` local only. Add it to `.gitignore`, rotate any values that were committed, and document keys in `.env.example`.",
            )
        )

    if env_example.is_file() and gitignore.is_file():
        gi = gitignore.read_text(encoding="utf-8", errors="ignore")
        if ".env" not in gi:
            findings.append(
                Finding(
                    id="config.gitignore_env",
                    module="config",
                    severity=Severity.medium,
                    path=".gitignore",
                    title="`.env.example` exists but `.env` is not ignored",
                    evidence=".env.example without a .env gitignore entry",
                    remediation="Add `.env` (and variants) to `.gitignore` so local secrets are not committed.",
                )
            )
    elif env_example.is_file() and not gitignore.is_file():
        findings.append(
            Finding(
                id="config.gitignore_env",
                module="config",
                severity=Severity.medium,
                path=".gitignore",
                title="`.env.example` exists but there is no `.gitignore`",
                evidence=".env.example",
                remediation="Add a `.gitignore` that excludes `.env` so local secrets are not committed.",
            )
        )

    for path in list(root.rglob("docker-compose*.yml")) + list(root.rglob("docker-compose*.yaml")) + list(root.rglob("compose.y*ml")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "0.0.0.0" in text:
            findings.append(
                Finding(
                    id="config.compose_bind_all",
                    module="config",
                    severity=Severity.medium,
                    path=_rel(path, root),
                    title="Compose publishes a port on 0.0.0.0",
                    evidence="0.0.0.0",
                    remediation="Bind to 127.0.0.1 for local-only services, or put the service behind a firewall / reverse proxy you control.",
                )
            )

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".ini", ".toml"}:
            continue
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if DEBUG_RE.search(text):
            findings.append(
                Finding(
                    id="config.debug_enabled",
                    module="config",
                    severity=Severity.medium,
                    path=_rel(path, root),
                    title="Debug flag appears enabled",
                    evidence="debug=true (or equivalent)",
                    remediation="Disable debug in committed configs and enable it only via local env for development.",
                )
            )
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
