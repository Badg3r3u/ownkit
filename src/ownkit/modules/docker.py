from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity

FROM_LATEST = re.compile(r"(?im)^\s*FROM\s+\S+:latest\b")
HAS_USER = re.compile(r"(?im)^\s*USER\s+\S+")
PRIVILEGED = re.compile(r"(?i)privileged\s*:\s*true")
DOCKER_SOCK = re.compile(r"/var/run/docker\.sock")


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    dockerfiles = list(root.rglob("Dockerfile")) + list(root.rglob("Dockerfile.*"))
    dockerfiles += list(root.rglob("*.dockerfile"))
    for path in dockerfiles:
        if _skip(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = _rel(path, root)
        if FROM_LATEST.search(text):
            findings.append(
                Finding(
                    id="docker.from_latest",
                    module="docker",
                    severity=Severity.medium,
                    path=rel,
                    title="Image tag is `:latest`",
                    evidence="FROM …:latest",
                    remediation="Pin a digest or a specific version tag so rebuilds stay reproducible and you notice base-image updates.",
                )
            )
        if not HAS_USER.search(text):
            findings.append(
                Finding(
                    id="docker.runs_as_root",
                    module="docker",
                    severity=Severity.medium,
                    path=rel,
                    title="Dockerfile never sets USER (likely runs as root)",
                    evidence="no USER instruction",
                    remediation="Add a non-root `USER` near the end of the Dockerfile after packages are installed.",
                )
            )

    for path in list(root.rglob("docker-compose*.yml")) + list(root.rglob("docker-compose*.yaml")) + list(root.rglob("compose.y*ml")):
        if _skip(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = _rel(path, root)
        if PRIVILEGED.search(text):
            findings.append(
                Finding(
                    id="docker.privileged",
                    module="docker",
                    severity=Severity.high,
                    path=rel,
                    title="Compose service enables privileged mode",
                    evidence="privileged: true",
                    remediation="Drop `privileged: true` and grant only the capabilities the service actually needs.",
                )
            )
        if DOCKER_SOCK.search(text):
            findings.append(
                Finding(
                    id="docker.socket_mount",
                    module="docker",
                    severity=Severity.high,
                    path=rel,
                    title="Docker socket is mounted into a container",
                    evidence="/var/run/docker.sock",
                    remediation="Avoid mounting the host Docker socket. If you must, isolate that container and treat it as root-equivalent on the host.",
                )
            )
    return findings


def _skip(path: Path) -> bool:
    return any(part in {".git", ".venv", "venv", "node_modules"} for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
