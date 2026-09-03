from __future__ import annotations

from pathlib import Path
import re

from ownkit.finding import Finding, Severity

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

DEBUG_RE = re.compile(r"(?i)\bdebug\s*[=:]\s*(true|1|yes)\b")
CORS_RE = re.compile(r"(?i)access-control-allow-origin[\s\"':=,]+\*")
TLS_OFF_RE = re.compile(
    r"(?i)(?:verify_ssl|ssl_verify|verify_certs|tls_verify|insecure_skip_verify)"
    r"\s*[=:]\s*(?:false|0|no|off)\b"
)
NODE_TLS_RE = re.compile(r"(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0")
PRIVILEGED_RE = re.compile(r"(?i)^\s*privileged\s*:\s*true\b")
NET_HOST_RE = re.compile(r"(?i)^\s*network_mode\s*:\s*host\b")
PID_HOST_RE = re.compile(r"(?i)^\s*pid\s*:\s*host\b")
BIND_ALL_RE = re.compile(r"0\.0\.0\.0")
ALLOWED_HOSTS_RE = re.compile(r"(?i)allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]")
USER_RE = re.compile(r"(?i)^USER\s+(\S+)")
ENV_SKIP = {".env.example", ".env.sample", ".env.template"}
COMPOSE_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_env_file(path: Path) -> bool:
    name = path.name
    if name in ENV_SKIP:
        return False
    return name == ".env" or name.startswith(".env.")


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    return name == "Dockerfile" or name.startswith("Dockerfile.") or lower.endswith(".dockerfile")


def _is_compose(path: Path) -> bool:
    return path.name.lower() in COMPOSE_NAMES


def _iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def _scan_dockerfile(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    has_user = False
    for lineno, line in enumerate(text.splitlines(), 1):
        match = USER_RE.match(line.strip())
        if not match:
            continue
        has_user = True
        user_name = match.group(1).split(":", 1)[0]
        if user_name.lower() in {"root", "0"}:
            findings.append(
                Finding(
                    id="config.dockerfile_user_root",
                    module="config",
                    severity=Severity.high,
                    path=rel,
                    title="Dockerfile runs as root",
                    evidence=line.strip(),
                    remediation="Add a non-root USER instruction after installing packages so the container process does not run as uid 0.",
                    line=lineno,
                )
            )
    if not has_user:
        findings.append(
            Finding(
                id="config.dockerfile_missing_user",
                module="config",
                severity=Severity.medium,
                path=rel,
                title="Dockerfile has no USER instruction",
                evidence="no USER instruction",
                remediation="Add USER with a dedicated non-root account after the image is built so a breakout starts unprivileged.",
                line=1,
            )
        )
    return findings


def _scan_compose_line(line: str, lineno: int, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if BIND_ALL_RE.search(line):
        findings.append(
            Finding(
                id="config.compose_bind_all",
                module="config",
                severity=Severity.medium,
                path=rel,
                title="Compose publishes a port on 0.0.0.0",
                evidence=line.strip(),
                remediation="Bind to 127.0.0.1 for local-only services, or put the service behind a firewall / reverse proxy you control.",
                line=lineno,
            )
        )
    if PRIVILEGED_RE.search(line):
        findings.append(
            Finding(
                id="config.compose_privileged",
                module="config",
                severity=Severity.high,
                path=rel,
                title="Compose service enables privileged mode",
                evidence=line.strip(),
                remediation="Remove privileged: true and grant only the capabilities the process needs.",
                line=lineno,
            )
        )
    if NET_HOST_RE.search(line):
        findings.append(
            Finding(
                id="config.compose_host_network",
                module="config",
                severity=Severity.medium,
                path=rel,
                title="Compose service uses host networking",
                evidence=line.strip(),
                remediation="Use bridge networking and publish only the ports you need instead of network_mode: host.",
                line=lineno,
            )
        )
    if PID_HOST_RE.search(line):
        findings.append(
            Finding(
                id="config.compose_host_pid",
                module="config",
                severity=Severity.medium,
                path=rel,
                title="Compose service shares the host PID namespace",
                evidence=line.strip(),
                remediation="Remove pid: host unless the workload truly must see host processes.",
                line=lineno,
            )
        )
    return findings


def scan(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    files = _iter_files(root)
    display_root = root if root.is_dir() else root.parent

    gitignore_text = ""
    gitignore_path = None
    for path in files:
        if path.name == ".gitignore":
            gitignore_path = path
            try:
                gitignore_text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                gitignore_text = ""

    saw_env_example = False
    saw_committed_env = False

    for path in files:
        rel = _rel(path, display_root)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if _is_env_file(path):
            saw_committed_env = True
            findings.append(
                Finding(
                    id="config.committed_env",
                    module="config",
                    severity=Severity.high,
                    path=rel,
                    title="Environment file present in the scanned tree",
                    evidence=path.name,
                    remediation="Keep .env local only. Add it to .gitignore, rotate any values that were committed, and document names in .env.example.",
                    line=1,
                )
            )
        if path.name in ENV_SKIP:
            saw_env_example = True

        if _is_dockerfile(path):
            findings.extend(_scan_dockerfile(text, rel))

        if _is_compose(path):
            for lineno, line in enumerate(text.splitlines(), 1):
                findings.extend(_scan_compose_line(line, lineno, rel))

        for lineno, line in enumerate(text.splitlines(), 1):
            if DEBUG_RE.search(line):
                findings.append(
                    Finding(
                        id="config.debug_enabled",
                        module="config",
                        severity=Severity.medium,
                        path=rel,
                        title="Debug flag appears enabled",
                        evidence=line.strip()[:120],
                        remediation="Disable debug in committed configs and enable it only via local environment for development.",
                        line=lineno,
                    )
                )
            if CORS_RE.search(line):
                findings.append(
                    Finding(
                        id="config.cors_wildcard",
                        module="config",
                        severity=Severity.high,
                        path=rel,
                        title="CORS allows any origin",
                        evidence=line.strip()[:120],
                        remediation="Replace * with an explicit allow-list of origins you control.",
                        line=lineno,
                    )
                )
            if TLS_OFF_RE.search(line) or NODE_TLS_RE.search(line):
                findings.append(
                    Finding(
                        id="config.tls_verify_disabled",
                        module="config",
                        severity=Severity.high,
                        path=rel,
                        title="TLS certificate verification is disabled",
                        evidence=line.strip()[:120],
                        remediation="Leave TLS verification on. Fix the trust store or use a private CA instead of disabling checks.",
                        line=lineno,
                    )
                )
            if ALLOWED_HOSTS_RE.search(line):
                findings.append(
                    Finding(
                        id="config.allowed_hosts_wildcard",
                        module="config",
                        severity=Severity.medium,
                        path=rel,
                        title="ALLOWED_HOSTS permits any host",
                        evidence=line.strip()[:120],
                        remediation="List the hostnames this app should accept instead of *.",
                        line=lineno,
                    )
                )

    if saw_env_example or saw_committed_env:
        ignored = ".env" in gitignore_text
        if not ignored:
            findings.append(
                Finding(
                    id="config.gitignore_env",
                    module="config",
                    severity=Severity.medium,
                    path=_rel(gitignore_path, display_root) if gitignore_path else ".gitignore",
                    title=".env is not listed in .gitignore",
                    evidence="missing .env ignore rule",
                    remediation="Add .env and .env.* (except .env.example) to .gitignore so local secrets stay untracked.",
                    line=1,
                )
            )
    return findings
