from __future__ import annotations

from pathlib import Path
import stat

from ownkit.finding import Finding, Severity

KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv"}


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        rel = _rel(path, root)
        if mode & stat.S_IWOTH:
            findings.append(
                Finding(
                    id="perms.world_writable",
                    module="perms",
                    severity=Severity.high,
                    path=rel,
                    title="World-writable file",
                    evidence=oct(mode & 0o777),
                    remediation="Restrict the mode (for example `chmod o-w` / `chmod 644` or `600` for secrets) so other users cannot modify it.",
                )
            )
        if path.name in KEY_NAMES and (mode & 0o077):
            findings.append(
                Finding(
                    id="perms.ssh_key_open",
                    module="perms",
                    severity=Severity.critical,
                    path=rel,
                    title="SSH private key is group/world accessible",
                    evidence=oct(mode & 0o777),
                    remediation="Run `chmod 600` on the key and confirm it was never copied into a shared directory.",
                )
            )
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
