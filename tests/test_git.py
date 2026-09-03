from __future__ import annotations

import subprocess
from pathlib import Path

from ownkit.modules import git

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def test_git_skips_non_repo(tmp_path: Path):
    items, notes = git.scan(tmp_path)
    assert items == []
    assert notes


def test_git_history_detects_fixture_secret(tmp_path: Path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "dev@example.com")
    _git(tmp_path, "config", "user.name", "ownkit fixture")
    leaked = (ROOT / "app.py").read_text(encoding="utf-8")
    (tmp_path / "leak.py").write_text(leaked, encoding="utf-8")
    _git(tmp_path, "add", "leak.py")
    _git(tmp_path, "commit", "-m", "FAKE example commit")
    (tmp_path / "leak.py").unlink()
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "remove fake secret from tree")
    items, notes = git.scan(tmp_path)
    assert notes == []
    ids = {item.id for item in items}
    assert "git.aws_access_key" in ids
    assert all(item.remediation for item in items)


def test_git_remote_url_credentials(tmp_path: Path):
    _git(tmp_path, "init")
    token = (ROOT / ".env").read_text(encoding="utf-8").split("=", 1)[1].splitlines()[0]
    url = f"https://user:{token}@github.example.invalid/org/repo.git"
    _git(tmp_path, "remote", "add", "origin", url)
    items, _notes = git.scan(tmp_path)
    ids = {item.id for item in items}
    assert "git.remote_url_credentials" in ids
    finding = next(item for item in items if item.id == "git.remote_url_credentials")
    assert finding.severity.name == "critical"
    assert token not in finding.evidence
