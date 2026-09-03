from __future__ import annotations

from pathlib import Path
import stat

from ownkit.modules import perms

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_perms_flags_world_writable_and_open_key():
    findings = perms.scan(ROOT)
    ids = {item.id for item in findings}
    assert "perms.world_writable" in ids
    assert "perms.ssh_key_open" in ids
    assert all(item.remediation for item in findings)


def test_perms_clean_file(tmp_path: Path):
    target = tmp_path / "ok.txt"
    target.write_text("ok\n", encoding="utf-8")
    target.chmod(0o644)
    findings = perms.scan(tmp_path)
    assert findings == []


def test_perms_tmp_world_writable(tmp_path: Path):
    target = tmp_path / "open.txt"
    target.write_text("nonsensitive\n", encoding="utf-8")
    target.chmod(0o666)
    assert target.stat().st_mode & stat.S_IWOTH
    findings = perms.scan(tmp_path)
    assert any(item.id == "perms.world_writable" for item in findings)
