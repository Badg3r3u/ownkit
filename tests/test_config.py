from pathlib import Path

from ownkit.modules import config, deps

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_config_flags_env_and_compose():
    findings = config.scan(ROOT)
    ids = {f.id for f in findings}
    assert "config.committed_env" in ids
    assert "config.compose_bind_all" in ids
    assert "config.debug_enabled" in ids


def test_deps_flags_unpinned():
    findings = deps.scan(ROOT)
    assert any(f.id == "deps.unpinned" and "requests" in f.title for f in findings)


def test_config_flags_dockerfile_and_cors():
    findings = config.scan(ROOT)
    ids = {f.id for f in findings}
    assert "config.dockerfile_missing_user" in ids
    assert "config.cors_wildcard" in ids
    assert all(f.remediation for f in findings)
