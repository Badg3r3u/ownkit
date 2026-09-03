from pathlib import Path

from ownkit.modules import secrets

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_secrets_hits_fixtures():
    findings = secrets.scan(ROOT)
    ids = {f.id for f in findings}
    assert "secrets.github_pat" in ids or "secrets.generic_assignment" in ids
    assert "secrets.aws_access_key" in ids
    assert "secrets.private_key" in ids
