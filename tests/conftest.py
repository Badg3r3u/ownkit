"""Git checkouts do not preserve world-writable modes. Set them for fixture scans."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def _fixture_file_modes() -> None:
    app = FIXTURES / "app.py"
    key = FIXTURES / "id_ed25519"
    if app.exists():
        app.chmod(0o666)
    if key.exists():
        key.chmod(0o644)
