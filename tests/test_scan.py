import json
from pathlib import Path

from ownkit.cli import main

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_scan_json_and_fail_on(capsys):
    code = main(["scan", "--path", str(ROOT), "--format", "json", "--fail-on", "high"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] >= 1
    modules = {f["module"] for f in payload["findings"]}
    assert "secrets" in modules
    assert "config" in modules


def test_fail_on_never(capsys):
    code = main(["scan", "--path", str(ROOT), "--fail-on", "never"])
    assert code == 0
    assert capsys.readouterr().out
