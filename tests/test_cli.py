from __future__ import annotations

import json
from pathlib import Path

from ownkit.cli import main

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_missing_path_exits_two(capsys):
    code = main(["scan", "--path", str(ROOT / "does-not-exist")])
    assert code == 2
    err = capsys.readouterr().err
    assert "path not found" in err


def test_json_flag_includes_remediation(capsys):
    code = main(["scan", "--path", str(ROOT), "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] >= 1
    assert payload["findings"]
    first = payload["findings"][0]
    assert "remediation" in first
    assert first["remediation"]
    modules = {item["module"] for item in payload["findings"]}
    assert "secrets" in modules
    assert "deps" in modules
    assert "perms" in modules


def test_text_report_has_fix_lines(capsys):
    code = main(["secrets", "--path", str(ROOT)])
    assert code == 1
    out = capsys.readouterr().out
    assert "fix:" in out


def test_clean_tree_exits_zero(tmp_path: Path, capsys):
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "ok.py").chmod(0o644)
    code = main(["scan", "--path", str(tmp_path), "--fail-on", "high"])
    assert code == 0
    out = capsys.readouterr().out
    assert "No findings." in out or "finding" in out.lower()


def test_subcommand_deps(capsys):
    code = main(["deps", "--path", str(ROOT), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert any(item["id"] == "deps.unpinned" for item in payload["findings"])
    assert code in {0, 1}
