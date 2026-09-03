from __future__ import annotations

import argparse
from pathlib import Path
import sys

from ownkit.scan import DEFAULT_MODULES, fail_on_from_name, run_modules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ownkit",
        description="Defensive checks for systems and repos you own.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--path", default=".", help="Directory to scan (default: cwd)")
        sp.add_argument("--format", choices=("text", "json"), default="text")
        sp.add_argument(
            "--fail-on",
            choices=("low", "medium", "high", "critical", "never"),
            default="high",
            help="Exit 1 if any finding is at or above this severity (default: high)",
        )

    scan_p = sub.add_parser("scan", help="Run the default defensive set")
    add_common(scan_p)
    for name, help_text in (
        ("secrets", "Leaked-secret patterns in the tree"),
        ("config", "Project misconfiguration"),
        ("deps", "Unpinned / wildcard dependencies"),
        ("git", "Secret patterns in recent git history"),
        ("perms", "World-writable files and open SSH keys"),
    ):
        sp = sub.add_parser(name, help=help_text)
        add_common(sp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"path not found: {root}", file=sys.stderr)
        return 2
    modules = DEFAULT_MODULES if args.cmd == "scan" else [args.cmd]
    report = run_modules(root, modules)
    out = report.to_json() if args.format == "json" else report.to_text()
    sys.stdout.write(out)
    fail_on = fail_on_from_name(args.fail_on)
    if report.above(fail_on):
        return 1
    return 0
