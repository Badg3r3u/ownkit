from __future__ import annotations

import argparse
from pathlib import Path
import sys

from ownkit import __version__
from ownkit.scan import DEFAULT_MODULES, fail_on_from_name, run_modules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ownkit",
        description=(
            "Defensive checks on a local path you own: leaked secrets, "
            "unsafe project configs, unpinned dependencies, git-history "
            "secret patterns, and risky file permissions. ownkit does not "
            "attack remote systems or use any credential it finds."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ownkit {__version__}",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--path",
            "-p",
            default=".",
            help="Local directory or file you own (default: cwd)",
        )
        sp.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="Report format (default: text)",
        )
        sp.add_argument(
            "--json",
            action="store_true",
            help="Shorthand for --format json",
        )
        sp.add_argument(
            "--fail-on",
            choices=("low", "medium", "high", "critical", "never"),
            default="high",
            help="Exit 1 if any finding is at or above this severity (default: high)",
        )

    sub.add_parser("scan", help="Run the default defensive set").set_defaults(
        _help_scan=True
    )
    add_common(sub.choices["scan"])
    for name, help_text in (
        ("secrets", "Leaked-secret patterns in the working tree"),
        ("config", "Project misconfiguration and hardening smells"),
        ("deps", "Unpinned or wildcard dependencies"),
        ("git", "Secret patterns in recent local git history"),
        ("perms", "World-writable files and overly open private keys"),
        ("docker", "Dockerfile and compose hygiene"),
        ("ci", "GitHub Actions workflow pitfalls"),
    ):
        add_common(sub.add_parser(name, help=help_text))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"ownkit: path not found: {root}", file=sys.stderr)
        return 2
    root = root.resolve()
    modules = DEFAULT_MODULES if args.cmd == "scan" else [args.cmd]
    report = run_modules(root, modules)
    fmt = "json" if args.json else args.format
    out = report.to_json() if fmt == "json" else report.to_text()
    sys.stdout.write(out)
    if report.above(fail_on_from_name(args.fail_on)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
