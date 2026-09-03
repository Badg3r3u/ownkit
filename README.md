# ownkit

[![ci](https://github.com/Badg3r3u/ownkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Badg3r3u/ownkit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://github.com/Badg3r3u/ownkit)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Local-only CLI that runs **defensive hygiene checks** on a path you already own: leaked secrets, unsafe project configs, unpinned dependencies, secret patterns in git history, Docker/CI smells, and risky file permissions.

Sibling of [ownscan](https://github.com/Badg3r3u/ownscan). ownscan stays the focused secrets/misconfig scanner. ownkit is the suite around the same idea.

It reads local files, prints findings with **remediation** (how to fix or harden), and exits. It does not open a network connection, does not scan remote hosts, and does not use or validate any credential it finds.

## Commands

| Command | Check |
| --- | --- |
| `ownkit scan` | Default set: secrets, config, deps, docker, ci, git, perms |
| `ownkit secrets` | Leaked-secret patterns in the working tree (values redacted) |
| `ownkit config` | Committed `.env`, debug flags, CORS `*`, TLS verify off, Dockerfile `USER`, compose bind/privileged |
| `ownkit deps` | Unpinned or wildcard versions in requirements files |
| `ownkit docker` | Dockerfile `:latest` / missing `USER`, privileged compose, docker.sock mounts |
| `ownkit ci` | GitHub Actions `pull_request_target` and secrets echoed into logs |
| `ownkit git` | Same secret patterns in recent local git history, plus credentials in remote URLs |
| `ownkit perms` | World-writable files and overly open SSH private keys |

## Install

Python 3.11 or newer.

From this repo:

```bash
git clone https://github.com/Badg3r3u/ownkit.git
cd ownkit
python3 -m pip install -e ".[dev]"
```

Or one shot:

```bash
python3 -m pip install "git+https://github.com/Badg3r3u/ownkit.git"
```

## Run

```bash
ownkit scan --path fixtures
ownkit scan --path fixtures --json
ownkit secrets --path .
python -m ownkit scan --path fixtures
```

Useful flags (all subcommands):

- `--path` / `-p` — local directory or file you own (default: current directory)
- `--format text|json` or `--json`
- `--fail-on low|medium|high|critical|never` (default: `high`)

Exit codes: `0` nothing at/above `--fail-on`, `1` findings at threshold, `2` path missing.

## Sample

Against the bundled **FAKE/EXAMPLE** fixtures (placeholders only, never real credentials):

```text
$ ownkit scan --path fixtures
[CRITICAL] secrets.aws_access_key  app.py:1
  Possible secret in source tree
  evidence: AKIAEXAM…
  fix: Rotate the key in IAM, remove it from the repo, and load secrets from a secret manager...
```

JSON objects include `id`, `module`, `severity`, `path`, `line`, `title`, `evidence`, and `remediation`.

## What it will never do

No exploits, recon against other people's hosts, password-cracking, sniffing, social-engineering, or pentest playbooks. Pattern-based only, local files only, not a live-credential verifier. Treat reports as sensitive if the original tree was.

If ownkit reports a real secret in a repository you maintain, rotate that credential and remove it from history. See [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m pip install -e ".[dev]"
pytest
```

See [CHANGELOG.md](CHANGELOG.md). MIT license in [LICENSE](LICENSE).
