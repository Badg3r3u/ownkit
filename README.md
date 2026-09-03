# ownkit

A local-only CLI that runs **defensive hygiene checks** on a path you already own: leaked secrets, unsafe project configs, unpinned dependencies, secret patterns in git history, and risky file permissions.

ownkit is a sibling of [ownscan](https://github.com/Badg3r3u/ownscan). ownscan stays the focused secrets/misconfig scanner. ownkit is the small suite around the same idea.

It reads local files, prints findings with **remediation** (how to fix or harden), and exits. It does not open a network connection, does not scan remote hosts, and does not use or validate any credential it finds.

## Commands

| Command | Check |
| --- | --- |
| `ownkit scan` | Default set: secrets, config, deps, git, perms |
| `ownkit secrets` | Leaked-secret patterns in the working tree (values redacted) |
| `ownkit config` | Committed `.env`, debug flags, CORS `*`, TLS verify off, Dockerfile `USER`, compose bind/privileged |
| `ownkit deps` | Unpinned or wildcard versions in requirements files |
| `ownkit git` | Same secret patterns in recent local git history, plus credentials in remote URLs |
| `ownkit perms` | World-writable files and overly open SSH private keys |
| `ownkit docker` | Dockerfile latest tag / missing USER, privileged compose |
| `ownkit ci` | GitHub Actions workflow pitfalls |

## Install

Python 3.11 or newer.

```bash
python3 -m pip install -e ".[dev]"
```

## Run

```bash
ownkit scan --path fixtures
ownkit scan --path fixtures --json
ownkit secrets --path .
ownkit config --path .
ownkit deps --path .
ownkit git --path .
ownkit perms --path .
ownkit docker --path .
ownkit ci --path .
python -m ownkit scan --path fixtures
```

Useful flags (all subcommands):

- `--path` / `-p` — local directory or file you own (default: current directory)
- `--format text|json` or `--json`
- `--fail-on low|medium|high|critical|never` (default: `high`)

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` (default: high and critical) |
| 1 | One or more findings at or above the threshold |
| 2 | Path does not exist |

## Sample

Against the bundled **FAKE/EXAMPLE** fixtures (placeholders only, never real credentials):

```text
$ ownkit scan --path fixtures
[CRITICAL] secrets.aws_access_key  app.py:1
  Possible secret in source tree
  evidence: AKIAEXAM…
  fix: Rotate the key in IAM, remove it from the repo, and load secrets from a secret manager...
```

Exact line numbers and redaction widths may differ. JSON objects include `id`, `module`, `severity`, `path`, `line`, `title`, `evidence`, and `remediation`.

## What it looks for

**Secrets (redacted in output)**

- AWS access key IDs (`AKIA…`)
- GitHub personal access tokens (`ghp_…`)
- Slack bot/user tokens
- PEM / OpenSSH private-key armor headers
- Quoted `api_key` / `secret_key` / `access_token` assignments

**Config**

- Committed `.env` files (templates like `.env.example` are skipped)
- `DEBUG = True` and similar
- CORS `Access-Control-Allow-Origin *`
- TLS verification disabled
- Dockerfiles with `USER root` or no `USER`
- Compose `0.0.0.0` binds, `privileged: true`, host network/PID

**Dependencies**

- Unpinned lines in `requirements*.txt` (`requests` with no `==`)

**Git (local repo only)**

- Secret patterns in `git log -p` of recent commits
- Passwords or tokens embedded in remote URLs

**Permissions**

- World-writable files
- SSH private keys with group/other access

Directories skipped for content walks: `.git`, `node_modules`, `venv`, `.venv`, `dist`, `build`, `__pycache__`, and similar.

## Limitations

- **Local files only.** There is no remote scan and no cloud API check.
- **Pattern-based.** High-entropy blobs that do not match a known shape are not reported.
- **Not a verifier.** A hit means “this looks like a leak or a smell,” not “this credential is live.”
- **Redaction is best-effort.** Treat reports as sensitive if the original tree was.
- **Not an exploit toolkit.** It will not generate payloads, attack services, or use discovered credentials.

If ownkit reports a real secret in a repository you maintain, rotate that credential and remove it from history — do not just delete the line on `main`.

## Development

```bash
python3 -m pip install -e ".[dev]"
pytest
```

Fixture values under `fixtures/` are labeled **FAKE/EXAMPLE** and include well-known documentation placeholders. They are not usable credentials.

## License

MIT. See [LICENSE](LICENSE).
