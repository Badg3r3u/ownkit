# ownkit

Defensive security toolkit for **systems and repos you own**. A small collection of checks under one CLI. Not a pentest distro.

Sibling of [ownscan](https://github.com/Badg3r3u/ownscan): ownscan stays the focused secrets/misconfig scanner. ownkit is the suite.

## What it does

| Command | Check |
| --- | --- |
| `ownkit scan` | Default set: secrets, config, deps, docker, ci, perms (git history if `.git` exists) |
| `ownkit secrets` | Pattern scan for leaked keys/tokens in a local tree |
| `ownkit config` | Project misconfig (committed `.env`, debug flags, compose bound to `0.0.0.0`) |
| `ownkit deps` | Unpinned requirements / wildcard versions |
| `ownkit docker` | Dockerfile `:latest`, missing `USER`, privileged compose, docker.sock mounts |
| `ownkit ci` | GitHub Actions `pull_request_target` and secrets echoed into logs |
| `ownkit git` | Same secret patterns in recent git history |
| `ownkit perms` | World-writable files and overly open SSH private keys |

Findings include **remediation** (how to fix), not attack steps.

## Install

```bash
python3 -m pip install -e ".[dev]"
ownkit scan --path fixtures
```

Useful flags: `--format text|json`, `--fail-on low|medium|high|critical|never` (default `high`).

## What it will never do

No exploits, recon against other people's hosts, password-cracking, sniffing, social-engineering, or pentest playbooks. Pass `--path` (and git history of that repo) for assets you own.

## License

MIT
