# Security

ownkit is a **defensive, local-only** scanner. It does not connect to the network or use credentials it finds.

## If ownkit finds a secret in *your* repo

1. Rotate the credential at the issuer (GitHub, AWS, etc.).
2. Remove it from the working tree.
3. If it was committed, purge it from git history and treat the old value as burned.

## Reporting a bug in ownkit

Open a GitHub issue on this repository. Do not attach real secrets, production configs, or private keys. Reproduce with FAKE/EXAMPLE values like the ones under `fixtures/`.

There is no bounty program and no request for exploit PoCs.
