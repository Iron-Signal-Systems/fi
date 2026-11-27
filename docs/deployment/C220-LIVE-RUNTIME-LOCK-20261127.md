# C220 live runtime source lock — November 27, 2026

This records the installed, working FI backend. It does not authorize
redeployment or changes to PostgreSQL, signed custody, or running services.

## Recorded candidate source revisions and observed installed hashes

| Executable | Source revision | Installed SHA-256 |
| --- | --- | --- |
| fi-receiver | 49609398d91e105fdeb74190a39bf2e390175996 | c0006e7de05c38eb4da4869de5c9b8ecb56663b4ea35ed44b7a248ca23375f8c |
| fi-c1-sor-live | d78e37010389abb4ba9922ab83abb0d2d6bab8a8 | 54ea5cce0538ba0f65cd1d6effc78b695ed44bd2f8257aa14781bf1e58e558b2 |
| fi-telemetry-backend | 0c2ffb6b32c40e19a3cdc4b0b1cc50e695889fae | dab1deb8cc39ded4c9b293e74bc8c39f30a61393828dc73899a8db560ccf3a11 |

C1's recorded source snapshot is retained at:

runtime/baselines/c220-20261127/c1/go/

The supplied verifier script proposes rebuilding receiver and telemetry from their pinned Git revisions and C1 from the retained snapshot.

Run on FreeBSD amd64:

    sh tools/deployment/freebsd/operations/verify_c220_live_sources.sh

The verifier requires Go 1.27.4 and builds with CGO_ENABLED=1,
GOAMD64=v1, -trimpath, and -buildvcs=false.

The three runtime source revisions are intentionally isolated because
the receiver and C1 executable were built against different revisions
of shared code. Do not mix them or replace accepted Windows code.

**Verification state as of 2026-11-27:** The source revisions and installed SHA-256 hashes above are recorded, and the reproducibility-check script is committed. This document does **not** contain a captured successful run of that script for all three executables. Therefore bit-for-bit matching of all three reconstructed binaries to the live installed binaries remains **unverified by this repository evidence**. Do not treat the word *verified* in a source directory name or historic investigation as an accepted reproducibility result.

A successful, retained verifier transcript for the exact revisions and build environment would establish application-binary identity for those artifacts only. It would **not** establish fresh-install disaster recovery, configuration/secret equivalence, service state, or telemetry delivery acceptance.
