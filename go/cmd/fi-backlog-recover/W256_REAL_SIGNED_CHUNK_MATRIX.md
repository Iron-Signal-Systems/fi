# FI: real-signed W256 / K32–K128 / adaptive memory experiment

**Scope:** Disposable FreeBSD/PostgreSQL 18.6 experiment only. Do not run against the canonical File Intelligence system of record. No Accepted journal event or authoritative generation publication is permitted.

## Design invariants

- The **W256 atomic SQL boundary** is at most 262,144 original signed source records **and** 2 GiB source data, using whole signed batches. It is not a 2 GiB RAM allocation.
- The four **nominal** processing chunk ceilings are 32,768, 65,536, 98,304, and 131,072 source records. They preserve original source-batch identities, order, and the single serialized SQL transaction.
- One private W256 memory governor samples current Go runtime memory and FreeBSD process high-water RSS before signed batches. Pressure closes a chunk early and monotonically lowers subsequent chunk ceilings to K32. Nominal and effective chunk sizes are reported separately.
- Go-managed memory has a 3 GiB soft GC target, or a lower operator-set `GOMEMLIMIT`. Memory accounting and observed RSS are diagnostic, not a hard cap. **No RACCT/RCTL, sysctl, boot configuration, or reboot is required.** If the process exhausts memory, the usual operating-system/process failure and transactional rollback apply.
- The original signed FIGT batch data, SHA-256, strict typed decoding, PostgreSQL foreign-key validation, field indexes, verified artifacts, and atomic marker commit remain mandatory.
- **Never reuse W128 checkpoints as W256 checkpoints**: signed W128 and W256 descriptor chains are different. The existing W128 experiment remains unchanged.

## Prerequisites

1. The **separate** `/home/jwood/fi-deferred-experiment` worktree is clean and detached at the W256 experiment branch. The canonical FI checkout remains untouched.
2. The real original signed custody and already authenticated 8,399-batch cache at `/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache` remain readable.
3. PostgreSQL 18.6 tooling and at least 96 GiB disk headroom are available inside `fi-dev`. The fixture's private socket uses port 55870 for the seed, then ports 55991–55994 for the four arms.

**The benchmark now provisions everything else automatically.** It creates a new empty PostgreSQL database from FI's five canonical migrations and audited private-schema generator, installs the isolated field partition, authenticates and commits signed W256 window zero, then clones that one committed W256 seed into four independent K32–K128 candidates. No W128 SQL checkpoint is reused. No RACCT/RCTL or host boot configuration change is required.

## Build and run

On `jwood@fi-dev`:

```sh
cd /home/jwood/fi-deferred-experiment
git fetch origin
git checkout --detach origin/experiment/fi-w256-memory4g-chunk-matrix-20261107
cd go
GOAMD64=v1 go test ./internal/recordingest ./cmd/fi-backlog-recover -count=1
sh -n ./cmd/fi-backlog-recover/provision_w256_fresh_seed_jail.sh
sh -n ./cmd/fi-backlog-recover/run_w256_seed_host.sh
sh -n ./cmd/fi-backlog-recover/provision_w256_chunk_matrix_jail.sh
sh -n ./cmd/fi-backlog-recover/run_w256_chunk_arm_host.sh
sh -n ./cmd/fi-backlog-recover/run_w256_chunk_matrix_host.sh
```

Then on `root@fi-backend-b` run exactly ONE command:

```sh
jailroot=$(jls -j fi-dev path)
sh "${jailroot%/}/home/jwood/fi-deferred-experiment/go/cmd/fi-backlog-recover/run_w256_chunk_matrix_host.sh"
```

The orchestrator stops at the first failed preflight or committed-window verification and leaves isolated diagnostics on disk. It does not delete or mutate the original signed custody, verified cache, canonical source database, or W128 checkpoint chain.

The seed authenticates the original FIGT transfer. Each arm uses the immutable receipt-bound cache with fresh per-batch hashes, and commits four consecutive W256 windows. The four arms execute **serially**; no multiworker ingestion.

## Acceptance and analysis

For EACH arm, require:

- Four complete, durable W256 source+typed checkpoints after window zero and zero authoritative or Accepted outcomes.
- Exactly matching original signed descriptor chains and record/byte counts across all four arms.
- Every Security-field partition attached with validated PK and FK constraints.
- Identical signed data and manifests on disk after publication, compared byte-for-byte against the original cache.
- Process RSS high-water, Go-managed memory, memory-pressure/actual-chunk statistics recorded. The 4 GiB target is advisory, not an enforced maximum.
- Compare `FI PRIVATE STAGE PROFILE`, `FI PRIVATE W256 MEMORY COMMITTED`, and exact durable elapsed/rates. Collect external PostgreSQL waits, CPU, GC and disk I/O where supported; distinguish source processing from durable committed throughput.

A smaller chunk that creates more COPY calls but lower memory may still win. A 128K arm that shrinks under pressure is an **adaptive K128-ceiling arm**, not evidence of fixed K128 throughput.

**Status:** Source changes, tests, and host runners are committed on the isolated experiment branch. GitHub CI can validate compilation and synthetic/PostgreSQL fixtures. Only execution on `fi-backend-b` with the user's genuine signed custody and fresh W256 database can establish real throughput and observed memory use.
