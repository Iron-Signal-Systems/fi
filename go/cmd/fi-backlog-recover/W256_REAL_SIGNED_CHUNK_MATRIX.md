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

1. On `fi-dev`, update the **separate detached** worktree to `origin/experiment/fi-w256-memory4g-chunk-matrix-20261107`; do not edit the canonical FI checkout.
2. Keep the complete previously authenticated 8,399-batch signed cache at `/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache` on `fi-backend-b`.
3. Provision a **NEW, EMPTY, ISOLATED** PostgreSQL 18.6 database `fi` with the existing 49-table relational schema, the private `fi_recovery` and `fi_recovery_projection` schemas, the partitioned Security-field table, and the fixture's `fi_m1_admin` / `fi_ingest` roles and grants. Start it inside `fi-dev` under `/home/jwood/fi-w256-seed` at port `55870`, with a socket directory `/home/jwood/fi-w256-seed/socket`. The three-window **W128 seed is NOT usable** for this step. A populated, authoritative, or already checkpointed database must fail preflight. The scripts deliberately do not provision or silently migrate this prerequisite.
4. Confirm adequate free disk space (at least 96 GiB for the four independent trial databases). No resource-accounting tunables or reboot are needed.

## Test and build

In the detached worktree on `jwood@fi-dev`:

```sh
cd /home/jwood/fi-deferred-experiment
git fetch origin
git checkout --detach origin/experiment/fi-w256-memory4g-chunk-matrix-20261107

cd go
GOAMD64=v1 go test ./internal/recordingest ./cmd/fi-backlog-recover -count=1

sh -n ./cmd/fi-backlog-recover/run_w256_seed_host.sh
sh -n ./cmd/fi-backlog-recover/provision_w256_chunk_matrix_jail.sh
sh -n ./cmd/fi-backlog-recover/run_w256_chunk_arm_host.sh
sh -n ./cmd/fi-backlog-recover/run_w256_chunk_matrix_host.sh
```

Only after those checks pass, on `root@fi-backend-b`:

```sh
jail_root=$(jls -j fi-dev path)
base="${jail_root%/}/home/jwood/fi-deferred-experiment/go/cmd/fi-backlog-recover"

# First W256 window; the seed runner reauthenticates the entire signed
# FIGT, rather than trusting or copying W128 SQL checkpoint identities.
sh "$base/run_w256_seed_host.sh" /home/jwood/fi-w256-seed 55870

# Four independent W256 database clones, K32/K64/K96/K128.
# Each arm commits exactly windows 1–4 before stopping.
sh "$base/run_w256_chunk_matrix_host.sh" /home/jwood/fi-w256-seed 55870
```

The seed scans original custody. The matrix uses that signed receipt and the already authenticated immutable cache; each replay checks the source hashes again. No arbitrary ten-minute cutoff is used. The matrix is serial: only one ingest worker executes at a time.

## Acceptance and analysis

For EACH arm, require:

- Four complete, durable W256 source+typed checkpoints after window zero and zero authoritative or Accepted outcomes.
- Exactly matching original signed descriptor chains and record/byte counts across all four arms.
- Every Security-field partition attached with validated PK and FK constraints.
- Identical signed data and manifests on disk after publication, compared byte-for-byte against the original cache.
- Process RSS high-water, Go-managed memory, memory-pressure/actual-chunk statistics recorded. The 4 GiB target is advisory, not an enforced maximum.
- Compare `FI PRIVATE STAGE PROFILE`, `FI PRIVATE W256 MEMORY COMMITTED`, exact durable elapsed/rates, PostgreSQL waits, CPU, GC and disk I/O; distinguish source processing from durable committed throughput.

A smaller chunk that creates more COPY calls but lower memory may still win. A 128K arm that shrinks under pressure is an **adaptive K128-ceiling arm**, not evidence of fixed K128 throughput.

**Status:** Source changes, tests, and host runners are committed on the isolated experiment branch. GitHub CI can validate compilation and synthetic/PostgreSQL fixtures. Only execution on `fi-backend-b` with the user's genuine signed custody and fresh W256 database can establish real throughput and observed memory use.
