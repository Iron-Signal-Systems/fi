# FI: real signed W128 deferred ZFS clone experiment

This is an opt-in, **private only**, one-worker experiment. Do not use in
production or against canonical FI source-of-record PostgreSQL. The original
signed FIGT custody, original 8,399-batch verified cache, Accepted journal,
and existing FI deployment must remain untouched.

## Implementation

The original W128 source and typed ingestion paths remain. In the experimental
path, the signed cache artifact is COW-cloned into a private, **unpublished**
directory. No data hash is skipped: the existing ingestSourceBatch verifies the
exact LF-terminated SHA-256 for each signed source batch during typed projection.
A provisional artifact marker is inserted inside that **same uncommitted
PostgreSQL transaction** before source COPY, satisfying the schema's existing
immediate foreign-key constraints. After every signed batch passes verification,
all source/typed coverage checks pass, and all SQL rows/markers are still
uncommitted, the independently cloned data files are durably published with
directory synchronization. The original transaction commits the artifact,
source, and typed markers together. Any failure rolls back all SQL markers.
A crash between file publication and SQL commit leaves files without a
checkpoint; the existing ready-artifact path fully hashes them on resume.

The experiment is guarded by `-deferred-verified-clone`, requiring the verified
cache, W128/K32/P3/F3, detached private Security field partitions and an
existing three-window seed. It cannot write canonical SoR or Accepted rows.

## Build in fi-dev over the existing SSH session

```sh
cd /home/jwood/src/fi
git fetch origin
git worktree add --detach /home/jwood/fi-deferred-experiment \
 origin/experiment/fi-deferred-verified-clone-20261106
cd /home/jwood/fi-deferred-experiment/go
go test -count=1 ./internal/recordingest ./cmd/fi-backlog-recover
go vet ./internal/recordingest
go build -o /home/jwood/fi-deferred-experiment/fi-backlog-recover \
 ./cmd/fi-backlog-recover
```

Never merge this experimental branch into the working directory containing
uncommitted local fresh-artifact proof and profiling modifications.

## First real-data acceptance: one W128 window

Use the **idle K64 database clone** under
`/home/jwood/fi-window-bench-optfield-20261106T010206Z/K64`, which was
provisioned at checkpoint 3 (390,387 records). It is a disposable clone; the
processor setting is K32 despite the old cluster's K64 directory label.
Before running, check that the K64 database still has exactly
`3|390387|2` and zero canonical/Accepted entries.

Start the existing `fi-optfield-relay` from the FreeBSD **host** with:
`-cluster-root=/home/jwood/fi-window-bench-optfield-20261106T010206Z`,
`-base-port=55981`, and a new `/var/tmp/fi-window-chunks-...` output
directory (mode 0700). Use the already compiled jail relay binary through
`-jail-binary=/home/jwood/fi-window-bench-optfield-20261106T010206Z/fi-optfield-relay`.
The host relay provides `pg-K64` on local socket port 55982.

Run the experiment binary from the host-visible jail root with the existing
source/generation, private 0700 output directory and verified cache path.
Use `-continuous-private -private-writes -private-field-partitions`,
`-window-profile=W128 -processing-chunk-records=32768`,
`-security-profile=P3 -file-profile=F3`, `-start-window=3`,
`-max-windows=0 -test-stop-after-windows=1`,
`-deferred-verified-clone`, and `-max-runtime=5m`.

Require:
- `FI DEFERRED ARTIFACT PUBLISHED window=3` (only says prepared before commit)
- `FI PRIVATE EXACT WINDOW STOP start=3 windows=1 last=3` (durable result)
- exactly 4 artifact/source/typed markers, 519,822 committed source records,
  4 detached Security field partitions, and zero SoR/Accepted rows
- signed checkpoint hashes for all 4 windows must match in all 3 marker tables
- the original verified-cache source files must remain byte-identical and
  unchanged, including on failure
- the private ready window's files must pass the independent full-hash
  `VerifyMaterializedBacklogWindow` replay proof

## Next gates

After the first real signed window succeeds, use fresh independent clones of
the identical seed for fail/rollback injection, restart-after-publication
verification, and a controlled 10-window A/B (same hardware, signed bytes,
PostgreSQL durability, K32/P3/F3, field partitions and distinct database
clones). Do not claim throughput gains from a filesystem-only probe or a
single window. Compare 10-window committed rate with the observed
2,300.2 committed records/sec control, plus CPU, WAL, PostgreSQL waits,
storage I/O, staging and typed stage profiles.

Never relax source/typed foreign keys, disable fsync, bypass signed batch
digests, or permit an Accepted journal insert.
