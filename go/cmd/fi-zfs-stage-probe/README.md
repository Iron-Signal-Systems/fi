# FI ZFS copy-on-write staging probe (development only)

This standalone program is NOT wired into File Intelligence ingestion. It reads
already verified, immutable cache artifacts and writes only to a unique 0700
scratch directory on the same filesystem. It deletes those scratch files when
finished. It does not alter PostgreSQL, the custody archive, recorded receipts,
source cache, or private checkpoint chain.

The probe compares:
1. Existing-style streaming copy with SHA-256 and fsync (one pass).
2. FreeBSD 15 `copy_file_range(2)` with the clone-required flag, followed by
   independent destination SHA-256 and fsync.

The clone-required flag is essential: an ordinary `copy_file_range` request
may silently fall back to byte-copy. When cloning cannot be performed this
probe FAILS rather than claiming a false speedup.

On fi-dev (use local changes exactly as currently preserved):

```sh
cd /home/jwood/src/fi
git fetch origin
git merge --ff-only origin/work/fi-joined-private-performance-20261102
cd go
go build -o /home/jwood/fi-zfs-stage-probe ./cmd/fi-zfs-stage-probe
```

On the FreeBSD host (not inside the jail):

```sh
/usr/local/jails/containers/fi-dev/home/jwood/fi-zfs-stage-probe \
 -cache-root=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache \
 -scratch-parent=/var/tmp -start-batch=158 -count=57
zpool list -o name,bcloneused,bclonesaved,bcloneratio zroot
```

The 57 batches are the measured W128 window 4 (after the three-window seed).
The source SHA-256 must match each verified manifest before a test begins;
both output files are independently checked against that SHA-256. No part of
the benchmark is accepted as a durable FI checkpoint or a production change.

This probe intentionally omits per-directory fsync, manifest publication and
the existing recovery ledger; the result estimates bulk-data staging savings
only. A full change must retain the existing atomic publication, write-path
restrictions, manifest hashing, crash recovery, and fail-closed behavior.

Avoid running the probe simultaneously with other FI benchmarks.
