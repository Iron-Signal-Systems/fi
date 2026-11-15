# FI H16/W512 C220 baseline — TWO workers, TEN windows

**Active development experiment, not production.**
All work remains on `experiment/fi-candidate-a-w512-2g-20261113`.
Do not modify `main`. Do not start `fi_ingest_worker`, mutate the
authoritative FI-SoR, or bypass signed-source verification.

## Historical reference (old FreeBSD VM)

- W512, K32, P3/F3, TWO preparation workers, FOUR in-flight credits,
  ONE PostgreSQL writer.
- Signed two-window pilot, windows 1-2: **997,434 records / 312.630s
  = 3190.2 records/s**.
- Old VM PostgreSQL 18.6, fsync/synchronous_commit/full_page_writes on,
  max_wal_size=1GB, wal_buffers=4MB.
- The later W512 16-worker ten-window result (4,969,466 records) is NOT
  the two-worker baseline.

## Verified migration evidence, 2026-11-15

C220 authenticated private cache stage passed against the original FIGT and
immutable receipt: 8,399 batches, 15,140,785 records, 31 W512 windows.
First-window records 493,478; descriptor SHA-256
`ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319`.
The cache at `/home/jwood/fi-w512-c220-verified-cache` inside FI-dev is
receiver-authenticated and receipt-bound; it was NOT made by plain extraction.
The read-only FI custody/trust mounts were left in FI-dev by Stage 1.

## Stage 2: build original TWO-worker seed, W512 window 0

Fetch the *exact latest experiment branch commit* from GitHub into the
SEPARATE FI-dev checkout `/home/jwood/fi-w512-c220-stage` (never reset
the recovered `fi-deferred-experiment` worktree):

```sh
cd /home/jwood/fi-w512-c220-stage
git fetch --no-tags origin experiment/fi-candidate-a-w512-2g-20261113
git checkout --detach FETCH_HEAD
git rev-parse HEAD
```

Run on root@c220, passing the host copy of the GitHub-pinned runner:

```sh
seedrunner=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-stage/go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w512_c220_seed_host.sh
sh -n "$seedrunner" || exit 1
sh "$seedrunner" preflight || exit 1
sh "$seedrunner" h16
```

The final `FI EFFICIENCY FINISHED` message prints the disposable
`/home/jwood/fi-window-bench-w512-TIMESTAMP` seed location inside FI-dev,
and its host metrics path `/var/tmp/fi-window-chunks-h16-w512-seed-TIMESTAMP`.
Store that exact 16-character UTC TIMESTAMP for Stage 3. The seed writes
ONLY to a new isolated PostgreSQL 18.6 Unix-socket cluster in FI-dev
(port 55983, listen_addresses empty), then shuts that cluster down.
Historical signed source and cache are read-only. Do not run against fi-sor.

A passing seed must show `FI W512/2G FRESH SIGNED SEED ACCEPTED` with
493,478 records, 6,194,967 Security field rows and zero authoritative/Accepted
writes, plus exact descriptor and SHA evidence. Stop on any failure.

## Stage 2.5: **EXACT historical 2-window baseline — run FIRST**

This is now the first C220 measured baseline. Use the same original Candidate A
pilot workload as the former fi-backend-b benchmark: windows 1–2, **997,434**
signed records, TWO workers, FOUR credits, ONE SQL writer, K32, P3/F3, and
PostgreSQL 18.6 max_wal_size=1GB. Historical 2-window result:
**312.630s = 3,190.46 source records/s**.

The C220 seed completed successfully on Nov 15 at
`20261115T153532Z`: 493,478 records, 6,194,967 Security field rows,
one W512 typed/source/artifact checkpoint, historical descriptor matched,
zero authoritative/Accepted rows, and isolated PostgreSQL stopped cleanly.
Its signed seed evidence bundle SHA-256 is:
`52d45162719f56b26fa9cda739e746bfd7da488cfabd839c9b9f311196cd40cf`.

Update the **separate** FI-dev Git checkout to this document's latest branch commit
and retain the original historical Git objects already fetched there:

```sh
# Run ONLY inside SSH: jwood@fi-dev, NOT root@c220.
cd /home/jwood/fi-w512-c220-stage
git fetch --no-tags origin experiment/fi-candidate-a-w512-2g-20261113
git checkout --detach FETCH_HEAD
git rev-parse HEAD
```

Then, on the **C220 host**:

```sh
pilot=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-stage/go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w512_c220_p2_host.sh
seedstamp=20261115T153532Z
sh -n "$pilot" || exit 1
sh "$pilot" preflight "$seedstamp" || exit 1
sh "$pilot" h16 "$seedstamp"
```

The runner is an additive C220 adaptation of the exact historical TWO-WINDOW
pilot, **not** a shortened version of the ten-window runner. It verifies the
accepted seed evidence SHA and offline database state, enforces original
signed W0/W1/W2 descriptors, 997,434 additional records, exactly 431
byte-identical signed batch artifacts, two prep workers/four credits/one writer,
atomic SQL integrity, and zero Accepted/authoritative rows.

The two-window metric uses the recovery log's
`FI PRIVATE EXACT WINDOW STOP ... committed_window_time=...` rather than
source build, fresh seed creation or offline seed database-copy time.
Only after `FI C220 W512 TWO-WINDOW BASELINE ACCEPTED` and
`FI W512 SIGNED READBACK PASS` should the exact C220 records/sec rate be
compared with old backend's 3,190.46 source records/sec.

**Do not run Stage 3 ten-window test before accepting Stage 2.5.**

### 2026-11-15 C220 two-window trust-path correction

The first two-window private pilot attempted at `20261115T155117Z`
stopped before any window on the C220 host: the host-run FI recovery
executable tried to open the FI root CA at the installed receiver path
`/usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem`, which is valid inside
FI-dev but not populated on C220's host. The isolated seed remained intact,
and the private copied PostgreSQL cluster shut down cleanly.

The C220 two-window runner now uses a **second disposable build** from
the exact archived seed source. Before any SQL replay, the original
`generation_trust.go` source is compared byte-for-byte to historical
commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`; only the four
trust *filesystem path constants* are adapted for the host-run private
binary. The root CA, signing issuer, current receiver CRL, and enrolled
source config are all loaded from the read-only original C220 migrated
directories. There is NO global host trust installation, no change to
certificate/CRL validation semantics, no change to the original seed or
Git working tree, and no live FI ingestion. The private compiled recovery
binary's SHA is recorded in the baseline manifest. Compiler/tests are
executed before starting the disposable PostgreSQL clone.

The benchmark timer begins **after** this copy, compile, PostgreSQL clone
and relay setup; its measured interval remains the exact original W512
two-window replay (997,434 records, 2 workers, 4 credits, 1 writer).

Run the newly staged branch commit on jwood@fi-dev, then rerun
`sh "$pilot" preflight "$seedstamp"` on root@c220 before trying
`sh "$pilot" h16 "$seedstamp"` again. Do NOT reuse the failed private copy,
and do NOT modify `/usr/local/etc/fi` on the host.

## Stage 3: extended ten-window TWO-worker experiment (later)

Run on root@c220, with the EXACT timestamp printed by Stage 2:

```sh
tenrunner=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-stage/go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w512_c220_w2_ten_host.sh
seedstamp=YYYYMMDDTHHMMSSZ  # replace with Stage 2 timestamp
sh -n "$tenrunner" || exit 1
sh "$tenrunner" preflight "$seedstamp" || exit 1
sh "$tenrunner" h16 "$seedstamp"
```

Stage 3 copies only the OFFLINE seed data, runs in another private PostgreSQL
cluster, performs EXACTLY ten durable W512 windows indices 1..10,
and checks:

- Two workers / four credits / one ordered SQL writer (never sixteen).
- Signed source batches, immutable receipt/cache, SHA and manifest
  byte-identical readback for **2,292** batches across ten windows.
- Exactly **4,969,466** new source records, total private prefix
  **5,462,944**, and 11 SQL checkpoints including seed W0.
- Original W512 W0/W1/W2 descriptor SHA values exactly match the 2026-11-15
  validated C220 window plan.
- Atomic joined source/typed/verified-artifact writes, SQL cardinality and
  field-partition integrity, and 0 authoritative/Accepted rows.
- PostgreSQL 18.6 with durability on; max_wal_size=1GB and wal_buffers=4MB;
  collects WAL, I/O, checkpointer, CPU/memory and per-window timings.

**Stage 2 seed was accepted on C220. Stage 2.5 pilot and Stage 3 extended
experiment are staged source and have not been executed.** Run `sh -n`, inspect and pass the preflight before launching
each workload. Each runner fails closed and stops only its own private PG
cluster on exit. The original historical runner is unchanged.

The Stage 3 `FI W512 W2 TEN ACCEPTED` and
`FI W512 SIGNED READBACK PASS` markers are required before declaring a valid
C220 performance baseline.