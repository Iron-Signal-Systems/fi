# FI P7 first C220 test — clone settings permission failure

**2026-11-17, first P7 private two-window test. Status: FAIL before any
window-1 typed SQL replay. Not a P7 correctness acceptance.**

## Executed source and verified gates

- Top-level controller pinned at
  `307b9cf8d478c28c86bfedcd98017ac984eac724`.
- P7 source/overlay `6baf59d36bb3b4d51f4e26f5be54de178279de8f`.
- Private PostgreSQL clone:
  `/home/jwood/fi-window-bench-w512-family-p3-20261117T071335Z/clone-w512-2g/data`
  inside `fi-dev`, jail host path under
  `/fast/jails/roots/fi-dev/`.
- Run output:
  `/var/tmp/fi-window-chunks-family-p3-20261117T071335Z`.
- C220 passed: original signed custody, P5 accepted source, exact source
  overlay, Go compile and `TestPrivateP7`, Go race tests,
  original `TestPrivateP6` regression, five SQL module compilation,
  physical seed clone startup and private auth relay.
- No typed P7 rows committed; no W512 performance result.
- Shutdown reported `server stopped`, `exit=1`,
  `original_seed_unchanged=true`.

## Real failure

The first P7 source verification executed as ordinary SQL user
`fi_ingest` and attempted to read the protected PostgreSQL setting
`current_setting('data_directory')`. PostgreSQL 18.6 correctly returned:

```text
ERROR: permission denied to examine "data_directory" (SQLSTATE 42501)
```

This came from the fail-closed `privateP7VerifyCloneConnection`
guard in `private_p7_postgres_writers.go`. It did not reach the five
family transactions, the 13-kind graph, or FileObservation readback.
Do not interpret the result as an ingest slowdown or data corruption.

## Correction — private clone only

Preserve P7's exact physical `data_directory` guard.

After the runner copies the original signed PostgreSQL seed, starts
its own clone on its private UNIX socket, and BEFORE opening the five
writer backends, it now:

1. Verifies that the expected private clone is running, with PostgreSQL
   version 18 and its exact private socket and data path.
2. Connects to the newly started private clone over that private UNIX
   socket as the existing `jwood` PostgreSQL bootstrap owner; requires
   `current_user=jwood`, `rolsuper=true`, and
   `pg_is_in_recovery()=false`.
3. Reads the actual `data_directory` as that bootstrap role and
   requires an exact match to the copied private-clone path.
4. Only **inside that freshly copied clone**, runs
   `GRANT pg_read_all_settings TO fi_ingest`.
5. Reconnects as `fi_ingest` over the same private UNIX socket
   and requires successful reading of the identical `data_directory`.
6. Logs `FI P7 PRIVATE CLONE SETTINGS ACCESS PASS` only after all
   proofs. If any check fails, it stops before beginning W512 replay.

PostgreSQL 18 documents `pg_read_all_settings` as READ access to all
configuration variables, including restricted superuser-only settings.
This does not grant PostgreSQL superuser, database-table read-all/write-all,
server-file access, or role management privileges. It *does* expose
all settings to `fi_ingest` **in the isolated copied PostgreSQL cluster**,
and thus is intentionally not configured on the authoritative FI SoR.

## New immutable pins

- Source+patcher/tests: unchanged
  `6baf59d36bb3b4d51f4e26f5be54de178279de8f`.
- No-PostgreSQL compiler/race runner: unchanged
  `8b2ff76c6f97b22651c35378e5afe60cbfee608e`.
- Fixed clone-only SQL host runner:
  `e396533c80a460b5b1d4d8a11ec99c4136ac358b`.
- Top-level acceptance controller, repinned to fixed runner:
  `9fdf8c61d05e40fe9e90d3a615a7ded9d06c0288`.
- Original signed source seed: `20261115T153532Z`.
- Accepted P5: 4,190.987 records/sec on 997,434 signed rows.
- Accepted P6: 4,027.986 records/sec on the same rows.

## Next test gate

Run the new controller as `root@c220` on exactly the signed seed.
It repeats preflight, Go/race/P6 regression tests and the private
PG18 clone creation; it stops if its privileged private socket
bootstrap is not available. **The private-identity check is not
removed, and there is no SQL path to the authoritative SoR.**

Even after settings proof passes, P7 is NOT accepted until real five
PostgreSQL family backends finish both W512 windows with all 997,434
source/typed records, 431 signed batches, native File validation/reuse,
13-kind relational and FK coverage, M6.1 USN capture, exact security
field children, atomic typed marker and clean private shutdown.

## Second C220 attempt — 2026-11-17 07:22 UTC; role assumption corrected

The SQLSTATE 42501 correction passed every preflight, Go compilation,
Go race test, P6 regression test, and started the private clone. It stopped
at the private settings bootstrap with:

```text
psql: FATAL: role "jwood" does not exist
FI P7 PRIVATE GRANT STOP: clone owner cannot verify PostgreSQL data_directory
```

**Root cause:** `jwood` is the FreeBSD `fi-dev` Unix user that owns and
starts the disposable PostgreSQL postmaster. It is NOT necessarily a
PostgreSQL login role. The bootstrap code incorrectly assumed the Unix
account name was also the PostgreSQL superuser name.

**Fix:** Query `pg_catalog.pg_roles` read-only from the existing
`fi_ingest` private-socket connection to enumerate login-capable
superuser roles. Require **exactly one** discovered role, safe SQL
identifier syntax, and no `pg_` internal role. Connect to the same
private socket as that discovered SQL role, verify its `rolsuper` and
`pg_is_in_recovery=false`, and require its reported physical
`data_directory` to equal the newly copied private seed. Only then
grant `pg_read_all_settings` to `fi_ingest` within that disposable
clone and recheck the physical directory as `fi_ingest`.

The corrected runner refuses ambiguous or unauthenticated bootstrap
identities. It never falls back to changing the authoritative SoR,
granting superuser to `fi_ingest`, or bypassing the data-directory gate.

### Second corrected immutable pins

- Original source/pipeline remains
  `6baf59d36bb3b4d51f4e26f5be54de178279de8f`.
- New role-discovery private SQL runner:
  `b419c06e926c892d2ca1af83fc2edb3b46c9e36e`.
- New first-run controller:
  `d133b34ac0ecefd922a756aa9ba96463364d046e`.
- Previously attempted controllers `307b9cf8d478c28c86bfedcd98017ac984eac724`
  and `9fdf8c61d05e40fe9e90d3a615a7ded9d06c0288`
  are superseded for P7 testing.
- C220 second failed output:
  `/var/tmp/fi-window-chunks-family-p3-20261117T072232Z`.
- C220 private clone stopped cleanly; original signed source unchanged.
- **Still no P7 two-window acceptance or performance data.**

## Third C220 attempt — 2026-11-17 07:28 UTC: deferred artifact copy boundary

The latest role-discovery controller successfully passed all Go, race
and P6 regression tests, detected the actual private PostgreSQL
superuser, granted the configuration READ privilege only in the cloned
cluster, and emitted:

```text
FI P7 PRIVATE CLONE SETTINGS ACCESS PASS
```

Its first signed source stage then STOPPED **before any W512 typed SQL**:

```text
FI P7: authenticated durable source pre-stage:
FI backlog source stage: source copy verification failed:
lstat .../receipt-29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed/window-00000001:
no such file or directory
```

The accepted W512 C220 loader runs `-deferred-verified-clone`: it
can complete an authenticated artifact marker while postponing the
physical 0700 signed-window directory. The original joined source+typed
transaction tolerates that handoff; new P7 calls
`StageVerifiedBacklogSourceWindow` directly, and the source stage
requires physical, exact-byte-verified `batch-*.data` and
`batch-*.manifest` files.

### Correction

The P7-only source path now calls the underlying
`materializeBacklogWindow(...,reuseStage=false)` using the already
authenticated cache's original batch DataPaths. It requires the exact
receipt/window directory, rehashes every copied original signed
manifest and data payload via `VerifyMaterializedBacklogWindow`,
then invokes the durable SQL source stage. It never bypasses
source-file metadata, SHA validation, original parent/child or FK
checks and never writes to or modifies the shared verified cache.

A new source-only `TestPrivateP7DeferredVerifiedCacheCreatesPhysicalSignedWindow`
regression reproduces the missing-directory condition, verifies the
generated immutable signed window, requires safe re-verification,
rejects tampered bytes and changed descriptor identity and confirms
the source is unchanged. This test runs under the P7 Go and race gates.

The final M6.1 USN in-memory capture check was also moved to **after
all five SQL writer acknowledgments and before typed publication**, so
USN state is not read concurrently with the asynchronous USN writer.

The C220 runner now requires two explicit physical source proof
receipts with original window row counts and total 431 signed batches;
it archives their metrics alongside existing SQL/FK and byte-identical
readback receipts.

The former staging-only failure output:
`/var/tmp/fi-window-chunks-family-p3-20261117T072810Z`.
The initial original cache and accepted P5/P6 controls are unchanged.

### Corrected source and regression gate

- Source and native regression fixture:
  `546c6a1e1a12f30bb0f54c70809dee978afea5f3`
- Updated P7 compile/race runner:
  `ec9f99bdf2ca82717ade94ae0d814d81c8bd99db`
- Clean, audited P7 SQL runner with physical window evidence:
  `93e27858d93b22acc2e5ab810ffdae86a315acf1`

The fresh compiled C220 test and five-connection SQL replay have
**not yet executed** against this third correction. P7 is still
unaccepted and has no measured throughput.

## Fourth C220 attempt — 2026-11-17 07:41 UTC: deferred artifact marker absent

The four-stage private C220 trial using controller
`2c6fa62bccb49f5b9cf6dc074ddd9decdb385f8b`
passed authentication, source/pin preflight, P7 compiler/unit/race tests,
P6 regression, private PostgreSQL role discovery and `data_directory`
proof, and successfully materialized and verified W512 index 1:

```text
FI P7 PRIVATE MATERIALIZED WINDOW VERIFIED index=1 signed_batches=216 records=499052 bytes=2146829460 original_cache_unchanged=true
```

It then stopped **before signed source-row SQL staging or any five-writer
typed ingestion**:

```text
FI P7: authenticated durable source pre-stage:
FI backlog source stage: verified-artifact checkpoint missing or invalid:
no rows in result set
```

Reason: the accepted `-deferred-verified-clone` joined-transaction
recovery can defer the separate
`fi_recovery.verified_artifact_window` checkpoint. P7 had introduced
physical materialization and then directly called
`StageVerifiedBacklogSourceWindow`, which correctly rejects the
missing committed artifact checkpoint.

### Mandatory sequence correction (clone only)

The P7 entry now requires ALL THREE stages in this exact order:

1. `privateP7MaterializeSignedWindow` — private 0700 window, original
   SHA-256 manifest/data copy and verification;
2. `RecordVerifiedBacklogArtifactWindow` — independently committed
   signed `fi_recovery.verified_artifact_window` checkpoint. This
   function independently re-verifies source bytes, checks immutable
   original transfer/receipt/descriptor identity, enforces exact
   previous checkpoint continuity, and commits before returning;
3. `StageVerifiedBacklogSourceWindow` — independently verifies the
   artifact checkpoint, scans and hashes every signed source record,
   inserts `fi_recovery.pending_source_record`, verifies all SQL source
   rows before committing `fi_recovery.source_window`.

Only then may `privateP7PrepareCommittedWindow` create its Security
field partition and open five separate typed PostgreSQL writers.
The final W512 completion marker remains a separate verified transaction.

The runner explicitly checks the three chronological receipts for BOTH
windows, requiring 216+215=431 signed batches and 499,052+498,382=
997,434 records. It preserves and archives
`P7_MATERIALIZED_WINDOWS.txt` and `P7_SOURCE_CHAIN.txt`; it fails
closed if a checkpoint is missing, out of order or duplicated.

### Current pinned correction

- Exact source with physical+artifact+source chain:
  `03881677b33fe428154157fe07e8a7ec235d63c8`
- Go / Go-race / accepted P6 regression runner:
  `4e874be099e7d8b0fb1df3b198a191f27e096ebc`
- Private five SQL writer runner with chronological ledger acceptance:
  `080a74cafe2b5e4575e5ca913b48bf79ef58ba81`
- Top-level controller:
  `b7737a4df3a72ab40e365371a782b0cdf755afe2`

This corrected source has **not yet completed** the first C220 replay,
and neither 2-window P7 correctness nor throughput is accepted.
The authoritative SoR and signed cache remain unchanged.
