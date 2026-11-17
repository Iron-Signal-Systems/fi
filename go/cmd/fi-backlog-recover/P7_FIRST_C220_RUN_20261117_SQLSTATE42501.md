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
