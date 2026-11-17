# FI P7 — five real PostgreSQL family writers
## C220 first-run handoff, 2026-11-17

**Development only. Not a release. First C220 Go compilation, race tests, and
private SQL replay are still NOT completed.** Do not report this as an accepted
result until exact test receipts pass.

### Baselines (frozen)

- P5 persistent prep: **997,434 rows, 431 signed batches, 237.995 s,
  4,190.987 records/s**, single PostgreSQL writer; two W512 windows.
- P6 five relational modules with one SQL writer: **997,434 rows, 431
  signed batches, 247.626 s, 4,027.986 records/s**, same W512 windows.
- Both passed SQL integrity, signed manifests/byte-identical readback,
  13 typed parents, actual File validation reuse, and private shutdown.
- P7 changes the SQL execution model, **NOT** the W512 size, source seed,
  P5 dynamic 2..16 prep workers/family, or authoritative FI schema.

### P7 architecture

Each record family owns a distinct PostgreSQL connection and serialized
within-family queue:

| Family | Writer connection | Discipline |
|---|---|---|
| Security | Dedicated PG backend 1 | Security event, scopes/fields COPY |
| NTFS/File | Dedicated PG backend 2 | Original validated source token and full file children |
| Coverage | Dedicated PG backend 3 | Coverage/continuity SQL |
| USN/dependencies | Dedicated PG backend 4 | Source-ordered USN with File prerequisite fence |
| Other | Dedicated PG backend 5 | All other complete relational projectors |

A sixth connection is the original-signature, ordered `source_record`
parent ledger; the control connection performs committed source-window
staging and final publication/verification.

Every connection rejects a PostgreSQL backend unless all conditions hold:
private opt-in, expected role/database, exact disposable clone
`data_directory`, fsync=on, synchronous_commit=on and
full_page_writes=on. The private stage is **not** the authoritative SoR.

P7 first stages authenticated source envelopes and creates a committed
Security fields child partition. Each family then commits its own
relational staging transactions. After all five have acknowledged their
exact original source identities, the coordinator verifies source and
artifact digests, 13 typed parent coverage, existing nested SQL/FKs,
File source-validation/bulk reuse and M6.1 USN capture dependencies.
Only then does it insert the completed typed-window marker.

**Honest transaction model:** Five PostgreSQL connections cannot share
a normal atomic SQL transaction. Their partial staging transactions may
exist in the disposable clone if a writer fails; such a clone MUST be
discarded, not resumed or published. The final `typed_window` marker
is atomic and represents the all-family verified completion barrier.
No Accepted publication is ever authorized.

### Hard-review corrections since initial implementation

- Eliminate shared mutable NTFS validation counters between File and USN
  writers; each dedicated PostgreSQL family owns its own counter.
- Verify native File source/validated reuse against the real dedicated
  File SQL writer, not a synthetic or shared counter.
- Attach/validate Security fields partition **before** all final relational
  count and projection coverage queries, matching accepted P6.
- Keep original M6.1 in-memory USN capture verification **and** final SQL
  USN-capture completeness checks before publication.
- Require all signed batch read/count/byte/SHA verifications before
  printing an authenticated window receipt; do not reuse the obsolete
  one-writer hash-once message.
- Refuse completion until all five asynchronous SQL lanes have committed
  and the exact source/typed record identities reconcile.
- Validate distinct PostgreSQL backend process IDs for all five family
  writers plus the source ledger.
- Correct the patcher and run-manifest writer-count telemetry; no
  misleading claim that P7 is a one-writer run.
- Stage the modified P7-aware P6 completion barrier in the Go test-only
  overlay, not just the seven new P7 Go files.
- The 431 original signed files/manifests are byte-compared against the
  unmodified source cache, exactly as in accepted P5/P6.

### Frozen pins

- Branch: `experiment/fi-p6-five-concurrent-sql-writers-20261116`
- P7 source, patcher and regression tests:
  `6baf59d36bb3b4d51f4e26f5be54de178279de8f`
- P7 isolated Go/race test runner:
  `8b2ff76c6f97b22651c35378e5afe60cbfee608e`
- P7 two-window C220 runner:
  `ce11cb92b6667010dcc6144d3504f7df1321cbfa`
- Top-level first-run controller:
  `307b9cf8d478c28c86bfedcd98017ac984eac724`
- Signed original W512 seed: `20261115T153532Z`
- P5 archive SHA256:
  `7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a`
- P6 archive SHA256:
  `f8b28076c610f26bab85959db17d3ce3dae4d30753dfed622764f8da20edaa91`

### Safe C220 morning workflow

On `root@c220`, refresh only this branch into
`/home/jwood/fi-w512-c220-stage` inside the `fi-dev` jail, then
extract the controller from its **exact immutable Git SHA** to a unique
`/var/tmp` path. Run:

1. `sh "$controller" preflight 20261115T153532Z` — signed/cert/cache
   and source/patcher checks; **no PostgreSQL**.
2. `sh "$controller" tests 20261115T153532Z` — Go compile, targeted
   P7/P6 regression, race checks inside a separate disposable Go source
   directory; **no PostgreSQL**.
3. Only if both succeed:
   `sh "$controller" p7 20261115T153532Z` — repeats both gates before
   creating a private SQL clone; two authenticated W512 windows only.

The controller prevents running a P7 SQL benchmark when a single Go
test or source/provenance check fails. Its private test directories,
logs and tarball retain the failed candidate for diagnosis.

### Required first-acceptance receipt

- Full P5 worker pool start/stop and per-family totals.
- Exactly **six unique PostgreSQL backend IDs per window**:
  five typed family SQL writers + one ordered source ledger.
- Per family: committed records, SQL handoff count, elapsed SQL time,
  queue peaks; two windows and all five families (including zero-work).
- All **997,434** original signed records / 431 original signed
  batches / unchanged manifests; W512 1=499,052 and 2=498,382.
- Actual **104,830** File source validation tokens and **104,830**
  original bulk validation reuses; window1=52,519 and window2=52,311.
- Original source/typed/artifact chain, 13-kind relational parent
  completeness, full source/child checks, validated SQL constraints,
  M6.1 USN capture and attached Security field partitions.
- Zero authoritative writes, zero Accepted publications, clean
  private PostgreSQL shutdown and original seed unchanged.
- New genuine P7 two-window elapsed and records/s; compare
  P5 and P6 using identical source and settings.

### Known limit

No C220 execution or Go compile result is available yet. The source,
pin, gate and concurrency checks were audited statically, but C220 is
the only validated execution environment for the optimized historical
seed. **Stop on the first Go/race, source, SQL, FK or signed-data error.
Never relax a check to print PASS.** Do not proceed to a 10-window
P5/P6/P7 performance test until P7's first two-window correctness gate
passes with complete receipts.
