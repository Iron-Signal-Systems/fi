# FI isolated file/hash COPY latency replay — October 28, 2026

## Scope and safety

The source candidate `go/internal/recordingest/copy_latency_file_replay_integration_test.go`
is a FreeBSD-only, explicitly tagged integration test of the actual
signed-generation, receiver-custody, receipt-validation and relational ingest
path. The file is not yet tracked by Git as of this documentation checkpoint;
the corresponding `fi-dev` candidate was SHA-256 verified before execution.

It uses only `$HOME/fi-m1-postgres-20261012`, the isolated M1 PostgreSQL 18
fixture on Unix socket port 55418. It requires
`FI_M1_ALLOW_ISOLATED_WRITES=1`, verifies the exact fixture root,
PG_VERSION, PostgreSQL identity, socket-only connectivity, roles, and the
49-table FI schema. Test custody is created under `t.TempDir`.
Cleanup removes the generated generation's relational descendants and its
source-owned NTFS fixtures; it verifies zero residual generation, volume,
and journal rows. Neither the shared development SoR nor its worker is used.

The synthetic workload contains unique, 16-byte regular-file content facts,
distinct MD5/SHA-1/SHA-256 digests, NTFS identities, one governed root,
file metadata, bounded content prefixes, default streams, security and SACL
observations without ACEs. It is intentionally not a replica of the
full historical development-SoR workload, including its ACE densities and
large database indexes.

## Initial verified execution

The test compiled successfully with
`go test -tags fi_copy_latency_replay_integration ./internal/recordingest -run '^$' -count=1`
and passed `go vet` with the same build tag.
`gofmt -l` returned no files.

Commands executed in `/home/jwood/src/fi/go`:

```sh
FI_M1_TEST_POSTGRES_ROOT="$HOME/fi-m1-postgres-20261012" \
FI_M1_ALLOW_ISOLATED_WRITES=1 \
FI_COPY_LATENCY_FILE_RECORDS=1024 \
go test -tags fi_copy_latency_replay_integration \
    ./internal/recordingest \
    -run '^TestCopyLatencyFileGenerationReplay$' -count=1 -v
```

The same command was repeated using
`FI_COPY_LATENCY_FILE_RECORDS=4096`. The configuration is bounded
to 1–4,096 synthetic source records per signed generation.

## Observed measurements

| Metric | 1,024 files | 4,096 files |
|---|---:|---:|
| Relationally accepted source records | 1,024 | 4,096 |
| Ingest duration (`INGEST PROFILE total`) | 2.255s | 3.045s |
| Ingest rate | 454.2 records/s | 1,345.2 records/s |
| Projection | 1.747s | 2.353s |
| Hash COPY rows / calls | 1,024 / 1 | 4,096 / 4 |
| Hash COPY total | 196ms | 235ms |
| Hash COPY min / max | 196ms / 196ms | 30ms / 95ms |
| File COPY calls | 1 | 4 |
| File COPY min / max | 534ms / 534ms | 91ms / 155ms |
| Metadata COPY calls | 1 | 4 |
| Metadata COPY min / max | 106ms / 106ms | 30ms / 78ms |
| Metadata stage total | 106ms | 189ms |
| NTFS identity stage | 341ms | 436ms |
| NTFS cache hits / misses | 3,072 / 0 | 12,288 / 0 |
| COPY calls >= 1s or >= 5s (all three tracked tables) | 0 | 0 |
| Transaction commit | 1ms | 2ms |
| Whole Go test elapsed (includes fixture work and cleanup) | 6.684s | 16.987s |

Each test verified exactly N file observations, metadata observations,
content hashes, content prefixes, default-stream rows, security observations,
and SACL observations for N source records. Both runs reported
`PASS: isolated file replay fixture rows cleaned` and a passing Go test.

The 4,096-record run handled four times the source records in approximately
1.35 times the ingestion duration (about 2.96 times the recorded ingestion
rate). Single runs are not a stable scaling claim; cache state and fixed
costs differ. In particular, Go test wall duration contains
certificate/signing, fixture construction, and cleanup work; do not use
it interchangeably with relational ingest duration.

COPY duration overlaps projection and stage timing; these measurements
must not be added together. The fixture has far smaller indexes and simpler
ACL/SACL data than the shared development SoR.

## Contrast with security replay and remaining evidence

In the separate 4,096-event security replay, 61,440 security fields
required 6.730 seconds of aggregate field COPY and 9.864 seconds of
projection; see [security replay](COPY-LATENCY-SECURITY-REPLAY-20261028.md).
That is a different row mix and is not a like-for-like throughput comparison.
It motivates investigation of security-field ingestion and PostgreSQL
waits rather than a conclusion that all COPY paths are slow.

**Accepted:** tagged test compilation and vet, the two isolated file replay
generations, expected foreign-key projections, nonzero per-call telemetry,
and cleanup. **Outstanding:** tracked source checkpoint, repeated measurements,
database wait/resource correlation, varied realistic source-record mixes,
and measurements at large-index scale. No tuning or root-cause conclusion
is claimed.
