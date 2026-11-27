# FI C1 — frozen development ingest baseline

**Decision date:** 2026-11-21  
**Status:** FI's **canonical ingest design for ongoing DEVELOPMENT**.  
**Measured branch:** `dev/c1-two-process-20261120`  
**Pinned passing full-backlog C1 implementation:** `f42ec639ffeccba31f2a2d4de82f20294c90cd40`

## Decision

C1 is the FI ingest architecture going forward. Earlier stage names refer only to
development history and are not names for separate active architectures.

**Freeze the measured algorithm and settings.** Continue engineering its normal
development-SoR integration and failure recovery; do not silently re-tune the
data path or alter what the benchmark measured.

## Frozen C1 processing path

1. The original verified receiver custody remains immutable. Read signed
   records continuously and in their original order; enforce original signed
   batch, receipt, SHA-256, framing, byte, record and ordinal rules.
2. Five independent adaptive preparation families: **Security, NTFS/File,
   Coverage, USN Dependency, Other**. Family preparation uses bounded
   **2–32** workers per family.
3. Five persistent per-family SQL-ready buffers. A family flushes on its
   own capacity, genuine dependency, 30 seconds of inactivity for that
   family, or true end of input. Neither signed batch nor 4 GiB reporting
   boundary flushes other families.
4. **Exactly one ordered SourceParent writer**. Dependent children wait for
   their exact committed SourceParent ACK.
5. **One shared adaptive SQL worker pool, maximum 32 connections**. Security
   candidate uses **8,192 rows/32 MiB** per family handoff,
   **65,536 rows/16 MiB** per field COPY call, and reusable event/scope row
   iterators. All other family parameters remain as measured. Keep
   relational constraints, indexes and durability enabled.
6. File/NTFS committed fences precede dependent USN SQL jobs. A bounded
   **64-handoff** FIFO schedules USN work; a single dispatcher submits one
   USN job at a time to the existing shared SQL pool.
7. PostgreSQL benchmark settings: `max_wal_size=8GB`,
   `wal_buffers=16MB`. Never infer that the full benchmark rate is a
   guaranteed rate on the real populated development SoR.
8. Independent read-only **process B** verifies group and whole-generation
   relational evidence. Completion requires every SQL ACK and both
   identity/count proof and B proof. Exclude verifier time from ingest-only
   throughput, but separately report full wall clock.

## Passing complete-generation development evidence

C220 full-backlog replay completed **2026-11-21**, private PostgreSQL clone,
source revision `f42ec639ffeccba31f2a2d4de82f20294c90cd40`.

| Measured result | Value |
| --- | ---: |
| Records newly processed after unchanged seed | 14,647,307 |
| Total original signed generation records independently verified | 15,140,785 |
| New source bytes | 63,081,148,153 |
| Reporting groups | 15 |
| Ingest-only elapsed seconds | 701.147 |
| **Ingest-only records/sec** | **20,890.49** |
| Peak SQL workers | 19/32 |
| SourceParent ordered writers | 1 |
| SourceParent SQL/COPY total | 11m27.438s / 11m8.488s |
| Independent B group / final verification | 148.087s / 1.381s |
| Whole-generation relational verification | PASS |
| Database publication and Accepted outcome | Disabled for benchmark |

Evidence on C220:
`/var/tmp/fi-c1-full-candidate.UhU0yzbV`
and `/var/tmp/fi-c1-full-backlog-4g-20261121T121128Z`.

## Next acceptance: existing populated development SoR

The next goal is **real development SoR acceptance of the entire signed
generation** while retaining millions of existing canonical records. Use the
*populated-SoR* identity/FK remapping and atomic Accepted path, not the
empty-SoR bootstrap and not a replacement database.

The repository already contains
`PromoteVerifiedBacklogToPopulatedSoR`, which remaps generated identity and
FK values, preserves natural NTFS identity sharing, and inserts the Accepted
journal event in one transaction after independent private verification.
Its publisher requires the verified private relational relations to reside
**on the same PostgreSQL cluster** as the canonical `fi` schema.

**Current gap:** The passing C1 runner deliberately creates a separate,
disposable PostgreSQL cluster and hard-requires a clone socket/PGDATA. Its
private results are not automatically present on `fi-sor-db`, and the
canonical tables have not been written by that test.

Acceptance engineering must (a) establish and verify the current real SoR
state using the read-only C220 preflight; (b) safely run this unchanged C1
pipeline with properly isolated *private* staging relations on the actual
development SoR's PostgreSQL cluster; (c) verify and remap the complete signed
generation into the already-populated canonical schema; (d) enforce journal,
rollback, retry and duplicate identity behavior; (e) measure preparation,
SQL/COPY, canonical promotion, independent B verification, WAL, CPU, memory,
index costs and total elapsed time **separately**. The user explicitly wants
a real SoR acceptance, not another clone benchmark.

No script that currently targets a clone should be pointed at the SoR by
changing its DSN. Require an audited distinct preflight gate and successful
integration/race/rollback tests before any canonical write. Do not disable
indexes/FKs/durability or discard existing SoR records to improve throughput.

## Result status

C1 **design and isolated full-generation benchmark: FROZEN/PASS**.
C1 **populated development SoR acceptance: PENDING** until the full
canonical Accepted proof succeeds. These are two separate test results,
not separate releases or products.
