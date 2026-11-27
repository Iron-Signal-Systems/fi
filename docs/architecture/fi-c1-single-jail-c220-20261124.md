# FI C1 — single-jail fi-sor processing (C220 development)

**Decision:** Retire the old `fi-ingest` jail from the FI processing topology.
`fi-receiver` remains the sole owner of original signed generation custody.
`fi-sor` performs complete C1 preparation, buffering, relational SQL,
independent verification B, and canonical Accepted publication.

## Architecture and boundaries

```text
 fi-receiver
  original signed custody (immutable), recorded receipts (immutable)
  READY scheduling markers (only mutable receiver-owned hint)
       |
       | host nullfs, original generation + recorded receipts READ ONLY
       | READY scheduling mount RW for removal after Accepted only
       v
 fi-sor (the ONLY C1 processing jail)
  1. Read signed original receipts/custody with installed trust/CRL
  2. Extract receiver-verified batch contents to disposable fast-pool
     fi-sor-local scratch; it is NOT new authoritative custody
  3. ONE continuous original C1 P5 reader with 5 dynamic prep lanes (2..32)
  4. ONE persistent original P6 SourceParent buffer + 5 family buffers
  5. ONE ordered PostgreSQL parent writer + adaptive shared 1..32 SQL
     family workers, using existing fi-c1-pending full relational schema
  6. Original independent B verifier in a separate fi-sor OS process,
     read-only SQL, reads original receiver custody
  7. Original governed atomic canonical remap, Accepted journal, independent
     readback; Pending is retired ONLY after canonical acceptance
  8. Retire READY scheduling marker ONLY after Accepted proof
       |
       v
 fi-sor PostgreSQL 18 on fast pool, Unix socket ONLY
```

No `fi-ingest` jail, no inter-jail TCP/TLS, no 4 GiB shared-RAM handoff,
no per-buffer wire ACK or duplicate P5 processing path. Signed batches,
reporting groups, preparation workers, source/typed SQL order, original five
family SQL modules, security field COPY, USN dependency queue, independent B
and authoritative acceptance remain unchanged.

The executable for this architecture is `fi-c1-sor-local` (FreeBSD-only,
`fi_c1_sor_dev` build). It is distinct from the obsolete two-jail
`fi-c1-sor-worker` service, which must not be running simultaneously.

## Ground truth baseline

The C220 private benchmark on 2026-11-21 processed 14,647,307 records at
**20,482.34 records/sec** over 715.119 seconds of INGEST time, with 32
permitted shared PostgreSQL workers and 22 peak workers. Independent B proof
and canonical publication were EXCLUDED from this ingest-only clock. Source
is signed receiver backlog, not a fabricated synthetic event stream.

**The new jail architecture is NOT accepted merely because it compiles or
because a generation becomes canonical.** On an isolated disposable PostgreSQL
18 clone and the *same* immutable signed data, measure separately:

- Original custody read/verified scratch extraction, wall time and bytes.
- Post-extraction original P5 + P6 + PostgreSQL commit-drain ingest wall.
- Independent B verification elapsed and parallel overlap.
- Canonical Accepted publication/retirement elapsed.
- End-to-end receiver-custody-to-Accepted wall and effective rec/sec.
- Peak SQL worker count, Security child COPY throughput, SourceParent wait,
  USN File dependency fences, SQL checkpoint/WAL/CPU waits.

This comparison is a release gate. Do not claim 20,482 rec/sec on the new
path until a comparable real run demonstrates it.

## Safety and operational gates

1. **Do not destroy, move, rewrite, recompress or delete** any of the 8,399
   original signed receiver batches, recorded receipts, or canonical SoR.
2. Do not reset existing `fi` or `fi_c1_pending`. A Pending generation
   cannot be overwritten; explicit replay requires audited identical signed
   source and read-only relational prefix reconciliation.
3. Old `fi-ingest` jail may be stopped with
   `fi_c1_c220_stop_obsolete_ingest_jail.sh --stop`; that script never
   deletes a jail root or edits boot settings.
4. Audit persistent `/etc/jail.conf.d/fi-ingest.conf`, `jail_list`, host
   nullfs and ram fstab before retiring the old boot entry and RAM mounts.
   The actual host state must be reviewed; do not assume it.
5. Verify `fi-sor` has original signed generation and recorded receipts
   mounted **read-only**, separate independent verifier trust, and **only**
   READY scheduling marker directory writable. Never make signed custody RW.
6. Provision fi-sor-owned local disposable **fast pool** staging with capacity
   for one full unpacked generation plus PostgreSQL free-space safety margin.
   The original custody is a compressed durable transport container; the
   existing C1 preparer uses verified JSONL batches on the local SSD, as in
   the proven clone benchmark. The extraction time is measured separately.
7. Build and run as the existing unprivileged fi-sor service account. Only
   local PostgreSQL Unix socket roles, no remote DSN.
8. Start with `--preflight` only; do not enable continuous ingestion.
   Run the first full signed replay only against a disposable isolated SoR
   clone (no already-Accepted generation replays against live canonical).
9. Pass correctness, cryptographic readback, crash/replay tests, 15M benchmark
   and performance parity before retiring old persistent jail resources.
10. Never delete or truncate any signed custody or Pending SQL automatically.

The single-jail code is DEVELOPMENT pending the real C220 acceptance run.
