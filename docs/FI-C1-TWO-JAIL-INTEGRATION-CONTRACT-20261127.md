# FI C1 — approved two-jail integration contract

Status: **approved design; development implementation; no unattended C220 activation or full-load acceptance claim**.  
Scope: C220 FreeBSD host, `fi-receiver` and `fi-sor` only.  
Approved 2026-11-27: preserve the tested C1 engine; change only the receiver input and real canonical destination.

## Exact jail boundaries and flow

```text
Windows senders
     |
     v
+-------------------- C220: jail fi-receiver --------------------+
| Original FIGT -> authenticate/validate -> immutable custody     |
|                           |                                     |
|                           +-> receipt-bound verified batch cache|
|                                  [receiver RW]                  |
+----------------------------------|------------------------------+
                                   |  work ZFS / nullfs RO
                                   v
+----------------------- C220: jail fi-sor ----------------------+
| SAME TESTED C1, NO REPLACEMENT ENGINE                          |
| P5 Preparation (unchanged) -> P6 Family Processing (unchanged) |
|        -> original shared adaptive 1..32 SQL pool               |
|        -> PostgreSQL 18 canonical fi relations                  |
|                     |                                           |
|                     +-- durable group COMMIT notifications --+  |
|                                                             |  |
| B: separate OS process, read-only PostgreSQL, original tested|
|    commit-ready group count/relational/USN checks, parallel  |
|    with A, independent from P5/P6 buffers                    |
|                           |                                  |
| Final generation proof: all groups + relational + USN        |
|                           |                                  |
| Exactly ONE canonical Accepted journal entry, AFTER all proof|
+--------------------------------------------------------------+
```

## Integration invariants

1. The receiver is the authority for original signed-custody validation, receipt, and receiver-verified batches. Do not authenticate or decompress the complete signed FIGT again inside production B.
2. Only one source input for real P5: receiver-verified cache, mounted **RW** in `fi-receiver`, **RO** in `fi-sor`. Original signed custody and receipt remain immutable, RO to SoR.
3. Reuse `privateC1ConsumeContinuousSigned`, original P5 pool, original P6 five-family buffers and original adaptive SQL pool, without per-batch/window reinitialization, group flushes or a 99% tail.
4. Reuse the tested `privateC1AsyncVerifyGroup` for read-only relational verification as each durably committed group becomes READY. B must not reparse all 15,140,785 original signed records or call `c1NativeBVerifyDataWithCommitment` on the real canonical path.
5. B is separate from A, read-only, with proof gated on complete independent group and final-generation relational/USN checks. B cannot write SQL or control P5/P6.
6. Real canonical publisher checks the full signed receiver batch ledger under SHARE locks and a final B group commitment. No second ordered scan/hash of all 15M `source_record` rows, no 49-table remapper, no added persistent staging DB.
7. Only two runtime jails. `fi-ingest` is retired and must not participate.
8. READY is a scheduling signal, not authentication. Retire it only after exactly one signed-generation Accepted and readback.
9. PostgreSQL is authoritative after commit. Interruption must fail closed; never auto-delete or blindly replay partial canonical writes.
10. The existing C220 process must never be replaced or interrupted by source edits.

## Implementation mapping

| Approved diagram element | Source |
| --- | --- |
| Receiver verified-cache publication | `go/internal/generationrecorder/verified_batch_cache.go`, `go/internal/transportreceiver/generation_cache_backfill_freebsd.go` |
| Receiver RW / SoR RO mounts | `go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_receiver_cache_mount_install.sh` |
| Receiver cache -> P5 | `go/internal/recordingest/c1_sor_verified_cache.go`, `c1_sor_local_runtime.go` |
| Tested continuous P5/P6 | `go/internal/recordingest/private_c1_continuous_signed_stream.go`, `private_p6_family_buffers.go` |
| Original adaptive SQL workers | `go/internal/recordingest/c1_sor_local_sql.go`, `private_c1_five_sql.go` |
| Tested asynchronous read-only B relational groups | `go/internal/recordingest/private_c1_async_verify.go`, `c1_sor_native_b_process.go`, `c1_sor_verified_cache.go` |
| One canonical Accepted, full group proof and locked ledger | `go/internal/recordingest/c1_sor_direct_canonical.go` |
| Unattended source queue | `go/internal/recordingest/c1_sor_local_ready.go`, `tools/deployment/freebsd/fi-c1-sor-local-run.sh` |

## Mandatory validation before C220 cutover

* Native FreeBSD builds and existing C1 Go tests PASS.
* Disposable real FreeBSD 15.1 / PostgreSQL 18 fixture proves real receiver-cache admission, early and final B proof in a separate process, correct final canonical Accepted, and rejection of forged or duplicate B evidence.
* Malformed cache, missing receipt, wrong batch digests, non-RO SoR mounts, early FINAL, missing READY, or incomplete relational proof all fail closed.
* A/B tests show commit-ready group proofs overlap P5/P6 ingestion; no live canonical B full-signed-archive replay or per-2,048-row SQL audits, and no final 15M-row ordered SHA pass.
* **Full C220 end-to-end** signed 8,399 batches / 15,140,785 records acceptance, a single Accepted, and full elapsed performance proof. The November 27 19,377.6 rec/s P5/P6 stage **does not** establish end-to-end acceptance.
* Only after full acceptance: install exact tested binary/configuration for normal READY service, verify receiver supervisor emits the verified cache and READY, prove clean restart/power-loss behavior, and explicitly enable unattended processing.

No C220 deployment or service enable may be described as complete solely because GitHub source or CI tests pass.
