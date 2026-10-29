# FI development SoR COPY telemetry activation acceptance — October 28, 2026

## Environment and decision

FI is entirely in development. The shared development System of Record
(SoR) and ingestion service on `fi-backend-b` are not production systems.
The completed recovery run is not being rerun for this acceptance. The
purpose of this checkpoint is to document measured behavior, preserve the
previous executable, and activate per-COPY latency instrumentation without
changing PostgreSQL schema, receiver, source data, or custody settings.

Repository: `Iron-Signal-Systems/fi`.
Branch: `work/ingest-copy-call-latency-20261028`.
Acceptance source checkpoint: `d7913ce59ec293c14cc0214bba6460b54a9eda9c`.
The installed candidate was built at runtime source revision
`66c0767796dd1779a2fe8c04f324fde8f1731cfc`; the intervening
`d7913ce` checkpoint added tests and documentation, not runtime changes.
The previously installed executable reported Git revision `87cc57e`
with `vcs.modified=true`; its exact binary is retained for rollback.
The telemetry branch is 11 commits ahead of that reported revision.

## Controlled worker activation

Host: `fi-backend-b`; jail: `fi-ingest`.
Service: `fi_ingest_worker`; launcher:
`/usr/local/libexec/fi-ingest-worker-run`.
Worker path: `/usr/local/sbin/fi-ingest-worker`.

| Artifact | SHA-256 |
|---|---|
| Previous worker, retained as `/usr/local/sbin/fi-ingest-worker.rollback-20261028` | `54962a7d336d1cb749603ea5ad6b556144f096921ae3c9a1904d271173969430` |
| New worker, installed at `/usr/local/sbin/fi-ingest-worker` | `5604a0170052e39dbb88feb4074f272c852f44ae75dd2dd0d38762caa791b174` |

The staged executable was verified inside the jail, owned by
`root:wheel` with permissions `0555`. The original service was stopped,
and both `service fi_ingest_worker onestatus` and `pgrep` confirmed it
was no longer running. The original worker and rollback-copy checksums
matched before promotion. The staged worker was promoted within the
same jail directory and its installed checksum verified before starting.

After restart the service reported supervisor PID `33048` and worker
PID `33312`, configured with two workers against the development
PostgreSQL SoR endpoint `10.77.20.22:5432`.

## Observed post-activation acceptance

At 2026-10-28 19:40:54–19:40:55 UTC the restarted worker ingested and
accepted generation
`20261028T194017.987456300Z-c128840db8d9157b` from
`iss-fs-22b.iss.local`: 14 records committed; `INGEST PROFILE` total
719ms and `INGEST FINISH` elapsed 739ms.

The new `INGEST COPY LATENCY FILE` and
`INGEST COPY LATENCY SECURITY` messages appeared on this accepted
generation. Hash/file/metadata and security source/event/scope/field
COPY call counts were zero because this small generation contained no
rows for those profiled COPY paths. This proves logging is active but
**does not measure heavy-load per-call latency**.

At 19:43:22 UTC, `READY PLAN` for both sources reported
`markers=0 accepted=0 pending=0 conflict=0` on repeated polls.
The selected error-log search yielded no matching fatal, quarantine,
or ingestion-failure messages. These are bounded observations, not
a comprehensive absence-of-errors proof. Zero READY markers does not
independently establish complete source-to-SoR delivery.

## Authoritative development SoR verification

Read-only SQL against `fi.recorded_generation` at approximately
19:46 UTC returned:

| Source | Committed generations | Committed records | Latest ingested_at (UTC) |
|---|---:|---:|---|
| `iss-fs-22a.iss.local` | 2,312 | 37,706,103 | 2026-10-28 11:49:16.513693 |
| `iss-fs-22b.iss.local` | 1,639 | 58,217 | 2026-10-28 19:40:54.703833 |
| **Total** | **3,951** | **37,764,320** | — |

The final heavy recovered generation for `22a`,
`20261028T011951.495815100Z-a19bc3807d03ddfd`, was separately
verified in `fi.recorded_generation` with exactly **38,487 records**
and `ingested_at=2026-10-28 11:49:16.513693+00`.
Its performance profile was logged at 11:50:06 UTC. The different
timestamps do not invalidate the exact generation-and-count match.

## Final 22a pre-activation heavy-workload baseline

The final recovered `22a` generation above used the **previous**
worker, not the new per-call telemetry binary:

| Metric | Recorded result |
|---|---:|
| Source records | 38,487 |
| Total `INGEST PROFILE` | 50.429s |
| Projection | 40.085s |
| Hash COPY | 13,373 rows; 14 calls; 8.622s aggregate |
| Security events / scopes / fields | 25,050 / 25,050 / 375,750 |
| Security field COPY | 6.884s aggregate |
| DACL / SACL COPY | 71 calls; 1.772s aggregate |
| Transaction commit | 3ms |

Projection was approximately 79.5% of this generation-local total.
COPY times occur inside the measured stages and must not be summed
with stage totals. The pre-activation log gives aggregate COPY timings,
not per-call min/max, slow-bucket counts, or a proven root cause.

## Acceptance and remaining work

**Accepted:** development worker activation, unchanged rollback-copy
verification, service restart, actual SoR commit under the new worker,
both telemetry log families, and exact independent SoR verification
of the final recovered `22a` generation.

**Not accepted or established:** full source-to-SoR completeness,
post-activation heavy `22a` per-call latency, repeatable scaling
behavior, underlying PostgreSQL/ZFS wait causality, and full
collector-to-query throughput. The recovery run is complete; do not
manufacture another shared SoR backlog to obtain these measurements.

Next performance work belongs in isolated `fi-dev` fixtures:
file/hash/metadata-heavy signed-generation replay, repeated
security-heavy controls, PostgreSQL wait and resource telemetry, and
comparison of equivalent workloads. Existing isolated security replay
results are documented in
[COPY-LATENCY-SECURITY-REPLAY-20261028.md](COPY-LATENCY-SECURITY-REPLAY-20261028.md).

The development SoR worker is to remain running. No additional
database tuning, schema changes, receiver changes, or restart is
required by this acceptance record.

## Subsequent read-only worker observation — October 29, 2026, 01:01 UTC

From `fi-dev`, SSH to `jwood@192.168.1.218` and `jexec fi-ingest`
verified `fi_ingest_worker` running as supervisor PID 33048 and
`/usr/local/sbin/fi-ingest-worker` running as PID 33312 with two
configured workers. Both source READY plans repeatedly showed zero
pending markers during the sampled period, except for a transient
`iss-fs-22b.iss.local` pending marker at 01:00:22 UTC.

At 01:00:23 UTC, `iss-fs-22b.iss.local` generation
`20261029T010017.987461900Z-c8cb310b235007d0` reported accepted
with 11 of 11 records committed and `INGEST FINISH elapsed=421ms`.
`INGEST PROFILE total=409ms`, `source_sql=4ms`, `projection=3ms`,
`commit=1ms`, and `other=399ms`. Source batch COPY recorded 11
rows in one call (1ms), and security coverage COPY recorded 11
coverage observations, 44 policies and 11 roots (3ms).

The successful generation had no hash, file, metadata, Windows Security
event/scope/field, USN, or ACE COPY calls. It therefore establishes
that the worker and the new telemetry are active, **not** that heavy
COPY paths are performing well against the existing large SoR.
The selected `INGEST.*(error|failed|fatal|quarantine)` search returned
no matches in the current `daemon.log`; its scope was limited, and
no claim of complete error-free operation or delivery completeness is made.

**Next observation:** inspect the relevant current and rotated
`daemon.log` files for completed generations with nonzero COPY calls.
Only if representative activity is present should COPY latency be
correlated with PostgreSQL and FreeBSD/ZFS resource telemetry. Leave
worker deployment, receiver/custody, PostgreSQL and the completed
recovery backlog unchanged. The persistent issue being investigated is
intermittent heavy-load latency, not worker uptime.
