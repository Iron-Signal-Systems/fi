# FI Phase 2 / Gate 2 Closeout

Closeout date: 2026-09-20

Phase 2 status: **COMPLETE — PASS**

Gate 2 status: **COMPLETE — PASS**

Phase 3 / Gate 3: **ACTIVE**

Repository baseline at closeout preparation:

```text
41906af fix: isolate governed-root USN scheduling
```

## Gate 2 invariant

Phase 2 is accepted against this rule:

> **An FI record either reaches durable backend custody or remains safely under
> source custody.**

The source does not retire an active generation until the sender validates an
exact `recorded` or `already_recorded` acknowledgement bound to the durable
transfer identity.

## Accepted transport boundary

The accepted Phase 2 transport model is:

```text
verified Phase 1 spool
        |
        v
freeze exact generation
        |
        v
canonical representation
        |
        v
zstd encoded generation
        |
        v
signed generation descriptor
        |
        v
FIGT transfer
        |
        v
durable receiver FIGT custody
        |
        v
semantic generation validation
        |
        v
immutable durable recorder receipt
        |
        v
recorded / already_recorded ACK
        |
        v
exact sender ACK validation
        |
        v
source generation retirement
        |
        v
bounded acknowledged-generation reclaim
```

The durable generation receipt is a Phase 2 custody/acknowledgement fact. It is
not the Phase 3 FI System of Record.

## Generation identity and replay decision

The final Phase 2 protocol does **not** use a separate monotonic transport
sequence number.

A generation descriptor cryptographically binds:

- source identity;
- generation identity;
- canonical version;
- encoding;
- artifact count;
- source byte count;
- canonical byte count and SHA-256; and
- encoded byte count and SHA-256.

The generation ID is a source-local durable identity used for ordering and
identity binding. It is not a monotonic security sequence.

For Gate 2, replay protection means:

- exact re-delivery of the same source/generation identity and exact bytes is
  idempotent and returns the duplicate-safe `already_recorded` outcome once
  durable receiver state already exists;
- the sender accepts that outcome only when it binds the exact transfer identity;
- the same identity with conflicting bytes fails closed rather than replacing or
  rewriting existing durable state; and
- lost acknowledgement is therefore safe: exact retransmission cannot create an
  ambiguous second history or authorize retirement of different bytes.

Accordingly, the earlier roadmap terms `sequencing` and `sequence conflict` are
retired as stale pre-generation terminology. The accepted contract is
**generation identity + exact byte/hash conflict detection**, not a separate
sequence protocol.

## Accepted bounds/resource interpretation

Gate 2 is not defined as an enumeration of every possible operating-system
failure reason.

The accepted resource-bound requirements are:

- sender and receiver enforce explicit canonical/encoded/manifest byte ceilings;
- oversized input is rejected before it can cross an invalid custody boundary;
- failures before valid acknowledgement do not authorize source retirement;
- retryable downstream unavailability accumulates source backlog rather than
  causing ambiguous loss; and
- restoration of the downstream path allows normal retry and drain.

A full receiver filesystem is therefore another reason durable receiver custody
cannot complete; from the sender custody contract it is equivalent to downstream
unavailability: no valid durable acknowledgement means no source retirement.
A separate live disk-full variant is not required to prove the already-accepted
custody invariant.

## Integrated and automated acceptance

Phase 2 automated/integrated coverage includes:

- generation construction and exact descriptor binding;
- canonical and encoded byte ceilings;
- signed generation verification;
- certificate and CRL authorization/revocation checks;
- source identity mismatch rejection;
- payload/canonical/hash mutation rejection;
- durable receiver custody;
- durable semantic recorder receipts;
- exact duplicate handling;
- conflicting same-identity handling;
- `recorded` and `already_recorded` acknowledgement validation;
- mismatched acknowledgement rejection;
- lost-acknowledgement retry;
- receiver startup discovery/recovery;
- sender startup recovery;
- source retirement only after exact acknowledgement;
- acknowledged-generation tombstone reclaim;
- interrupted reclaim recovery; and
- active-generation protection during reclaim.

## Live receiver-outage acceptance

The Server 2016 live environment exercised receiver unavailability while the
250K workload remained active.

Approximately 10-minute receiver outage:

```text
Source custody retained:    PASS
Automatic recovery/drain:   PASS
Manual sender repair:       NOT REQUIRED
```

Approximately one-hour receiver outage:

```text
Queued generations:         7
Queued records:             51,538
Source custody retained:    PASS
Exact receiver custody:     PASS
Automatic backlog drain:    PASS
Backlog custody after start: approximately 8m53s
Manual sender repair:       NOT REQUIRED
```

The seven retained generations later had exact FIGT/receipt transfer-hash
agreement.

## Measured source impact during backlog recovery

The one-hour outage campaign deliberately compared source-server telemetry while
the receiver was offline, while the backlog drained, and after recovery.

| Metric | Receiver offline | Backlog recovery | Post-recovery |
| --- | ---: | ---: | ---: |
| Host CPU average | 10.033% | 9.946% | 9.882% |
| Host CPU maximum | 11.57% | 11.45% | 11.64% |
| FICollector CPU average | 7.525% | 7.422% | 7.380% |
| Combined FI CPU average | 7.711% | 7.626% | 7.569% |
| Combined FI working set max | 129.97 MiB | 130.15 MiB | 124.23 MiB |
| Minimum host available RAM | 6527.98 MiB | 6526.46 MiB | 6514.17 MiB |
| Y: read average | 22.924 MiB/s | 21.302 MiB/s | 21.977 MiB/s |
| Y: read maximum | 46.711 MiB/s | 48.073 MiB/s | 44.985 MiB/s |
| Y: read latency average | 9.395 ms | 9.378 ms | 10.005 ms |
| Y: queue average | 0.617 | 0.717 | 0.706 |
| Y: queue maximum | 2 | 3 | 3 |
| Network total maximum | 0.004 MiB/s | 0.298 MiB/s | 0.297 MiB/s |

Backlog recovery was operationally similar to the surrounding 250K workload.
The recovery interval did not create a source-server CPU, memory, or
logical-volume recovery storm.

These values are measurements from the tested environment, not universal
production thresholds.

## Live sender-interruption acceptance

The generation sender was intentionally interrupted while the 250K workload was
active.

```text
Observed interruption:       approximately 10m31s
Source custody retained:     PASS
Scheduled sender recovery:   PASS
Recovered manifests:         2
Representative generation:   15,054 records
Durable ACK:                 recorded
Queues drained:              PASS
```

Later `already_recorded` processing remained duplicate-safe.

## Collector interruption and source continuity characterization

FICollector was deliberately terminated during the 250K campaign. FIUSNReader
remained running. The operation interruption remained explicit and the
independent telemetry monitor preserved before/down/after resource data.

After normal service restart, the source workload resumed without a sustained CPU
recovery surge.

This was source-runtime resilience characterization; the Phase 2 transport
custody rule remained unchanged.

### Post-closeout Windows Security scheduling remediation

Subsequent work on 2026-09-20 found that service-mode Windows Security collection
could be delayed behind multi-hour governed-root/current-state work. The Windows
Security source was moved to an independent sequential worker with bounded
EventRecordID windows, immediate backlog drain, durable spool verification before
checkpoint advancement, and Security-specific continuity-gap recovery.

The source-side remediation was live validated on the Server 2016 250K lab with
the Security log returned to 20 MiB, including successful selection and durable
local spooling of a controlled pair of Event ID 4719 records.

This source-runtime change does not alter the Gate 2 generation, custody,
acknowledgement, retry, replay, or retirement contract accepted by this closeout.
Full receiver/relational proof of the exact controlled 4719 pair is tracked under
Phase 3.

See `PHASE-2-WINDOWS-SECURITY-WORKER-VALIDATION.md`.

## Governed-source full-volume characterization

A separate governed NTFS root on T: was driven to zero free bytes.

The volume remained Healthy, and after the root-isolation remediation FI safely
recovered an outstanding USN backlog while the source volume still had zero free
bytes:

```text
Accepted checkpoint before recovery: 352
Live journal NextUSN:                274368
Accepted checkpoint after recovery:  274368
Volume free bytes during recovery:   0
```

This test characterized source collection/checkpoint behavior. It was not a
separate transport-custody requirement.

## Cross-root scheduler defect and remediation

The 250K campaign exposed a real process-global governed-root locking defect:
long configured work on one root could block the independent USN scheduler before
it serviced an unrelated root.

The remediation committed as `41906af` established:

- governed-root-scoped synchronization;
- same-root serialization;
- non-blocking same-root skip for the independent USN scheduler;
- fixed-cadence scheduling;
- independent root dispatch;
- separate supporting-SID state serialization; and
- spool recovery synchronization at the spool publication boundary.

Live proof used a Y: baseline lasting approximately 5h32m. During that exact
interval, 33 independent USN cycles completed on the expected approximately
10-minute cadence.

Each overlapping cycle reported:

```text
configured_roots=2
completed_roots=1
skipped_roots=1
failed_roots=0
```

The unrelated root remained serviceable while Y: held its same-root boundary.

Result:

```text
Cross-root independent USN scheduling: PASS
```

## 250K campaign disposition

The 250K generator created:

```text
250,000 payload files
20,000 directories
maximum depth 15
seed 7966157670060267791
```

Four deliberate manual semantic-validation probes were later introduced, giving
a live governed-tree count of 250,004 files.

The original strict clean 250K acceptance was intentionally interrupted during
fault injection and remains:

```text
INTERRUPTED — NOT A CLEAN PASS
```

That does not invalidate the retained resilience findings. The campaign is
preserved as engineering/resilience characterization rather than rewritten as a
clean scale result.

See:

- `PHASE-2-250K-RANDOM-NESTED-ONBOARDING-PLAN.md`
- `PHASE-2-250K-RANDOM-NESTED-ONBOARDING-REPORT.md`

## Gate 2 decision

The Gate 2 invariant is satisfied by the implemented, automated, integrated, and
live-tested transport behavior.

No ambiguous record loss was accepted.

Final decision:

```text
Phase 2 — Secure Record Transport:       COMPLETE — PASS
Gate 2 — Secure Durable Record Transfer: COMPLETE — PASS
Phase 3 — Ingest & Recorder:             ACTIVE
```
