# FI Phase 2 — 250K Randomized Nested Onboarding & Resilience Engineering Report

Report date: 2026-09-20

Repository at report preparation:

```text
41906af fix: isolate governed-root USN scheduling
```

## Status

**CAMPAIGN COMPLETE AS ENGINEERING / RESILIENCE CHARACTERIZATION**

**ORIGINAL CLEAN 250K ACCEPTANCE RUN: INTERRUPTED — NOT A PASS**

The run began as the planned post-Gate-1 250K randomized nested onboarding
campaign. It then intentionally became a resilience campaign through receiver
outage, sender interruption, collector interruption, multi-root activation,
governed-volume exhaustion, and a live cross-root scheduler defect/remediation
exercise. The interrupted clean acceptance run is not rewritten as a success.

## Dataset

```text
Payload-file target: 250,000
Directories:         20,000
Maximum depth:       15
Seed decimal:        7966167548685396239
Seed hexadecimal:    0x6E8D7A31C4B2190F
Generators:          4
```

A later live enumeration before the collector fault observed 250,004 files and
approximately 393.921 GiB in the governed tree.

The generator itself created exactly **250,000 campaign payload files**. The
additional four files were deliberately introduced during the active onboarding
campaign as **manual semantic-validation probes**. They were not generator
output and they were not incidental test debris.

### Manual semantic-validation probes

The four manually introduced files were designed to exercise FI's distinction
between NTFS object identity, path/parent relationship, filename, content state,
and historical change.

1. `Y:\FI-Lab\What does it matter.txt`

   This was the original root-level probe. It was introduced during the active
   baseline and then modified **in place**. The purpose was to verify that FI
   preserves the same underlying NTFS object identity while recording later
   content state as a new historical observation rather than treating the
   modified bytes as a new file object.

2. `Y:\FI-Lab\d014991\What does it matter.txt`

   This was a copy of the edited root probe placed under a different parent.
   It intentionally had the same filename and the same resulting content as the
   first probe, but it was a different NTFS object with its own file reference,
   parent relationship, and path.

3. `Y:\FI-Lab\d011F39\d022012\d032503\What does it matter.txt`

   This was another copy of the same edited content placed deeper in the
   governed tree. Together with probes 1 and 2, it tested that matching filename
   and matching content hash do not collapse separate NTFS objects into one FI
   identity.

4. `Y:\FI-Lab\d010BF6\d020D0F\d034743\What does it matter.txt`

   This probe deliberately reused the same filename while carrying different
   content. Its purpose was to verify that FI does not treat filename equality
   as object identity or content equality.

The first three probes ultimately shared this content SHA-256:

```text
8A455F263B740AE0F48253B0C33EF1DFA8BC99FE95748D482B7F1D03FAAD7DD0
```

The fourth probe used different content:

```text
SHA256=5E05E29D4BE6E4305F704AC93E3E7E810F7A0C4FBEC36205EA916A505088AD8
Length=33,120 bytes
```

These probes exercised three different FI semantic cases:

```text
same NTFS object
    + later content state
    = same object identity, new historical observation

same filename + same content
    + different FRN / parent / path
    = different file objects

same filename + different content
    + different FRN / parent / path
    = different file objects and different content state
```

Accordingly, the later count of **250,004** is intentional:

```text
250,000 generated payload files
      + 4 manual semantic-validation probes
      = 250,004 observed files
```

Byte accounting was not fully reconciled during the campaign. An earlier
deterministic base total was 421,910,556,433 bytes (about 392.935 GiB), while a
later live enumeration reported about 393.921 GiB. This report therefore does
not claim one reconciled exact generated-byte total.

## Environment

```text
Windows source: ISS-FS-01 / Windows Server 2016
Primary root:   Y:\FI-Lab
FI state/spool: Y:\FI-Gate1
Receiver:       fi-receiver-a / 192.168.1.119:8443
Receiver FIGT:  /var/lib/fi/custody/generation
Receipts:       /var/lib/fi/custody/recorded
Collector:      ISS\gFI-FS01$
USN helper:     ISS\gFI-USN-FS01$
```

Initial installed binaries included:

```text
fi.exe
781C4D0A940F9C247EF8DAF4D944D6C439FB22513FAEB84289692DB39013A7F7

fi-usn.exe
82C261FD082630B7455654E5FF98C5B39E529BD1AA94019D96EB1B5B805AF92A

fi-sender.exe
EBAD839B348DD969EECCFD80C44915015C4E30A8A4D41114D8EBC13C267753C6
```

The root-isolation remediation test binary was:

```text
81350B7236FC1DC9E26E90E803C6CDD38EE61A155409016EA34642735680805E
```

and its source was committed/pushed as `41906af`.

## Original run disposition

FI started at `2026-09-19T14:29:30.987566Z`; the original Y baseline began at
`2026-09-19T14:29:31.015925900Z`.

The clean acceptance harness was later interrupted by the deliberate collector
termination. Therefore:

```text
Original clean 250K acceptance: INTERRUPTED
Strict acceptance:             NOT A PASS
```

The independent telemetry run survived and was retained.

## Source-host impact around collector interruption

Before the deliberate collector stop:

```text
Host CPU avg/max:          9.104% / 15%
Available memory:          ~6.4 GiB
Y: read avg/max:           20.041 / 55.227 MiB/s
Y: write avg:              0.063 MiB/s
Y: queue avg/max:          0.562 / 2
FI CPU avg/max:            7.19% / 12.5% of host
FI working set:            ~50.99 MiB
```

While FICollector was down, host CPU averaged about 1.75% and Y: read activity
fell to zero. After recovery, host CPU averaged about 8.661%, FI CPU about
7.47%, and no recovery CPU storm was observed.

## Receiver outage results

A roughly 10-minute receiver outage retained source custody and drained after
receiver recovery without manual sender repair.

A roughly one-hour receiver outage ran from approximately `16:45:49Z` to
`17:45:51Z`. During it:

```text
Generations retained: 7
Records retained:     51,538
```

All seven later had exact FIGT/receipt transfer-hash agreement. Backlog reached
receiver custody within approximately 8m53s after receiver startup, with no
manual sender intervention.

```text
10-minute receiver outage: PASS
60-minute receiver outage: PASS
Source custody retained:   PASS
Automatic backlog drain:   PASS
```

## Measured source impact during one-hour receiver-outage recovery

The campaign intentionally monitored CPU, memory, logical-volume I/O, queue
depth, sender activity, and network traffic before, during, and after backlog
recovery. This was a first-class part of the test: the question was not only
whether FI could recover the backlog, but whether recovery would materially
hammer `ISS-FS-01`.

The three comparison windows contained 128 samples while the receiver was
offline, 106 samples during backlog recovery, and 119 samples after recovery.

| Metric | Receiver offline | Backlog recovery | Post-recovery |
| --- | ---: | ---: | ---: |
| Host CPU average | 10.033% | 9.946% | 9.882% |
| Host CPU maximum | 11.57% | 11.45% | 11.64% |
| FICollector CPU average | 7.525% | 7.422% | 7.380% |
| FICollector CPU maximum | 9.21% | 8.72% | 8.92% |
| FIUSNReader CPU average | 0.161% | 0.158% | 0.170% |
| FIUSNReader CPU maximum | 0.39% | 0.43% | 0.47% |
| Sender CPU average | 0.026% | 0.048% | 0.020% |
| Sender CPU maximum | 0.89% | 1.05% | 1.55% |
| Combined FI CPU average | 7.711% | 7.626% | 7.569% |
| Combined FI CPU maximum | 9.32% | 8.89% | 9.59% |
| Minimum host available RAM | 6,527.98 MiB | 6,526.46 MiB | 6,514.17 MiB |
| Maximum host memory load | 27% | 27% | 28% |
| FICollector working set max | 50.95 MiB | 50.91 MiB | 51.00 MiB |
| FIUSNReader working set max | 14.36 MiB | 14.84 MiB | 14.34 MiB |
| Sender working set max | 65.57 MiB | 65.48 MiB | 59.42 MiB |
| Combined FI working set max | 129.97 MiB | 130.15 MiB | 124.23 MiB |
| Y: read average | 22.924 MiB/s | 21.302 MiB/s | 21.977 MiB/s |
| Y: read maximum | 46.711 MiB/s | 48.073 MiB/s | 44.985 MiB/s |
| Y: write average | 0.079 MiB/s | 0.066 MiB/s | 0.064 MiB/s |
| Y: write maximum | 0.156 MiB/s | 0.164 MiB/s | 0.225 MiB/s |
| Y: read latency average | 9.395 ms | 9.378 ms | 10.005 ms |
| Y: read latency maximum | 13.419 ms | 13.610 ms | 14.711 ms |
| Y: write latency average | 0.196 ms | 0.186 ms | 0.192 ms |
| Y: write latency maximum | 1.112 ms | 0.378 ms | 0.443 ms |
| Y: queue average | 0.617 | 0.717 | 0.706 |
| Y: queue maximum | 2 | 3 | 3 |
| Network total average | 0.001 MiB/s | 0.020 MiB/s | 0.006 MiB/s |
| Network total maximum | 0.004 MiB/s | 0.298 MiB/s | 0.297 MiB/s |
| Approx. link utilization max | 0% | 0.025% | 0.025% |
| Spool files max | 2 | 0 | 2 |
| Spool size max | 31.996 MiB | 0 MiB | 32.000 MiB |
| Stage files max | 14 | 14 | 2 |
| Stage size max | 10.195 MiB | 10.195 MiB | 1.465 MiB |

The recovery interval was effectively indistinguishable from the surrounding
250K workload in host CPU and FI CPU consumption. Host CPU average actually
moved from `10.033%` while the receiver was offline to `9.946%` during backlog
recovery, and combined FI CPU average moved from `7.711%` to `7.626%`.

Memory remained similarly stable: the maximum combined FI working set was
`130.15 MiB` during recovery versus `129.97 MiB` while the receiver was offline,
with more than `6.5 GiB` of host memory still available.

Logical Y: read throughput and latency also stayed in the same operating range.
The recovery did not produce a large source-volume queue spike: observed queue
maximum increased only from `2` to `3`.

The clearest change was network transmit activity, which is expected because the
queued generations were being delivered. Even there, observed maximum traffic
was only approximately `0.298 MiB/s`, or about `0.025%` of the measured link
capacity.

Therefore the measured conclusion is:

> **Recovering the one-hour receiver outage did not materially increase CPU,
> memory, or logical-volume pressure on ISS-FS-01. Backlog transport recovery was
> not a source-server recovery storm.**

These are measured values from this test environment and are not universal
production limits.

## Collector-fault resource comparison

The independent monitor also allowed the collector interruption itself to be
compared before, during, and after the fault.

| Metric | Before fault | Collector down | After restart |
| --- | ---: | ---: | ---: |
| Host CPU average | 9.104% | 1.75% | 8.661% |
| Host CPU maximum | 15% | 5% | 15% |
| FICollector CPU average | 7.19% | not running | 7.47% |
| FICollector CPU maximum | 12.5% | not running | 12.5% |
| FICollector working set | ~50.99 MiB | not running | ~15.27 MiB |
| Y: read average | 20.041 MiB/s | 0 MiB/s | 17.854 MiB/s |
| Y: read maximum | 55.227 MiB/s | 0 MiB/s | 87.717 MiB/s |
| Y: write average | 0.063 MiB/s | — | — |
| Y: queue average | 0.562 | — | — |
| Y: queue maximum | 2 | — | — |

The restart restored the ongoing workload without a sustained CPU surge. A
higher instantaneous Y: read maximum was observed after restart, but the average
read rate remained below the pre-fault average and host CPU returned to roughly
the same level as before the interruption.

## Sender interruption

The generation sender was intentionally stopped during the 250K workload. The
observed outage was about 10m31s. The normal scheduled sender path restored
processing, two manifests were recovered, and a 15,054-record generation
received a `recorded` acknowledgement. Queues later drained.

Receiver FIGT/receipt association was verified by transfer SHA-256, not filename
stem. Later `already_recorded` processing did not create duplicate receipt state.

```text
Sender interruption/recovery: PASS
Source custody retained:      PASS
ACK-before-retirement:        PASS
```

## Collector interruption

FICollector was intentionally terminated at approximately
`2026-09-19T19:34:19.9572913Z`. FIUSNReader remained running. No automatic SCM
restart was observed in the test configuration. A normal manual start was issued
at `19:35:35.1489866Z`, with a new collector process active about 75.259 seconds
after the fault. Operation lifecycle history remained explicit.

## Governed-volume exhaustion

A second governed NTFS volume was created as an 8 GiB dynamic VHDX:

```text
T:
FI-GATE2-FULL
8,587,833,344 total bytes
```

The configured roots were:

```text
T:\FI-Gate2-Full
Y:\FI-Lab
```

A corrected fill harness drove T: to a genuine out-of-space condition. The
failing file was:

```text
T:\FI-Gate2-Full\exhaust-0018\payload-000922.bin
```

The requested write was 8 MiB and the observed partial file length was
5,242,880 bytes. T: remained Healthy with `SizeRemaining=0`.

This exhausted a governed **source** filesystem. It did not exhaust FI transport
spool/generation stage or receiver custody storage.

## Cross-root scheduler defect

While T: remained full and Y: was in a long configured baseline, the independent
USN lane stopped completing on schedule.

Source review showed one process-global `serviceRootUSNMu` around the entire
`writeConfiguredRoot` call. A long baseline on one root therefore blocked
independent USN work for unrelated roots.

```text
Cross-root independent USN scheduling:
FAIL — implementation defect found
```

The failure remains part of the engineering history.

## Remediation

The fix replaced the global governed-root mutex with per-root synchronization,
made busy same-root USN work a non-blocking skip, dispatched roots independently
inside the USN cycle, changed the scheduler to a fixed ticker, serialized shared
supporting-SID state separately, and moved active-spool interrupted-artifact
recovery to the spool publication boundary.

Focused tests, `go test ./cmd/fi`, and the complete Go test tree passed before
live deployment.

```text
Validated binary:
81350B7236FC1DC9E26E90E803C6CDD38EE61A155409016EA34642735680805E

Final commit:
41906af fix: isolate governed-root USN scheduling
```

## T backlog recovery at zero free space

At remediated startup:

```text
T checkpoint NextUSN: 352
T journal NextUSN:    274368
T free bytes:         0
```

Catch-up started at `2026-09-19T21:50:22.247390700Z`.
ReObservation completed at `21:54:30.818440800Z`.
USNCatchUp completed at `21:54:31.459457200Z`.

The durable checkpoint advanced to `274368` while T: remained Healthy and full.

```text
Zero-free governed source:      PASS
Backlog recovered:              PASS
No false checkpoint advance:    PASS
Checkpoint 352 -> 274368:       PASS
```

## Cross-root live remediation proof

Immediately afterward Y began baseline operation
`op-90b82e3e4dcdcbc512a4940d06f852c6`:

```text
Start:   2026-09-19T21:54:31.472472400Z
Finish:  2026-09-20T03:26:34.459846600Z
Outcome: Complete
```

During that 5h32m baseline, 33 independent USN cycles completed on the intended
approximately 10-minute cadence. Each reported:

```text
configured_roots=2
completed_roots=1
skipped_roots=1
failed_roots=0
```

Y held its own root synchronization boundary while the unrelated root remained
independently serviceable.

```text
Cross-root independent USN scheduling:
PASS — live remediation validated
```

The frozen validation record was sealed with:

```text
SHA256SUMS.csv
4FD69A48884005A5D8F9314D5E39101AF4D100B3F8ADA390E8D1307B14519547
```

During those 33 cycles T was already caught up. The overlap therefore proves
root-lock/scheduler isolation; the immediately preceding T recovery separately
proves non-empty backlog processing at zero free space.

## Campaign conclusions

The campaign establishes, in the tested environment:

- receiver outage becomes backlog rather than ambiguous loss;
- a one-hour receiver outage retained seven generations / 51,538 records and
  drained after recovery;
- measured backlog recovery did not materially increase source-host CPU, memory,
  or logical-volume pressure relative to the surrounding 250K workload;
- sender interruption preserves custody and resumes safely;
- collector interruption remains explicit in operation history;
- a governed source NTFS volume can reach zero free space without taking down the
  FI process stack;
- FI does not falsely advance the tested T checkpoint;
- T later recovered from NextUSN 352 to 274368 while still full;
- a real cross-root head-of-line blocking defect was discovered;
- the defect was corrected and live validated; and
- 33 independent USN cycles continued during a 5h32m Y baseline.

This campaign does **not** establish a clean uninterrupted 250K acceptance result,
one reconciled exact generated-byte total, universal production sizing, or
transport-custody filesystem exhaustion behavior.

## Engineering disposition

```text
Original clean 250K acceptance:          INTERRUPTED — NOT A PASS
Receiver outage resilience:              PASS
Sender interruption/recovery:            PASS
Collector interruption history:          PASS
Governed-source zero-free behavior:       PASS
T backlog recovery at zero free:          PASS
Cross-root scheduler remediation:         PASS
```

A later clean 250K rerun may be used for a clean scale datapoint. It does not
replace this report.

This campaign contributes substantial live Gate 2 validation but is not itself
Gate 2 closeout. Remaining closure work is tracked in
`PHASE-2-GATE-2-CLOSURE-CHECKLIST.md`.
