# FI Phase 2 — Independent Windows Security Worker Validation

Validation date: 2026-09-20

Status:

```text
SOURCE-SIDE WINDOWS SECURITY WORKER: PASS
FULL RECEIVER / RELATIONAL PROOF OF THE CONTROLLED 4719 PAIR: PENDING
```

> **Later disposition:** Phase 3 / Gate 3 subsequently completed authoritative
> receiver/database support for all 13 supported record kinds, including
> `WindowsSecurityEvent`. The `PENDING` status above is retained as the
> 2026-09-20 checkpoint for this exact controlled 4719 pair; it is not a statement
> that Gate 3 or WindowsSecurityEvent relational support remains incomplete.

This note records the post-Gate-2 source-runtime remediation discovered during
the retained 250K randomized nested engineering/resilience campaign.

It does not rewrite the original clean 250K campaign as a pass and it does not
change the accepted Phase 2 transport contract.

## Problem discovered

The Windows Security Event Log is an independent source, but service-mode Security
catch-up could remain coupled to governed-root/current-state work.

On the Server 2016 250K lab workload, a configured Security reconciliation could
remain active for approximately 5.4-5.5 hours while the Windows Security log
retained only minutes of history at the observed event rate.

A measured continuity state showed:

```text
Checkpoint:             184209612
OldestAvailable:        185600266
NewestAvailable:        185629542
CheckpointBeforeOldest: true
RecordsBehindNewest:    1419930
```

That did not mean FI had lost 1.4 million FI-selected events. It meant Windows had
overwritten roughly 1.39 million Security-channel records before FI could examine
them and determine which, if any, were relevant to FI.

The source-truth behavior was correct: FI emitted
`WindowsSecurityContinuityGap` rather than claiming that the unavailable
interval contained no relevant events.

The scheduling behavior was not acceptable because Security-source maintenance
could be delayed by unrelated heavyweight root work.

## Engineering change

The persistent Windows service now has three intentional runtime lanes:

```text
FICollector
    |
    +-- governed-root/current-state lane
    |      root baseline / current-state work
    |      same-root reconciliation ownership
    |      supporting-source refresh
    |
    +-- independent USN lane
    |      established continuous root checkpoints
    |      default 10m
    |
    +-- independent Windows Security lane
           one sequential Security checkpoint owner
           default 1m
           bounded EventRecordID windows
           durable spool verification before checkpoint advance
           immediate next bounded window while backlog remains
```

Shared startup spool recovery completes before any independently scheduled writer
is allowed to publish.

The Security lane never overlaps itself. One worker owns
`windows-security.json`.

When one bounded Security window completes:

```text
more backlog?
    yes -> immediately process another bounded window
    no  -> wait for the steady-state interval
```

The one-minute interval is therefore a steady-state cadence, not a backlog
throttle.

## Service-mode continuity-gap behavior

A proven Security continuity gap remains `Incomplete`.

The service-mode worker now:

1. durably records the `WindowsSecurityContinuityGap`;
2. evaluates current Security-specific coverage;
3. durably records that coverage;
4. queries a fresh Security head after coverage work;
5. establishes the new forward Security checkpoint there; and
6. resumes bounded Security collection.

Security-specific coverage includes the effective audit-policy state,
Security-log readability, and governed-root SACL coverage.

The service-mode Security worker does not perform a full governed-file tree walk
merely to resume Event Log collection.

The current v0.1 gap record still carries:

```text
reconciliation_action = CurrentStateBaseline
```

for compatibility with the existing record contract. In the independent service
path that value must not be interpreted as proof that every governed file was
rescanned.

The one-shot configured `fi.exe -run` path retains its existing configured
reconciliation behavior.

## Build validation

The replacement was built from repository base:

```text
878e1d2a8c42baac29ef1fc3e1e99a55b2d5f0ae
tools: preserve Phase 2 validation harness
```

On ADMINBOX:

```text
go test .\cmd\fi
PASS
3.577s

go vet .\cmd\fi
PASS

go build -trimpath
PASS
```

Validated test binary:

```text
C:\FI-Test\fi-security-worker.exe
SHA256
DB88D1527AAEAF8CB65B507158CF2CDDA798B5AEACEE4E4953FBCCEBB037E45B
```

The same SHA-256 was installed as:

```text
C:\Program Files\FI\fi.exe
```

on `ISS-FS-01`.

## Startup result

The old collector was stopped at approximately:

```text
2026-09-20T16:06:39Z
```

The new collector started at:

```text
2026-09-20T16:07:09Z
```

The runtime immediately recorded:

```text
ServiceStarted
collection_interval=1m
usn_interval=10m
security_interval=1m
supporting_refresh_interval=30m
```

and then:

```text
WindowsSecurityCatchUp
outcome=Complete
security_checkpoint_reinitialized=true
security_continuity_gap=true
```

The initial gap/rebase was expected because the prior accepted checkpoint was
already older than the oldest retained Security record before this build was
installed.

The newly established checkpoint was:

```text
185816299
```

and the Security head measured seconds later was:

```text
185816419
```

a difference of 120 EventRecordIDs.

## 50 MiB intermediate validation

The Security log was first constrained to:

```text
52,428,800 bytes
50 MiB
retention=false
autoBackup=false
```

Repeated 15-second samples showed the independent worker advancing approximately
once per minute.

Observed samples included:

```text
12:08:38  checkpoint 185816933  newest 185817095  behind 162  safe=true
12:09:23  checkpoint 185817440  newest 185817547  behind 107  safe=true
12:10:23  checkpoint 185817877  newest 185817941  behind  64  safe=true
12:11:01  checkpoint 185817877  newest 185818461  behind 584  safe=true
12:11:16  checkpoint 185818549  newest 185818571  behind  22  safe=true
12:11:31  checkpoint 185818549  newest 185818651  behind 102  safe=true
```

Every sampled checkpoint remained within the retained Security-log window.

Runtime records also proved immediate backlog drain. At
`2026-09-20T16:08:11.285095800Z` one Security pass reported
`security_more_available=true`; the next pass completed at
`16:08:11.829475600Z`, approximately 0.54 seconds later rather than one minute
later.

## 20 MiB live validation

The Security log was then returned to the original Server 2016 lab value:

```text
20,971,520 bytes
20 MiB
retention=false
autoBackup=false
```

FI remained running with the independent Security worker.

A controlled File System audit-policy Failure toggle was performed and restored
immediately.

Windows emitted two genuine Event ID 4719 records:

```text
185819888
2026-09-20 12:13:32 local
System audit policy was changed
File System
Failure removed

185819899
2026-09-20 12:13:34 local
System audit policy was changed
File System
Failure added
```

The next relevant FI runtime record at
`2026-09-20T16:14:18.355753600Z` reported:

```text
security_read_windows=1
security_source_matching_events=2
security_selected_events=2
security_verified_batches=1
security_checkpoint_advanced=true
security_more_available=true
```

The worker immediately ran another bounded window at
`2026-09-20T16:14:18.879040700Z`.

The accepted Security checkpoint then reached:

```text
185820374
```

which is beyond both controlled 4719 EventRecordIDs.

This proves, for the tested source-side path:

```text
Windows emits selected Security event
        |
        v
independent FI Security worker reads bounded window
        |
        v
FI selection accepts event
        |
        v
local FI batch is durably verified
        |
        v
Security checkpoint advances past event
```

## Selection behavior

The validation also observed both selection outcomes.

Earlier runtime activity reported:

```text
security_source_matching_events=3
security_ignored_events=3
```

showing that matching event IDs are still evaluated against FI selection rules
rather than automatically promoted.

The controlled 4719 pair later reported:

```text
security_source_matching_events=2
security_selected_events=2
```

showing the positive selection path.

## Security-log sizing conclusion

The original 20 MiB log was sufficient for this tested steady-state worker once
Security scheduling was independent.

This does **not** establish 20 MiB as a universal production recommendation.

Log sizing still depends on:

- event rate;
- Windows audit policy;
- governed-root SACL scope;
- service outage tolerance;
- host maintenance windows;
- operational recovery objectives; and
- customer retention requirements.

The engineering conclusion is narrower:

> A large Security log must not be used as a substitute for timely Security
> collection. FI should keep the source checkpoint moving independently and use
> log capacity as operational retention margin.

## Resource-observation caveat

A visible drop in `ISS-FS-01` VM CPU, disk read activity, and I/O pressure
occurred at roughly the same time the new collector was installed.

However, `fi-sender` was accidentally stopped during that same interval.

Therefore the before/after Proxmox graphs are **confounded** and are not accepted
as quantitative proof that the Security worker alone caused the resource drop.

The source-worker validation in this note relies on checkpoint, retained-window,
runtime, selected-event, durable-batch, and build results rather than that
confounded resource comparison.

A later like-for-like performance comparison must keep the sender state identical
on both sides.

## Remaining validation

The source-side worker is accepted for this engineering test.

Still required for the exact controlled 4719 pair:

```text
fi-sender transport
receiver FIGT custody
recorder receipt
PostgreSQL WindowsSecurityEvent materialization
```

At this 2026-09-20 checkpoint, that downstream work belonged to the then-active
Phase 3 relational-validation effort.

## Disposition

```text
Independent Security service scheduling:        PASS
Single-owner Security checkpoint behavior:      PASS
Immediate bounded backlog drain:                PASS
20 MiB retained-log source-side continuity:     PASS for tested workload
Controlled 4719 selection:                      PASS
Durable local batch before checkpoint advance:  PASS
Full receiver/relational proof of 4719 pair:    PENDING
Universal 20 MiB production sizing claim:       NOT MADE
Quantitative resource-improvement claim:        NOT MADE
```
