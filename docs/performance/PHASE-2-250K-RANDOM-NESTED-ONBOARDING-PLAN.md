# Phase 2 — 250K Randomized Nested Onboarding Campaign Plan

## Status

**EXECUTED AS ENGINEERING / RESILIENCE CHARACTERIZATION**

**ORIGINAL CLEAN 250K ACCEPTANCE: INTERRUPTED — NOT A PASS**

This plan remains the record of the intended campaign. Execution began on
2026-09-19. The strict clean onboarding run was intentionally interrupted as the
campaign expanded into receiver-outage, sender-interruption,
collector-interruption, governed-volume-exhaustion, and cross-root scheduler
testing.

The resulting engineering record is preserved in
`PHASE-2-250K-RANDOM-NESTED-ONBOARDING-REPORT.md`.

This campaign remains post-Gate-1 characterization. It does not replace or reopen
the historical 100K Gate 1 acceptance result.

## Purpose

Exercise the current FI Windows collector, independent USN service lane,
generation sender, receiver custody, and durable generation acknowledgement
behavior against a larger and more realistic NTFS tree.

The campaign is intended to answer:

- how initial onboarding scales from 100K to 250K files;
- how irregular directory depth/fan-out changes collection behavior;
- whether source-server impact remains bounded;
- whether generation sealing/transport develops backlog;
- whether receiver custody keeps pace;
- whether a mutation made during baseline is preserved by the baseline's anchored
  catch-up; and
- whether the independent USN lane resumes normally once a continuous checkpoint
  exists.

## Dataset shape

The generated governed root will contain exactly:

```text
250,000 files
```

The directory tree will be randomized but reproducible. The exact seed is
recorded with the test result.

Tree requirements:

- irregular fan-out rather than fixed directory buckets;
- branch depth ranging from shallow paths through a maximum depth of 15 below the
  governed root;
- a mixture of empty directories, lightly populated branches, and dense leaves;
- no requirement that every branch reach depth 15;
- randomized file names and directory names;
- randomized file sizes;
- valid Windows/NTFS path components;
- bounded total path lengths suitable for the tested Windows configuration; and
- exact generated file count, directory count, byte total, depth histogram, and
  file-size histogram recorded before FI starts.

The generator must preserve enough metadata to reproduce the same tree from the
recorded seed.

## Initial-state rule

The dataset is built with `FICollector` stopped.

Before FI starts, the campaign establishes a clean source-side onboarding state
for the governed root so the run is an initial baseline rather than continuation
from an existing accepted checkpoint.

The destructive cleanup boundary is limited to the disposable FI lab dataset and
test state explicitly named by the campaign harness. The harness must fail closed
if the host, governed root, state path, spool path, service identity, or expected
FI executable hash does not match the test contract.

## Runtime configuration

The current Windows runtime has:

```text
configured collection lane
independent USN lane
supporting-source refresh
```

The independent USN lane defaults to `10m` unless
`FI_SERVICE_USN_EVERY` is intentionally set for the campaign.

During initial onboarding there is no accepted USN checkpoint. The independent
USN lane is therefore expected to skip the governed root. The configured
collector owns the baseline and its anchored catch-up.

After a continuous checkpoint exists, the independent lane is expected to run on
its configured interval and may overlap long configured/Security work within the
implemented ownership boundaries.

## Controlled mutation during onboarding

During the baseline, the campaign mutates one or more preselected files whose
original identities and hashes were recorded before FI starts.

At minimum, one test object will receive:

- a rename; and
- a content extension followed by a durable flush.

The campaign records the exact NTFS file reference number/sequence, mutation
timestamps, resulting USNs, old/new path, pre/post size, and pre/post SHA-256.

Acceptance requires the baseline's anchored catch-up to preserve the applicable
USN change facts and current re-observation after the initial checkpoint is
established.

This initial-baseline mutation is distinct from the already completed
2026-09-19 independent-USN concurrency test, where a continuous checkpoint
already existed.

## Full transport path

The Phase 2 sender and receiver remain active during the FI onboarding run.

The campaign records:

- source spool batch count/bytes;
- generation count;
- records per generation;
- source/canonical/encoded/transfer bytes;
- compression ratio;
- sender attempts and acknowledgements;
- `recorded` / `already_recorded` outcomes;
- source retirement;
- active/tombstoned/reclaimed generation state;
- receiver FIGT custody count/bytes;
- recorder receipt count; and
- any backlog over time.

Source custody must not be retired before the exact durable acknowledgement
contract is satisfied.

## Resource measurements

At a minimum, capture:

- FICollector cumulative/delta CPU and working set;
- FIUSNReader cumulative/delta CPU and working set;
- sender process CPU/RAM;
- whole-host CPU and available memory;
- Y: logical read/write throughput;
- Y: observed queue depth/latency where available;
- spool/stage/generation queue depth and bytes;
- network payload volume where directly measurable; and
- receiver generation/receipt growth.

Do not describe logical-disk counters as physical-media throughput.

## Completion record

The final campaign result must preserve:

- exact test date/time;
- server OS/build;
- FICollector, FIUSNReader, sender, and receiver executable hashes;
- repository commit;
- generator version and seed;
- generated file count;
- generated directory count;
- exact generated bytes;
- maximum observed depth and depth histogram;
- size histogram;
- initial checkpoint state;
- mutation facts and USNs;
- baseline start/end;
- baseline anchored catch-up result;
- independent USN results after checkpoint establishment;
- generation/receipt/custody totals;
- resource summaries;
- failures, interruptions, retries, or gaps; and
- final source and receiver custody state.

A failed or partial campaign remains part of engineering history and is not
rewritten after a later rerun.
