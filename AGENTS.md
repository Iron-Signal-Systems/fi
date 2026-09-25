# FI Agent and Contributor Rules

## Purpose

This file defines how contributors, coding agents, automation, and review agents
work within the File Intelligence (FI) repository.

It is a behavioral and engineering contract. It does not replace the governing
architecture, roadmap, source-contract, security, or validation documents.

Before making a material change, read the relevant current documents, including
as applicable:

- `README.md`
- `fi-roadmap/roadmap.md`
- `fi-roadmap/docs/roadmap/phase-01-windows-file-and-identity-intelligence.md`
- `fi-roadmap/docs/roadmap/phase-02-secure-record-transport.md`
- `docs/PHASE-3-INGEST-WORKER-OPERATING-CONTRACT.md`
- `docs/performance/PHASE-3-250K-RELATIONAL-INGEST-ACCEPTANCE.md`
- `docs/COLLECTOR-CONTRACT.md`
- `docs/LOCAL-SPOOL-INTEGRITY.md`
- `docs/GATE-1-RESULT-RECORD.md`
- `docs/WINDOWS-SERVER-VALIDATION.md`
- `docs/security/`
- `docs/performance/`
- `tools/gate1/README.md`

If code and documentation disagree, do not silently choose whichever is easier.
Identify the conflict and resolve it deliberately.

---

## Governing Principles

> **FI is centered on the file: what do we know about this file?**

> **Record what the source can actually establish, preserve where that fact came
> from, and never manufacture certainty beyond it.**

> **Observed source fact is not the same thing as derived interpretation.**

> **A gap in available history is not proof that an event did not occur.**

> **Current state is not historical state.**

> **Path is not durable file identity.**

> **A volume-wide USN source does not make the whole volume governed.**

> **The normal collector remains non-administrative. Privileged Windows work stays
> bounded inside the dedicated helper.**

> **FI is non-remediating with respect to the customer environment.**

> **Host availability and durable FI state take priority over maintaining nominal
> FI cadence.**

> **A slower correct collection is preferable to an aggressive collection that
> materially degrades the file server.**

> **A successful retry does not erase a failed attempt.**

> **Unknown is a real state. Do not replace it with null, empty string, zero, or
> false certainty.**

> **A published spool manifest is an ownership boundary, not just another file
> rename.**

> **Checkpoint advancement is a custody decision.**

> **Do not call process logical I/O physical disk I/O.**

> **Do not convert a test-environment measurement into a universal production
> sizing claim.**

---

## Product Model

FI is one system with intentionally separated source, transport, recording,
classification, and query responsibilities.

### Phase 1 — Windows File & Identity Intelligence

Phase 1 owns source-side observation and local durable custody for explicitly
governed Windows/NTFS roots.

It includes:

```text
governed-root baseline observation
NTFS object identity/state
content hashing / content-prefix observation where defined
alternate data streams
reparse observation
security descriptors
ACL / SACL source facts
SMB share source facts
local identity source facts
Active Directory source facts
Windows Security governed-file activity
USN change detection
fresh object re-observation
continuity / gap state
reconciliation
local operation history
durable local spool creation
checkpoint ownership
Windows service runtime
gMSA boundaries
bounded FIUSNReader operations
independent service USN catch-up after checkpoint establishment
```

Phase 1 is complete for Gate 1, but defect correction, supported-build
characterization, and pilot hardening remain valid work.

### Phase 2 — Secure Record Transport

Phase 2 begins at the finalized, verified, published local spool boundary.

Phase 2 owns:

```text
source / collector transport identity
authenticated transport
encryption
signing where required by the transport contract
sender / receiver mechanics
durable receiver staging
durable acknowledgement
retry / resume
duplicate handling
replay handling
conflicting duplicate handling
sequence handling
backlog / catch-up
restart / recovery behavior
generation freezing / canonicalization / zstd encoding
signed generation descriptors and FIGT transfer
durable generation custody and semantic recorder receipts
exact recorded / already-recorded acknowledgement binding
startup recovery and acknowledged-generation reclamation
local retirement after durable downstream custody
```

Phase 2 must not retroactively weaken Phase 1 local durability or source-truth
semantics.

### Phase 3 — Relational Ingest & Recorder

Phase 3 begins after durable receiver generation custody and the immutable
semantic recorder receipt exist.

Phase 3 owns:

```text
immutable recorder receipt discovery
exact FIGT custody loading
PostgreSQL relational authority
typed relational projection
generation-atomic ingest
duplicate-safe identity checks
conflict detection
append-only ingest attempt history
durable source-record rejection retry state
bounded READY-marker operational discovery
authoritative operational reconciliation / repair
explicit deep reconciliation / audit
host-local ingest-worker singleton protection
adaptive repair cadence
PostgreSQL availability reconnect / backoff
worker restart and transaction-crash recovery
```

The immutable recorder receipt is the authoritative generation-discovery source.
READY markers are bounded operational notifications only.

The append-only ingest journal preserves attempt history. A later success does
not erase an earlier rejection, failure, or incomplete attempt.

The accepted Phase 3 topology authorizes one active backend ingest-worker host
per deployment. The accepted worker is source-scoped through `-source`; that does
not define the final multi-source backend topology.

### Later phases

Later phases may own classification/enrichment, cross-source correlation and
derivation, higher-order projections/query, UX, and integrated release behavior.

Do not pull later-phase responsibilities into the Windows source collector,
transport path, or Phase 3 recorder merely because implementation there appears
convenient.

---

## Three Categories of FI Truth

Preserve the distinction between:

```text
WHAT THE SOURCE REPORTED
    native Windows / NTFS / USN / Security / SMB / AD source facts

WHAT FI DIRECTLY OBSERVED
    FI's exact observation of those sources at a specific time and scope

WHAT FI LATER UNDERSTOOD
    correlation / derivation / effective-access reasoning / classification /
    projection / interpretation
```

A deterministic same-source decode may live near collection when the mapping is
well-defined and the source representation remains available where needed.

Cross-source correlation is not source collection.

Examples:

```text
raw SID observed                     source fact
SID decoded to canonical text        same-source decode
SID correlated to directory object   later correlation

NTFS access mask observed            source fact
mask decoded to named rights         same-source decode
effective access through nested AD   later derivation

USN rename reason observed           source fact
current object freshly re-observed   new source observation
"the user renamed this file"         cross-source correlation unless directly
                                     established by a source record
```

Derived results remain traceable to the source records used to produce them.

Do not rewrite an old source record because later information changes FI's
interpretation.

---

## Governed Scope Rules

FI operates only on explicitly configured governed roots.

Never equate:

```text
FI installed on server     == whole server governed
volume opened for USN      == whole volume governed
share contains root        == whole share governed
directory reachable        == directory governed
object once governed       == object always governed
```

USN is volume-wide by nature. The collector must still establish current
governed-root containment before treating an object as governed.

Containment must use current object identity/state, not stale path text.

A rename or move can change whether an object is inside or outside governed
scope.

Do not manufacture history for the interval before FI began observing the root.

---

## File Identity Rules

Path is useful, but path is not durable identity.

Where the platform supports it, preserve stable filesystem identity such as NTFS
File ID/sequence and volume identity.

Do not assume:

```text
same path       == same file
different path  == different file
rename          == new file
delete/create   == rename
same filename   == same content
same hash       == same NTFS object
```

Historical paths are history, not current identity.

Hard links, alternate streams, reparse points, rename/move, object recreation,
and volume identity must remain distinct concepts.

---

## Source Collection Rules

Normal FI runtime is read-oriented and non-remediating.

FI does not intentionally:

```text
modify governed file content
rewrite source timestamps
change owner
change DACL
change SACL
grant or revoke access
change local/domain membership
change SMB share configuration
quarantine files or hosts
alter network configuration
repair customer state
```

Administrative deployment/test tooling may configure explicit prerequisites such
as services, service identities, audit policy, SACLs, state/spool ACLs, or lab
roots. Those actions are not normal collector behavior and must remain visibly
separate.

A source read can trigger operating-system-managed effects such as LastAccessTime
changes where enabled. Do not write metadata back merely to hide such effects.

---

## Windows Privilege Boundary

The normal Windows source collector is:

```text
FICollector
    per-host gMSA
    non-admin
```

The bounded privileged helper is:

```text
FIUSNReader
    separate per-host gMSA
    local Administrator on that host where required
```

`FIUSNReader` exposes only the narrow operations defined by the accepted design:

```text
QueryJournal
ReadJournal
CheckContainment
ReadSACL
```

Do not turn `FIUSNReader` into:

```text
arbitrary file reader
generic FSCTL proxy
generic device handle broker
command runner
PowerShell host
registry administration helper
service-control helper
remote administration endpoint
```

The helper independently validates/authorizes bounded requests.

Parsing, governed-root policy, record construction, hashing, spool ownership,
checkpoints, SMB/local/AD collection, and broad operation logic remain outside the
privileged helper.

Windows protected-object fallbacks must remain exact-build and behavior-gated
where required. Do not generalize a Windows-version workaround merely because it
worked on one build.

---

## Windows-Native Implementation Rules

Production Windows behavior should target Windows directly.

Prefer:

```text
Win32 / NT native APIs
documented Windows syscalls
Go x/sys/windows
platform-specific Go wrappers with clear semantics
```

Do not shell out to PowerShell, WMI command-line utilities, `sc.exe`, `wevtutil`,
`fsutil`, or other administrative commands from production collector code when a
stable native API is the correct product interface.

PowerShell is appropriate for:

```text
lab orchestration
Gate validation
deployment examples
administrative prerequisite setup
test harnesses
controlled failure injection
report generation / collection
```

PowerShell test convenience must not silently define the production architecture.

---

## Platform Targeting Rules

Code must target the platform it actually lives on.

Platform support is part of the product contract, not merely a compiler
implementation detail.

Use Go platform files when behavior or the supported deployment contract is
platform-specific:

```text
*_windows.go
*_linux.go
*_freebsd.go
```

Platform-specific Go implementation files and tests must also carry the explicit
Go build constraint for that platform:

```go
//go:build windows
```

```go
//go:build linux
```

```go
//go:build freebsd
```

Do not rely only on the developer's current operating system, package import
graph, CI job selection, filename convention, or accidental compiler behavior to
establish a platform boundary.

A platform-specific implementation must be excluded explicitly from unsupported
platform builds.

Do not place code in an unconstrained generic `.go` file when that code depends
on platform-specific:

```text
syscalls
filesystem semantics
service-management behavior
privilege models
runtime paths
socket / IPC behavior
operating-system APIs
platform-only types
platform-only implementation files
deployment assumptions
backend support contracts
```

This includes implementation that may technically compile on another operating
system but is not part of FI's supported deployment contract.

For example:

```text
generic postgres.go
    references Linux-only backend behavior
    compiles on the developer's Linux host
    is attempted by Windows CI
```

is a platform-boundary defect.

The correct boundary is:

```text
Linux backend implementation
    -> Linux-constrained source files

Windows source implementation
    -> Windows-constrained source files

portable contract / validation logic
    -> unconstrained shared source files
```

Do not hide fundamentally different operating-system semantics behind a generic
abstraction merely to make the source tree look portable.

If a component lives on Windows, implement Windows semantics.

If a component lives on Linux, implement Linux semantics.

If a future component is intentionally supported on FreeBSD, implement and test
FreeBSD semantics rather than assuming Linux behavior is portable.

Shared packages are appropriate only for genuinely shared:

```text
record contracts
schema-neutral data structures
deterministic validation
serialization
cryptography
protocol contracts
encoding
platform-independent state machines
pure transformation logic
```

A shared file must not acquire a platform-specific dependency merely because doing
so is convenient.

### Current FI Pilot Platform Contract

For the current FI pilot path, the supported platform boundary is:

```text
Windows
    FI source collector
    FI Windows service runtime
    NTFS source work
    USN source work
    Windows Security source work
    SMB source work
    Active Directory source work
    FIUSNReader privileged helper

Linux
    FI receiver
    durable backend generation custody
    generation recorder runtime
    PostgreSQL relational backend
    relational ingest worker
    relational reconciliation / repair runtime
```

FreeBSD is not currently part of the FI pilot support contract.

FreeBSD may be evaluated as a later backend portability target, but code must not
claim or imply FreeBSD support until that platform has its own implementation,
validation, packaging, and operational acceptance.

Do not broaden the supported platform contract merely because Go code happens to
compile there.

---

## Phase 3 Backend Authority and Runtime Rules

Phase 3 backend code must preserve the distinction between authoritative state,
operational notification, repair confidence, and process/runtime state.

### Recorder and READY authority

The immutable semantic recorder receipt is authoritative for generation
discovery. Exact FIGT custody is the corresponding immutable generation payload
boundary.

READY state is operational and non-authoritative:

```text
immutable recorder receipt
        |
        v
READY marker
        |
        v
bounded READY discovery
        |
        v
cheap relational identity check
        |
        v
ingest if pending
        |
        v
retire READY marker
```

Do not treat:

```text
READY missing             == generation missing
READY present             == generation valid
READY retired             == authority deleted
READY queue empty         == recorder fully reconciled
```

The normal steady-state path must remain bounded. Do not return to rescanning
every recorded receipt on every polling pass merely because it is simpler.

### Ingest journal and retry authority

The ingest journal is append-only attempt history and durable retry authority.

Preserve:

```text
AttemptStarted
terminal outcome where one was durably established
historical rejection/failure
later retry as a separate attempt
```

Do not fabricate a terminal outcome after an ambiguous connection loss or
process crash.

A source-record rejection governed by durable journal retry state is not a READY
failure. Due retries are selected from journal authority with bounded,
deterministic ordering.

A successful retry does not erase the earlier rejection.

### Singleton ownership

The accepted Phase 3 singleton lock is host-local `flock()` protection.

It prevents duplicate ingest-worker processes on one backend host. It is not a
distributed election or lease.

The accepted Phase 3 topology supports:

```text
one active backend ingest-worker host per deployment
```

PostgreSQL uniqueness and relational constraints are integrity backstops, not a
distributed singleton mechanism.

Before more than one backend host may contend for ingest ownership, add an
authoritative distributed coordination mechanism such as a PostgreSQL advisory
lock or database-backed lease.

The host-local `flock()` should remain even after distributed coordination is
added because the two controls solve different problems.

### Adaptive authoritative repair

Every worker start performs an immediate full authoritative operational
reconciliation before normal READY/retry processing settles into steady state.

The accepted adaptive repair cadence is:

```text
Validation
    1 hour x 6 clean repair sweeps
        |
        v
Intermediate
    12 hours x 1 clean repair sweep
        |
        v
Steady
    24-hour repair sweeps
```

Any repair anomaly resets confidence to Validation with a zero clean count.

Expected pending states do not by themselves reset repair confidence when the
pending generation has:

```text
the exact valid READY notification
or
durable SOURCE_RECORD_REJECTED retry state
```

A pending authoritative generation with neither explanation is an anomaly even
if the repair sweep safely ingests it.

Repair cadence state is non-authoritative and intentionally in memory. Losing
cadence state changes only how soon the next safety sweep occurs.

The explicit deep reconciliation/audit path remains separate from operational
repair. Do not make the normal worker perform deep reconciliation every cycle.

### PostgreSQL availability and reconnect

The ingest worker keeps its host-local singleton lock while PostgreSQL is
temporarily unavailable.

Availability retry uses bounded exponential backoff with current defaults:

```text
1s -> 2s -> 4s -> 8s -> 16s -> 30s -> 30s ...
```

Only PostgreSQL availability/connectivity failures are retryable.

Authentication, wrong database/runtime identity, malformed connection
configuration, schema/foundation mismatch, privilege-boundary violation,
relational conflict, and ordinary non-availability SQL failures remain
fail-closed.

A successful PostgreSQL connection or reconnect must re-run the existing runtime
boundary validation before ingest resumes. The accepted Phase 3 validation
includes:

```text
runtime user is fi_ingest
runtime database is fi
expected relational foundation exists
required core tables exist
JSON / JSONB / XML storage shortcuts are absent
fi.source_record remains append-only to the ingest identity
```

After successful reconnect:

```text
revalidate PostgreSQL boundary
        |
        v
reset repair confidence to Validation
        |
        v
immediate authoritative operational reconcile
        |
        v
resume READY / durable retry processing
```

Do not resume READY processing before that authoritative reconciliation.

SIGINT/SIGTERM/context cancellation must interrupt reconnect backoff promptly.

### Ambiguous database loss during ingest

A connection loss during relational ingest may occur before, during, or after a
database commit boundary.

Do not blindly replay the same in-flight operation and do not manufacture a
terminal journal result merely because the connection disappeared.

The recovery rule is:

```text
reconnect
    -> revalidate PostgreSQL boundary
    -> authoritative operational reconcile
    -> determine Accepted / Pending / Conflict from durable authority
    -> continue from that result
```

An incomplete `AttemptStarted` record after a crash or connection loss is valid
historical state when no terminal outcome was durably established.

### Phase 3 backend review rule

For any material Phase 3 backend change, ask:

```text
Did recorder authority change?
Did READY become authoritative by accident?
Did retry ownership move out of the journal?
Can two workers now contend on one host?
Did we accidentally imply distributed locking exists?
Can PostgreSQL loss terminate the worker unnecessarily?
Can a reconnect skip runtime-boundary validation?
Can READY/retry work run before reconnect reconciliation?
Can an ambiguous commit be replayed without reconciliation?
Can a later success erase an earlier failed/incomplete attempt?
Did operational repair accidentally become deep reconciliation?
```

If any answer is unclear, stop and resolve the ownership boundary before coding.

### Platform Boundary Review Rule

Whenever a new Go file is added or materially changed, review whether it introduces
a platform assumption.

Ask:

```text
Does this file depend on one operating system?
Does it depend on another platform-specific Go file?
Does it rely on platform-specific filesystem or process semantics?
Does it assume Linux paths, sockets, permissions, systemd, or PostgreSQL deployment?
Does it assume Windows services, NTFS, USN, registry, Event Log, or Win32 behavior?
Is this implementation actually supported on every platform on which the compiler
will attempt to build it?
```

If the answer establishes a platform-specific implementation, constrain the file
at the source boundary.

Do not wait for another platform's CI job to discover the boundary accidentally.

---

## Go Coding Rules

Production FI code is Go unless a governing design explicitly states otherwise.

Keep code simple, explicit, testable, and reviewable.

### Control flow

Use `switch` for discrete states/cases.

Use `if` for simple guards, boolean conditions, ranges, and compound predicates.

Do not build deeply nested condition forests when the state model is discrete and
a switch would expose it more clearly.

### Functions and types

Within a coherent file/section, keep functions and types alphabetized where doing
so does not break a required lifecycle/readability ordering.

Use explicit section comments where they improve navigation.

Do not move unrelated code merely to satisfy cosmetic ordering during a narrow
bug fix.

### Errors

Return explicit errors with enough context to identify:

```text
operation
source
object/root/volume where safe
expected state
actual state
```

Wrap errors rather than flattening useful origin information.

Do not swallow errors to maintain nominal cadence.

A later success does not erase the earlier failure record.

### State

Avoid semantic nulls.

Use established explicit states such as:

```text
not_known
no_record
not_observed
not_present
not_applicable
partial
failed
unavailable
continuity_gap
```

Use the exact schema enum/casing already defined by FI. Do not invent a new
spelling because it feels equivalent.

Empty string is not an acceptable substitute for an explicit unknown/error state
when the schema has a defined state model.

### Naming

Use names that describe product meaning, not only mechanics.

Prefer:

```text
governedRoot
sourceRecord
observationStatus
checkpoint
publishedManifest
collectionOperation
```

over ambiguous names such as:

```text
thing
data2
tmpResult
misc
helper2
```

Avoid product terminology that implies stronger certainty than FI has established.

---

## Record and Schema Rules

FI records should make it possible to determine:

```text
what source produced the fact
what system/volume/object it concerned
when FI observed it
what source identity/record identity exists
what collection/operation produced it
whether collection was complete, partial, failed, unavailable, or unknown
```

Where applicable, keep source identity separate from collection identity.

Do not collapse multiple independent source records merely because they refer to
the same file.

Avoid schema fields whose meaning depends on undocumented context.

When extending schemas:

1. define the product meaning first;
2. define unknown/not-applicable behavior;
3. define exact validation rules;
4. define compatibility/version behavior;
5. add tests;
6. update relevant documentation.

Do not add a field just because a source API exposes it.

---

## Common Truth Separations

Never collapse these distinctions:

```text
path                                      != file identity
filename                                  != object identity
same hash                                 != same NTFS object
same NTFS object                          != same path
volume access                             != governed scope
USN record                                != current file state
USN change                                != Windows Security actor attribution
Windows Security event                    != NTFS state change
Security event missing                    != event did not occur
current ACL                               != historical ACL
DACL                                      != SACL
share permission                          != NTFS permission
permission source facts                   != final effective access
direct group membership                   != transitive membership
directory membership                      != access actually used
possible access                           != observed access
observed access                           != successful modification
successful open                           != content read
successful write request                  != durable file modification
rename reason                             != actor identity
process name                              != user intent
source timestamp precision                != timestamp accuracy
later clock correction                    != rewritten historical timestamp
current path                              != historical path
current hostname association              != historical hostname association
source record                             != derived interpretation
same-source deterministic decode          != cross-source correlation
classification                            != source observation
classification result                     != file content
classification unavailable                != file unavailable
record written                            != checkpoint safe to advance
spool data finalized                      != batch published
manifest written privately                != manifest published
manifest published                        != downstream custody
bytes sent                                != backend durable
receiver accepted bytes                   != receiver durably committed
ACK received                              != source record newly observed
ACK lost                                  != record lost
duplicate                                 != conflict
retry                                     != duplicate source observation
checkpoint advanced                       != uninterrupted history
reconciliation complete                   != missing history reconstructed
new baseline                              != old gap erased
service running                           != collection healthy
collection complete                       != every supporting source complete
supporting source partial                 != governed file unavailable
helper unavailable                        != collector unavailable
collector unavailable                     != source data lost
source data unavailable                   != source data absent
file not observed                         != file not present
no record                                 != negative proof
not_known                                 != false
empty string                              != not_known
zero                                      != not_known
logical I/O                               != physical disk I/O
logical disk throughput                   != FI physical disk throughput
process CPU seconds                       != CPU percent
raw process CPU percent                   != host-normalized CPU percent
highest observed sample average           != instantaneous peak
one test host result                      != universal sizing limit
100K campaign                             != maximum supported dataset
1-minute acceptance configuration         != universal production cadence
PowerShell test harness behavior          != production collector architecture
configured collection cadence             != independent USN cadence
missing USN checkpoint                    != permission for background USN to create a baseline
generation recorder receipt               != full Phase 3 System of Record
successful lab workaround                 != supported product behavior
Windows 2025 behavior                     != Windows 2022 behavior
adjacent Windows build                    != automatically accepted build
admin deployment action                   != runtime remediation authority
gMSA                                      != unlimited local privilege
helper local Administrator membership     != arbitrary helper authority
local spool integrity hash                != cryptographic authenticity
SHA-256 manifest digest                   != digital signature
historical failure                        != current failure
current success                           != historical failure erased
READY marker                              != immutable recorder receipt
READY queue empty                         != authoritative recorder reconciliation
PostgreSQL row present                    != distributed worker ownership
PostgreSQL uniqueness                     != distributed singleton
AttemptStarted                            != terminal ingest outcome
PostgreSQL reconnect                      != permission to skip reconciliation
repair cadence state                      != FI authority
pending generation                        != failed generation discovery
```

---

## Failure-State Discipline

FI fails explicitly.

Use meaningful status rather than silent omission.

Examples include:

```text
Complete
Partial
Failed
Unavailable
NotPresent
NotKnown
NoRecord
ContinuityGap
RecoveryRequired
```

Use the exact established schema values for the component being changed.

Do not infer success from:

```text
absence of exception
empty result set
service still running
checkpoint file exists
manifest filename exists
sender returned
receiver connection closed normally
```

A partial source must remain partial even if unrelated source collection
succeeds.

An unavailable dependency must not silently become `NotPresent`.

A parser encountering malformed required data should fail closed for that fact
rather than emitting a plausible-looking value.

---

## Operation History Rules

Major FI work should remain attributable to an operation lifecycle.

Preserve enough information to answer:

```text
what operation started
when it started
what source/root it concerned
what candidate/configuration ran
what completed
what partially completed
what failed
why it failed
whether later recovery occurred
```

Do not rewrite a failed operation into success when a later retry works.

Retries are additional history.

Do not create one catch-all log file and call it operational history if the
product contract requires structured records.

---

## Local Spool Rules

The Phase 1 local spool is a real durable custody boundary.

The accepted publication sequence is:

```text
producer-private .open state
        |
        v
finalize data
        |
        v
construct manifest
        |
        v
verify private data + manifest
        |
        v
publish final manifest
        |
        v
transport-visible ownership
```

The final manifest publication is the ownership handoff.

After publication, the Phase 1 producer must not depend on reopening the
published pair for collection correctness.

Do not reintroduce:

```text
publish final manifest
then producer verifies/reopens it
```

because a Phase 2 sender may already have discovered and, after valid durable
acknowledgement, retired the pair.

Checkpoint advancement must happen only after the applicable durable local
boundary is satisfied.

Do not advance a checkpoint merely because source enumeration succeeded.

---

## Hashing and Content Observation Rules

When FI claims a full-file hash, the implementation must actually hash the full
content corresponding to the recorded observation.

Do not call a prefix/sample hash a full-file hash.

SHA-256 is the canonical modern content hash unless a governing record contract
requires another digest.

MD5/SHA-1 may be preserved for compatibility or specific operational
requirements, but do not treat them as the primary integrity choice for new
designs.

Avoid unnecessary full-content reads when the source facts can prove content did
not change, but do not introduce hash reuse without a defined invalidation and
reconciliation contract.

Content-affecting changes and metadata/security-only changes should remain
distinguishable.

Any optimization that reuses prior content hashes must be designed so a stale
hash cannot silently become current truth.

---

## Active Directory and Identity Rules

Preserve direct source facts from Active Directory.

Do not silently perform backend graph reasoning inside the Windows collector.

Examples:

```text
AD member attribute                 source fact
direct membership edge              deterministic source representation
nested/transitive membership        backend derivation
effective access through groups     backend derivation
```

`primaryGroupID` remains a raw source attribute unless/until the backend performs
the defined derivation.

Directory lookup failure does not mean the SID is nonexistent.

Demand-driven principal resolution and caching must preserve whether identity
information was observed, cached, unavailable, or not known.

---

## SMB and Windows Security Rules

SMB, Windows Security, NTFS, and USN are independent source domains.

Do not merge them into one event merely because timestamps and paths look
related.

Correlation belongs in a later layer unless one source explicitly provides the
relationship.

Preserve source record identifiers and log/session identifiers needed for later
correlation.

Do not globally collect unrelated Windows events merely because they may someday
be useful.

FI remains governed-file centered.

---

## Performance and Operational-Impact Rules

FI performance work exists to understand operational cost, not to win synthetic
throughput contests.

The core operational priority is:

```text
normal server workload
    >
FI background completion speed
```

Under onboarding or backlog, prefer bounded slower completion over aggressive
resource consumption.

Performance reports must clearly distinguish:

```text
initial onboarding
steady state
catch-up
reconciliation
transport backlog
simulated user workload
FI collector workload
supporting-source work
```

Always define units.

For CPU:

```text
CPU_TOTAL_SEC      cumulative/delta CPU seconds
CPU_RAW_PCT        process CPU normalized to one logical CPU
CPU_HOST_PCT       process CPU normalized to total host logical CPUs
```

For sampled peaks, say:

```text
highest observed N-second average
```

unless an actual instantaneous measurement exists.

For I/O:

```text
process logical reads        != physical reads
LogicalDisk(Y:) bytes/sec    != per-process physical disk bytes/sec
```

Do not claim physical media behavior unless it was directly measured at that
layer.

A single lab campaign is characterization, not universal sizing.

---

## Test Rules

Every production code change requires tests at the narrowest meaningful level.

At minimum, relevant Go changes should be checked with:

```text
gofmt
go test ./...
go vet ./...
git diff --check
```

Windows/PowerShell acceptance tooling should at least pass PowerShell parser
validation before being treated as a reusable artifact.

Platform-sensitive behavior requires platform-representative testing.

Do not replace a Windows semantics test with a Linux unit test and claim the
Windows boundary was proven.

Do not rerun a destructive or multi-hour acceptance campaign merely to repair a
report-formatting defect when existing raw results are sufficient.

Do rerun when the actual behavior under acceptance changed in a way that makes
the prior result no longer representative.

### Phase 3 backend failure acceptance

Backend runtime behavior that depends on PostgreSQL availability, singleton
ownership, or authoritative reconciliation requires platform-representative
failure testing, not only unit tests.

Relevant acceptance should prove, as applicable:

```text
worker starts while PostgreSQL is unavailable
worker retains the host-local singleton during database outage
a second same-host worker remains rejected
bounded reconnect backoff occurs
the same worker process can survive a live PostgreSQL session loss
successful reconnect revalidates the PostgreSQL runtime/foundation boundary
repair confidence resets to Validation after reconnect
authoritative operational reconciliation runs before READY/retry processing resumes
generations arriving during outage are accepted exactly once
stale READY markers retire only after relational identity is established
production authority/state is not modified by isolated acceptance harnesses
```

Use isolated PostgreSQL clusters, custody roots, READY roots, and lock paths for
failure injection unless the governing acceptance plan explicitly calls for a
production-impacting exercise.

### Cross-Platform Build Boundaries

Supported-platform CI must verify that platform boundaries remain correct.

FI currently has meaningful Windows and Linux code in the same Go module.
Therefore:

```text
Linux CI
    must compile and test Linux backend implementation

Windows CI
    must compile and test Windows source implementation

Windows CI
    must not attempt to compile Linux-only backend implementation

Linux CI
    must not accidentally substitute Linux behavior for required Windows semantics
```

Platform-specific implementation should disappear cleanly from unsupported builds
through Go build constraints.

A Windows build failure caused by an unconstrained Linux implementation file is a
source-boundary defect, not a reason to weaken or skip Windows CI.

Likewise, CI exclusions must not be used to hide incorrectly scoped source files.

Portable packages should continue to compile and test across applicable platforms
when their contracts are genuinely platform-independent.

For a change involving platform boundaries, validation should include the
applicable native tests plus cross-compilation or native CI sufficient to prove
that unsupported implementation is excluded.

For the current FI repository, relevant validation includes:

```text
Linux:
    go vet ./...
    go test ./...

Windows:
    go test ./...

Targeted cross-build checks where appropriate:
    GOOS=windows GOARCH=amd64 go build ./...
```

Do not interpret successful cross-compilation as proof of runtime support on a
platform. Runtime support requires platform-representative validation and an
explicit FI support contract.

### Preserve failed tests

Failed and partial campaigns are part of engineering history.

Do not delete or rewrite them to make the validation record cleaner.

Correct the harness, document why the earlier attempt failed, and record the
accepted rerun separately.

### Harness correctness

A test harness must not accidentally test a broader system than intended.

For example:

```text
focused spool publication test
    !=
unrestricted historical backlog drain
```

Validate scope, root, receiver, process names, and destructive actions before
launching a test.

---

## Gate 1 Acceptance Baseline

Phase 1 / Gate 1 is complete.

The final 100K source-impact campaign established:

```text
100,000 files
131,365,642,498 bytes
122.344 GiB

ConfiguredCollection:        Complete
Collection elapsed:          10,048.082 sec

Peak whole-host CPU:         36.91 %
Peak combined FI CPU:        11.14 % of host
Peak combined FI RAM:        36.21 MiB
Minimum host available RAM:  7,069.99 MiB
Peak host memory load:       21.00 %

Peak Y: logical read:        34.842 MiB/s
Peak Y: logical write:       0.723 MiB/s
Peak observed Y: queue:       3

Spool files:                 6,320
Spool bytes:                 870,946,901
Manifest record count:       202,012
```

Do not reinterpret this as a maximum supported dataset or universal production
cadence.

Phase 2 work must preserve the accepted Phase 1 source-side behavior.

Post-Gate-1 live characterization on 2026-09-19 also established that the
independent 10-minute USN worker can complete while a long configured collection
remains active. A rename plus content extension of one stable NTFS object was
re-observed, hashed, transported, and placed into receiver generation custody in
about 7 minutes 13 seconds. This is a lab measurement, not a universal latency
guarantee.

The next planned scale campaign uses 250,000 files in an irregular randomized
directory tree with depths from shallow paths through a maximum depth of 15.
That campaign is additional characterization and does not rewrite the accepted
historical 100K Gate 1 result.

---

## Phase 2 Transport Rules

A published local batch remains under source custody until the Phase 2 contract
establishes durable downstream custody.

A future sender must be safe under:

```text
normal delivery
receiver unavailable
connection loss
partial transfer
ACK loss
retransmission
duplicate delivery
sender restart
receiver restart
backlog growth
catch-up
```

The same batch identity with the same exact bytes may be a retry/duplicate.

The same identity with conflicting bytes is a conflict and must not be silently
accepted as equivalent.

Do not delete local source custody on:

```text
socket write success
TLS write success
HTTP success alone
receiver parsed bytes
receiver temporary-file creation
```

Retirement authority requires the exact durable acknowledgement contract defined
by Phase 2.

---

## Cryptography and Transport Rules

Do not invent cryptographic protocols.

Use standard, supported cryptographic constructions and libraries.

Keep purposes separated:

```text
transport TLS identity
record/package signing identity
journal identity
future classification-channel identity
administrative identity
```

A TLS connection being encrypted does not by itself establish authorization.

Certificate validation does not by itself establish application-level permission.

Define:

```text
trust root
identity
key purpose
rotation
revocation
expiry
failure behavior
```

before building around a certificate.

Never log private keys, bearer secrets, passwords, or reusable authentication
material.

---

## Security Rules

Assume the collector runs on systems containing sensitive customer files and
security metadata.

Minimize privilege, retained content, and unnecessary source reads.

Do not:

```text
add a vendor backdoor
add an undocumented support account
add a generic remote shell
weaken gMSA boundaries for convenience
disable certificate validation in production code
silently fall back to plaintext
silently broaden governed scope
silently skip spool verification
silently advance checkpoints after failure
store source-file content in normal record transport
```

Debug/diagnostic functionality must preserve the same trust boundaries as normal
operation.

---

## Documentation Rules

Documentation is part of the product contract.

When a change affects:

```text
architecture
trust boundary
record meaning
schema
failure behavior
spool custody
checkpoint behavior
supported Windows build
phase/gate status
performance interpretation
operator workflow
```

update the relevant documentation in the same work set.

Preserve historical test facts.

Do not replace:

```text
"this test failed for X"
```

with:

```text
"the test passed"
```

after a later rerun. Record both.

Do not turn measured values into marketing absolutes.

Use exact terms such as:

```text
measured
observed
characterized
accepted on exact build
not measured
not known
deployment-specific
```

where appropriate.

---

## Repository Hygiene

Keep the repository focused.

Do not commit:

```text
temporary patch backups
large raw lab datasets
generated spool contents
local credentials
private keys
machine-specific state
one-off broken harness copies
editor swap files
unrelated experiments
```

Reusable validation tooling, concise result records, regression tests, and
reviewed engineering reports belong in the repository when they materially
preserve the product contract.

Do not use broad `git add -A` when a change set contains lab or generated
material. Stage intended files explicitly.

Before a proposed commit, review:

```text
git status --short
git diff --check
git diff --stat
git diff
```

and after explicit staging:

```text
git diff --cached --check
git diff --cached --stat
git diff --cached
```

---

## GitHub and Change-Control Rules

Agents and automation must not perform repository writes without explicit user
authorization for that action.

Without explicit approval, do not:

```text
commit
push
merge
create a pull request
close or modify a pull request
change branches remotely
create/delete tags
change rulesets
change branch protection
change repository settings
create releases
delete files from GitHub
modify issues as a substitute for code approval
```

Local/offline analysis and working-tree preparation are allowed unless the user
says otherwise.

A prior approval for one action is not blanket approval for future actions.

Examples:

```text
"yes, edit locally"      != permission to commit
"yes, commit"            != permission to push
"yes, push this commit"  != permission to merge a PR later
```

Never interpret urgency as permission.

---

## Narrow-Fix Discipline

When fixing a narrow defect:

1. identify the violated contract;
2. fix the smallest correct ownership/logic boundary;
3. add a regression test;
4. avoid unrelated refactors;
5. update the governing documentation;
6. run the relevant validation.

A platform annotation correction should constrain the smallest correct
implementation boundary; do not mark genuinely portable contracts
platform-specific merely to make CI pass.

Do not redesign the subsystem merely because a small bug exposed one race.

The Gate 1 spool-publication correction is the model:

```text
problem:
producer published then re-opened a transport-visible manifest

correct boundary:
verify privately
publish once
producer stops depending on the pair
transport owns post-publication lifecycle
```

That is preferable to adding sleeps, retry loops, sender delays, or file-lock
workarounds that preserve the wrong ownership model.

---

## Review Questions

Before declaring a change ready, ask:

```text
What exact product fact changed?
Which phase owns that fact?
Is this source observation or later derivation?
Did governed scope change?
Did privilege change?
Did checkpoint behavior change?
Did spool custody change?
Can a failure now be mistaken for success?
Can unknown now be mistaken for absent?
Did we introduce a new platform assumption?
Is every platform-specific Go implementation explicitly constrained at the source-file boundary?
Did recorder authority, READY semantics, retry authority, or worker ownership change?
Can PostgreSQL reconnect resume work before authoritative reconciliation?
Can an ambiguous database outcome be mistaken for a terminal ingest result?
Did we call a logical measurement physical?
Did we turn one lab result into a universal claim?
Did we preserve historical failures?
Are tests proving the actual platform behavior?
Are docs consistent with the code?
Are only intended files staged?
Was explicit authorization given for any repository write?
```

If any answer is unclear, do not silently proceed.

---

## Final Engineering Rule

FI should remain understandable to the administrator who has to operate it during
an outage or investigation.

Prefer:

```text
explicit state
bounded privilege
native platform behavior
durable ownership
traceable source facts
small reviewable changes
clear failures
measured operational impact
```

over:

```text
implicit magic
hidden inference
generic administrative privilege
silent fallback
aggressive background throughput
opaque helper behavior
unverifiable historical claims
```

The system should be able to explain what it observed, what it did, what it could
not establish, and where custody currently resides.
