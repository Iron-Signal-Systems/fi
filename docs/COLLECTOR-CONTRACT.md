# FI Windows Collector Contract

The Windows collector is a source-observation component.

It collects and preserves source facts from explicitly governed Windows/NTFS
sources and supporting Windows identity/share/activity sources. It may perform
deterministic decoding of a documented value from the **same source** when the
native/raw representation required for later verification or reinterpretation is
also preserved where applicable.

The collector does not own cross-source correlation, transitive membership,
final effective-access calculation, intent, motive, causal conclusions between
independent sources, or reconstruction of source history that Windows no longer
retains.

Examples of allowed collector work include parsing a documented reparse buffer,
decoding a documented Windows access mask, canonicalizing a source timestamp,
and preserving a source-reported SID in a shared record structure.

Examples of backend work include deciding that two independently observed
identities represent the same organizational subject, traversing nested group
relationships, calculating final effective access across NTFS/share/identity
sources, or deciding that one activity record caused another state change.

A source failure or missing historical interval remains explicit. Current-state
reconciliation can establish current knowledge but cannot rewrite a historical
coverage gap as complete.

## Source-read side effects

Normal FI collection does not intentionally modify governed source state. A
source read can still cause operating-system-managed behavior. In particular,
reading file content can update NTFS `LastAccessTime` where Windows last-access
updates are enabled.

FI does not write or restore source metadata to hide such a read-side effect.
That would itself be a governed-source modification and would violate the
collector boundary.

## Active Directory primaryGroupID boundary

`primaryGroupID` is collected and preserved as the raw directory attribute
`PrimaryGroupIDRaw`.

The Windows collector does **not** construct a group SID from that value and does
not emit a primary-group membership edge. Turning the principal SID plus
`primaryGroupID` into a primary-group relationship is deterministic AD semantics,
but it is still a derived relationship rather than a relationship directly
returned by the collected `member` attribute.

That derivation belongs in the backend, where derived relationships can remain
distinct from the source facts used to produce them.

## Service scheduling boundary

The persistent Windows service has three intentional runtime lanes:

- the governed-root/current-state lane, which owns initial baselines, same-root
  reconciliation work, normal configured-root collection, and the slower
  supporting-source refresh;
- an independent USN catch-up lane for governed roots that already have a
  continuous accepted checkpoint; and
- an independent Windows Security lane that owns the single host Security
  checkpoint and bounded Security Event Log collection.

Shared startup spool recovery completes before any lane is allowed to publish.
After that boundary, source scheduling is independent where source ownership
allows it.

The independent USN interval defaults to 10 minutes and is configurable through
`FI_SERVICE_USN_EVERY`. The USN lane does not create an initial root baseline.
If no checkpoint exists, initial onboarding owns the baseline and anchored
catch-up. Same-root checkpoint-owning work remains serialized, while unrelated
governed roots must not block one another.

The independent Windows Security interval defaults to one minute and is
configurable through `FI_SERVICE_WINDOWS_SECURITY_EVERY`. One sequential worker
owns `windows-security.json`. Security windows do not overlap. Each accepted
window is durably spooled and verified before the checkpoint advances.

The Security interval is a steady-state wait, not a backlog throttle. If a
completed bounded EventRecordID window shows that the Security head is still
ahead, FI immediately processes another bounded window before returning to the
normal interval.

A service-mode Security continuity gap remains explicit and incomplete. FI
durably records the gap, records current Security-specific coverage, queries a
fresh Security head, and establishes a new forward Security boundary. The
independent Security worker does not require a full governed-file tree walk merely
to resume the Security source.

The current v0.1 `WindowsSecurityContinuityGap` schema retains
`reconciliation_action = CurrentStateBaseline` for compatibility. In the
independent service-worker path, that field does not mean that every governed
file was rescanned. The one-shot configured `fi.exe -run` path retains its
existing configured reconciliation behavior.

The lanes may overlap only where their source/checkpoint ownership boundaries
permit it. Spool publication/recovery has its own publication boundary and is not
protected by a process-global governed-root lock.

A scheduled interval is runtime policy, not a claim that source history only
exists at that cadence. Checkpoint and continuity rules remain authoritative.

## Local durable queue handoff

Phase 1 owns construction and verification of the local durable FI spool batch.

The producer verifies the private/unpublished data-manifest pair before
publication and must not depend on reopening that pair after final-manifest
publication.

Phase 2 begins at the published local queue boundary and owns discovery,
send/retry/resume, durable downstream acknowledgement,
duplicate/replay/conflict handling, backlog/catch-up, and eventual retirement of
the acknowledged local pair.
