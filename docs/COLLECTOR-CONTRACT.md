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

The persistent Windows service has two runtime lanes:

- the configured-collection lane, which also owns the slower supporting-source
  refresh; and
- an independent USN catch-up lane for governed roots that already have a
  continuous accepted checkpoint.

The independent USN interval defaults to 10 minutes and is configurable through
`FI_SERVICE_USN_EVERY`.

The independent lane does not create an initial baseline and does not perform
continuity-gap reconciliation. If no checkpoint exists, initial onboarding owns
the baseline and its anchored catch-up. If continuity is not continuous, the
configured collector owns reconciliation.

The lanes may overlap only where their ownership boundaries permit it.
Checkpoint-owning collection is serialized per governed root: same-root work does
not overlap, but long work on one governed root must not block independent USN
work for an unrelated root. A scheduled independent pass that finds its own root
busy skips that root rather than waiting behind the same-root operation.

Spool publication/recovery has its own publication boundary. It is not protected
by a process-global governed-root lock.

A scheduled interval is a runtime policy, not a claim that source history only
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
