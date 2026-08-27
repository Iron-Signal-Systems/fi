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
