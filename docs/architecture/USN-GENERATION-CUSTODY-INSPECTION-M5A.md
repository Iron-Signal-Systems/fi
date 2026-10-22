# M5A: read-only publication custody inspection (inactive)

M4 verifies recovery while original, complete, source-bound FI batch pairs
remain in the active spool. FISender can atomically freeze the active spool into
`generation-raw/generation-<id>`; the frozen directory still contains the
original batch pairs and exact source-bound USN observations.

`Store.InspectPendingPublicationCustody` is a **read-only diagnostic** that
checks the active spool and the immediately adjacent sender-owned raw-generation
root using FI's normal batch integrity and exact source-coverage verification.
It explicitly retains the M4 pending intent and never advances the processing
checkpoint or authorizes re-observation/republication.

The sender's subsequent raw-to-sealed generation builder is not serialized by
the spool rollover lock. This inspection can race that builder; failed or
incomplete reads remain fail-closed. No source identity is yet attested in
sealed compressed generation metadata or receiver durable acknowledgements.
A missing raw generation is not proof of nonpublication.

## Still required before restart-safe service activation

- A source-bound proof ledger that survives *every* raw-to-sealed-to-transported
  transition, including accepted acknowledgements and sender cleanup.
- A safe cross-process handoff/lease or equivalent proof of sealed custody
  before processing cursor advancement.
- Mixed-generation completeness validation, restart/crash injection, historic
  ancestry handling, backend compatibility, installer migration, and Windows
  native regression acceptance.

Never reset an existing USN capture or processing checkpoint to make a missing
source proof disappear. This patch changes no installed service runtime code.
