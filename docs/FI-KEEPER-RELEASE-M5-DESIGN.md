# FI Keeper Release M5 — transactional storage layer (not operational release)

**Status:** Development candidate; native FreeBSD test required. This does not authorize or activate a keeper release operation.

## What this adds

New, unreferenced code in `internal/quarantinekeeper` for a keeper-side release transaction. The existing worker protocol still accepts only `read` and `publish`. The keeper CLI remains unchanged and cannot invoke release. Neither the namespaced activation gate nor the running keeper is altered.

`releaseTransaction()` is package-private and MUST be called only after BOTH requirements are implemented and verified: (1) an independent administrative Unix-socket endpoint authenticated from FreeBSD kernel root peer credentials; (2) the keeper itself acquiring the exact same protected singleton inode lock that all ingest worker modes use. It is NOT safe to expose this transaction before those controls exist.

Transaction ordering:
1. Validate exact enrolled source, exact source confirmation, bounded reference/justification and root peer UID (supplied by future authenticated administrative handler).
2. Serialize with keeper marker operations and verify source marker identity plus protected history directory.
3. Publish and sync an immutable **intent** record containing original marker and SHA-256.
4. Create and sync a hidden guard in quarantine storage. The strict inventory treats it as an unexpected object and **fails closed**.
5. Recheck original marker inode, unlink it and synchronize quarantine directory.
6. Publish and sync an immutable **completion** record with actual release timestamp.
7. Unlink the guard and synchronize the directory; only now can the worker observe `clear`.

There is no automatic recovery or clearing of partial transactions. If the process crashes with a guard in place, the keeper refuses to start (or service worker reads) until independently reviewed. If intent exists but no guard, the original quarantine remains intact.

## New tests

- `TestKeeperReleaseTransactionAuditBeforeRetirement`
- `TestKeeperReleaseTransactionRejectsFalseConfirmation`
- `TestKeeperReleaseTransactionAuditFailurePreservesMarker`
- `TestKeeperReleaseTransactionGuardsInterruptedRelease`

Run native `go test -count=1 -v -run '^TestKeeperReleaseTransaction' ./internal/quarantinekeeper` and then the keeper+worker regressions and `go vet`.

## Not yet implemented / remains blocked

- Dedicated administrative Unix socket with `0600` mode in keeper-owned socket directory, bound by keeper UID; root kernel peer verification, no worker access.
- Trusted operator attribution beyond authenticated root UID, deliberate CLI with source/confirmation/reference/justification.
- Keeper-owned protected singleton lock acquisition *before* calling the transaction, with mixed flat/namespaced exclusion demonstrated.
- Native failure injection at each sync/unlink boundary, complete cross-UID release integration and restart test.
- Installer integration, safe socket lifecycle, policy-controlled activation, and operator recovery procedure.

The live `fi-dev` marker `m1-fixture-fs2019.local.json` **must remain quarantined** until the independent admin path is implemented and tested. Do not invoke release against it at this stage.
