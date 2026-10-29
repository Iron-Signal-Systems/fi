# FreeBSD FI CRL refresh: acquisition milestone (not production accepted)

## Objective

Replace repeated Windows-to-FreeBSD SCP of Microsoft AD CS CRLs with a native Go retrieval path. This milestone fetches **base** CRLs through explicitly configured HTTP or HTTPS Certificate Revocation Distribution Points (CDPs), validates them against already-installed FI issuing CA certificates, prevents rollback, and preserves root-controlled file custody. This does not implement Active Directory LDAP retrieval.

## Current limitations — do not deploy as an unattended service

- **Live activation is not implemented.** The existing `fi-receiver` loads transport and batch CRLs at startup and holds parsed copies in memory; replacing CRL files does not refresh its active trust. The ingest worker must also be examined for its in-memory CRL lifetime. A controlled restart is required until an accepted reload design exists.
- The installer does not yet ship or configure this binary or any periodic service. Do not add cron independently.
- This assumes both issued CRLs have an operator-approved, reachable HTTP(S) CDP. If an AD CS CA publishes only LDAP distribution points, HTTP(S) source setup or a reviewed LDAP client is required.
- Base CRLs only. Delta CRLs are rejected. This is intentional until a validated base+delta policy is implemented.
- Files are staged and published with per-file atomic rename. This is **not** an atomic transaction across both CRLs. If interrupted between renames, one CRL can be newer, but both installed CRLs have passed signature, issuer, and freshness validation before the first publication.
- Existing CRLs must be authentic and parsable even when expired. Corrupt or untrusted existing material requires deliberate manual recovery, not blind overwrite.
- No production acceptance or live FreeBSD test has been performed.

## Proposed command once built on the FreeBSD development host

```sh
cd /home/jwood/src/fi/go
go test ./internal/crlrefresh
go build -o /tmp/fi-crl-refresh ./cmd/fi-crl-refresh
sudo /tmp/fi-crl-refresh \
  -transport-url 'http://CA-HOST/CertEnroll/TRANSPORT-CA.crl' \
  -batch-url 'http://CA-HOST/CertEnroll/BATCH-CA.crl'
```

The URLs above are **examples, not discovered URLs**. Read each issued certificate's CDP extension and check which CA actually issues each CRL. Do not guess path names. The command refuses incomplete options and requires root. Both URLs must return the correct independently signed CRL. A successful update emits `ACTION REQUIRED` to make the missing activation obvious.

## Acceptance work required before regular operation

1. Inspect the actual FI transport, batch, and Windows CA certificate profiles/CDPs and decide HTTP vs LDAPS source policy.
2. Verify FreeBSD runtime path custody and ensure trust file replacement works in the receiver jail and in the ingest worker's jail (separate trust stores may exist).
3. Add a controlled activation contract so the receiver and ingest worker use verified new CRLs with no stale in-memory revocation decision.
4. Integrate a least-privilege refresher service, binary release, installer-managed configuration, log retention, alerting, and pre-expiration scheduling.
5. Run FreeBSD real-host acceptance: CA unreachable, CRL expired, revoked leaf, issuer mismatch, corrupt download, rollback, delta CRL, startup, restart/reload, crash during dual publication, and recovery.
6. Update repository validation/acceptance documentation in the same release and commit its evidence.

This milestone cannot be represented as production-complete until those checks pass.