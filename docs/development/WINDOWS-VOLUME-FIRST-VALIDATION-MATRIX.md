# Windows Volume-First Development Validation Matrix

**Status:** All cases NOT RUN. This matrix is a development requirement, not a test report.
**Branch:** `dev/windows-volume-first-20261108`
**Windows development/test machine:** `adminbox`

The branch now has a signed short-lived installer-intent verification package (`go/internal/windows/volumeconsent`) with unit tests. **It is not an installed v2 authority**: native signer, administrator approval token, protected installation state, transactional apply/rollback and privileged service startup remain NOT RUN/NOT IMPLEMENTED.

The branch now includes a read-only `freshinstall` SCM/path preflight and first-install-only verification wrappers. The supported v2 deployment starts with no FI, first approval sequence 1 and initial grant generation 1; no in-place update or migration is intended. The branch also includes a pure-Go signed installed-grant verifier with replay/tamper/scope/host/sequence regression tests. **The protected native grant commitment store, signer, transactional installation, privileged service handoff, and actual Windows acceptance are NOT RUN/NOT IMPLEMENTED.** See `WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md`.

## Rules of evidence

The branch includes an opt-in read-only `TestNativeEnrolledVolumeUSNReadOnly` test for `adminbox`, described in `WINDOWS-VOLUME-FIRST-USN-BROKER.md`. Its existence is NOT a PASS. All native acceptance rows remain NOT RUN until actual evidence is recorded.



Each test must record the exact source SHA, signed artifact and executable hashes, Windows build, source topology, starting configuration and custody, procedure, expected and observed outcomes, failure details and final state. Never count historical root-centric test results as proof of the redesigned implementation. Never treat compilation, unit tests or a benchmark as native Windows failure-path acceptance.

| ID | Required demonstration | Initial state |
| --- | --- | --- |
| V01 | Discover NTFS volumes with letters, mount directories and GUID-only identifiers; reject unsupported filesystems | NOT RUN |
| V02 | Discovered but unenrolled volumes generate no collected records; approved enrollment changes exactly selected volumes | NOT RUN |
| V03 | Two+ enrolled volumes each have independent USN capture, durable checkpoint, journal identity and epoch | NOT RUN |
| V04 | A volume with zero, one and overlapping governed roots captures each USN change once and produces appropriate policy memberships | NOT RUN |
| V05 | Changes outside governed roots yield bounded minimal evidence without unauthorized content, ACL or privileged object reads | NOT RUN |
| V06 | Rename, hard links, delete/recreate, inaccessible objects, ADS, reparse and cross-volume mount/move preserve correct identity and unknowns | NOT RUN |
| V07 | Journal recreation, aged-out history, volume reformat/replacement and repeated GUID/mount locator produce explicit gaps and new epoch | NOT RUN |
| V08 | Forced stop/reboot during acquisition, spool, manifest publication and checkpoint advance preserves custody and deterministic restart | NOT RUN |
| V09 | Volume failure/offline/missing journal does not block healthy volumes or independent Security processing | NOT RUN |
| V10 | Windows Security 4663 presence/absence, SACL coverage gap, circular log wrap and unavailable log yield correct attribution/coverage | NOT RUN |
| V11 | Non-admin FICollector, authenticated local pipe and helper narrow enrolled-volume authorization; reject unapproved raw-volume access | NOT RUN |
| V12 | FIObjReader is invoked only for bounded authorized exact-object observation, not a generic path/file proxy | NOT RUN |
| V13 | Resource limits, multi-volume fairness, spool pressure and large 10M-object workload; measure every stage separately | NOT RUN |
| V14 | Native installer read-only discovery, scope approval, normalized config, duplicate rejection and plan-only non-mutation | NOT RUN |
| V15 | Installer stale approval, unauthorized volume addition, scope widening, audit change and volume identity drift fail closed | NOT RUN |
| V16 | Fresh installation on an FI-free host, rejection if any of the five services/two FI-owned trees exist or cannot be inspected, stale-check race handling, rollback only of new transaction artifacts, service restart, no-update refusal | NOT RUN |
| V17 | New source records retained across verified spool, signing, sender/receiver retry, replay, duplicate handling and generation-size boundary | NOT RUN |
| V18 | Fresh PostgreSQL schema and Go ingest/projectors preserve epoch/gap lineage and governed policy associations | NOT RUN |
| V19 | Current docs, installer operator guides, schemas and test artifacts match observed implementation; historical tests remain unaltered | NOT RUN |
| V20 | `ISS-FS-22A` service configuration and stopped FISender remain untouched by development branch work | NOT RUN |

## Safety properties that block further integration when violated

- No checkpoint advances before verified custody; a retry does not delete history.
- No collector privilege expansion, unauthenticated pipe, generic raw-volume proxy or arbitrary protected-object reader.
- No implicit enrollment or SACL propagation from discovery.
- No invented file paths, actors, continuity or missing history.
- No conflation of source acquisition, deep observation, sender throughput, recorder custody and relational projection.
- No claim that `main`, a deployment, or a release has been updated merely because a branch commit exists.

## Development test closeout

Record PASS / FAIL / INCOMPLETE with source/build/environment/log references, every observed failure and its later retest. Include measured resource rates and backlog slope where relevant. Source and installer changes must have regression tests for both success and failure paths; native Windows tests run on `adminbox`. Any change to `main` is a separate explicitly authorized future integration decision.
