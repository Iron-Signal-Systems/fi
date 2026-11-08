# Volume-First FIUSNReader Broker — Security and Native Validation

**Date:** 2026-11-08
**Status:** Branch-only implementation and CI tests. NOT enabled in installed services; native acceptance on `adminbox` pending.
**Branch:** `dev/windows-volume-first-20261108`

## Current state versus target

The installed FIUSNReader still loads root-centric `version_id: 1.1` configuration and invokes `usnbroker.Serve(ctx, governedRoots)`. The existing USN query/read, containment and SACL operations remain unchanged for that mode.

The separately implemented `usnbroker.ServeEnrolledVolumes(ctx, approved)` accepts a strict `config.VolumeConfig` v2 declaration and independently discovers local NTFS volumes. It compares each configured volume GUID and full-width `FILE_ID_INFO` serial against native discovery. The broker retains an immutable enrollment-ID-to-native-target snapshot, rejecting missing, replaced, inaccessible and unsupported volumes individually while still allowing unaffected enrolled volumes.

This is NOT an install or configuration authority. Future installer code must first prove fresh explicit administrator approval, configuration integrity and permitted audit/policy changes before the service may select the new mode.

## Protocol isolation

The same bounded local pipe framing gains two operation codes:

| Operation | Code | Request selector | Data |
| --- | --- | --- | --- |
| Query enrolled volume | 6 | Canonical enrolled volume ID, at most 64 bytes | Journal state |
| Read enrolled volume | 7 | Same ID plus nonnegative USN cursor | Journal state and at most 1 MiB raw records |

An enrolled-volume request carries **no caller-supplied path, drive letter, volume GUID, serial, file ID or arbitrary FSCTL**. Only the broker's own approved native target is used. A legacy-mode broker denies the new codes; a volume-mode broker denies root-based query/read/containment/SACL codes. Fixed parameterless audit-policy queries remain independent. Both modes require authentication of the actual `NT SERVICE\FICollector` service SID on the locally secured named pipe.

FIObjReader and protected-object/SACL access have NOT been reauthorized for volume mode. Their current root-scoped mechanism cannot simply be expanded to all volume objects.

## Native verification and custody boundary

`go/internal/windows/usnraw/volume_windows.go` opens only a syntactically valid Windows volume GUID device path (GUID path minus its one final backslash), using the existing limited `FILE_READ_DATA` raw-USN right. Before querying the journal, the broker performs read-only `FSCTL_GET_NTFS_VOLUME_DATA` (0x00090064) on the **same open raw-volume handle**. It requires the documented 96-byte NTFS volume data buffer and compares the entire 64-bit serial with the approved identity. No 32-bit fallback and no separately opened directory handle is accepted as proof of which raw volume is being read.

The only subsequent native journal commands are `FSCTL_QUERY_USN_JOURNAL` and `FSCTL_READ_USN_JOURNAL`. The read uses the journal ID just queried on that same handle. All source reads remain bounded. USN parsing, continuity, spool custody, epochs and checkpoint advancement belong to FICollector and are NOT activated by this broker work.

Primary API references: [Microsoft volume handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-volume-handle-for-change-journal-operations), [FSCTL_GET_NTFS_VOLUME_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_volume_data), [NTFS_VOLUME_DATA_BUFFER](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer), and [FSCTL_READ_USN_JOURNAL](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_usn_journal).

The exact on-handle full-width serial behavior and its equality to `FILE_ID_INFO.VolumeSerialNumber` require native evidence on the supported Server builds. If unsupported, the operation must fail closed; do not silently downgrade to 32-bit identity checks.

## Tests implemented

Wire round-trips; backward-compatible legacy requests; invalid/mixed/path-based enrollment selectors; bounded requests; immutable volume authority; missing/reformatted/unsupported volume isolation; mock native dispatch proving no raw access after authorization failure; native target validation; full-width serial comparison and malformed FSCTL return rejection.

## Native integration and acceptance still required

- On `adminbox`, under the intended FIUSNReader service identity, verify GUID-only, drive-letter and mounted-folder NTFS volumes. Compare the native enumerator's 64-bit FILE_ID_INFO serial with FSCTL_GET_NTFS_VOLUME_DATA serial on the actual USN handle.
- Verify journal query/read under the actual service gMSA/permissions, local pipe SID authentication, denial of unauthorized clients/volume identifiers, and no downgrade to legacy root operations.
- Verify disappearance/replacement/reformat of an isolated, explicitly approved test volume causes denial or a visible continuity gap, not a guessed continuous cursor.
- Demonstrate two-volume fault isolation, SCM restart/stop, bounded resource use and failure response semantics.
- Deliver installer v2 configuration approval, drift revalidation, gMSA/service setup, policy-root authorization and transactional recovery before switching FIUSNReader startup to the new mode.
- Validate FICollector-owned source and checkpoint custody, backend records, and the full signed transport before describing this as operational.

Keep exact build, SHA, test setup, timestamps, native errors and retests in the acceptance record. No experimental formatting/journal reset is permitted outside explicit test disks. GitHub Windows runner compilation and unit tests are not this native acceptance.

**Unchanged:** Main branch, installed ISS-FS-22A services, stopped FISender, existing root-centric deployments.
