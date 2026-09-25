// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

func ensureGovernedRoot(ctx context.Context, tx pgx.Tx, sourceID string, value records.GovernedRootIdentity) (int64, error) {
	volumeID, err := ensureNTFSVolume(ctx, tx, sourceID, value.VolumeIdentity)
	if err != nil {
		return 0, err
	}
	objectID, err := ensureNTFSObject(ctx, tx, volumeID, value.ObjectIdentity)
	if err != nil {
		return 0, err
	}
	requested, err := decodeBase64URL(value.RequestedPathUTF16LEBase64URL, true, "governed_root.requested_path")
	if err != nil {
		return 0, err
	}
	resolved, err := decodeBase64URL(value.ResolvedPathUTF16LEBase64URL, true, "governed_root.resolved_path")
	if err != nil {
		return 0, err
	}

	var id int64
	err = tx.QueryRow(ctx, `
INSERT INTO fi.governed_root (
    source_id, scope_id, containment_method_version,
    ntfs_volume_id, ntfs_object_id,
    requested_path_utf16le, resolved_path_utf16le
)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (source_id, scope_id, ntfs_volume_id, ntfs_object_id, requested_path_utf16le, resolved_path_utf16le)
DO NOTHING
RETURNING governed_root_id
`, sourceID, value.ScopeID, value.MethodVersion, volumeID, objectID, requested, resolved).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("insert FI governed root: %w", err)
	}

	var existingMethod string
	if err := tx.QueryRow(ctx, `
SELECT governed_root_id, containment_method_version
FROM fi.governed_root
WHERE source_id=$1 AND scope_id=$2 AND ntfs_volume_id=$3 AND ntfs_object_id=$4
  AND requested_path_utf16le=$5 AND resolved_path_utf16le=$6
`, sourceID, value.ScopeID, volumeID, objectID, requested, resolved).Scan(&id, &existingMethod); err != nil {
		return 0, fmt.Errorf("reload FI governed root: %w", err)
	}
	if existingMethod != value.MethodVersion {
		return 0, errors.New("FI governed-root identity method conflicts with existing relational identity")
	}
	return id, nil
}

func ensureNTFSObject(ctx context.Context, tx pgx.Tx, volumeID int64, value records.NTFSObjectIdentity) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
INSERT INTO fi.ntfs_object (
    ntfs_volume_id, identity_method_version, file_reference_number, sequence_number
)
VALUES ($1,$2,$3::text::numeric,$4::text::numeric)
ON CONFLICT (ntfs_volume_id, file_reference_number, sequence_number)
DO NOTHING
RETURNING ntfs_object_id
`, volumeID, value.MethodVersion, value.FileReferenceNumber, value.SequenceNumber).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("insert FI NTFS object identity: %w", err)
	}

	var existingMethod string
	if err := tx.QueryRow(ctx, `
SELECT ntfs_object_id, identity_method_version
FROM fi.ntfs_object
WHERE ntfs_volume_id=$1
  AND file_reference_number=$2::text::numeric
  AND sequence_number=$3::text::numeric
`, volumeID, value.FileReferenceNumber, value.SequenceNumber).Scan(&id, &existingMethod); err != nil {
		return 0, fmt.Errorf("reload FI NTFS object identity: %w", err)
	}
	if existingMethod != value.MethodVersion {
		return 0, errors.New("FI NTFS object identity method conflicts with existing relational identity")
	}
	return id, nil
}

func ensureNTFSVolume(ctx context.Context, tx pgx.Tx, sourceID string, value records.VolumeIdentity) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
INSERT INTO fi.ntfs_volume (source_id, identity_method_version, volume_guid, volume_serial)
VALUES ($1,$2,$3,$4::text::numeric)
ON CONFLICT (source_id, volume_guid, volume_serial)
DO NOTHING
RETURNING ntfs_volume_id
`, sourceID, value.MethodVersion, value.VolumeGUID, value.VolumeSerial).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("insert FI NTFS volume identity: %w", err)
	}

	var existingMethod string
	if err := tx.QueryRow(ctx, `
SELECT ntfs_volume_id, identity_method_version
FROM fi.ntfs_volume
WHERE source_id=$1 AND volume_guid=$2 AND volume_serial=$3::text::numeric
`, sourceID, value.VolumeGUID, value.VolumeSerial).Scan(&id, &existingMethod); err != nil {
		return 0, fmt.Errorf("reload FI NTFS volume identity: %w", err)
	}
	if existingMethod != value.MethodVersion {
		return 0, errors.New("FI NTFS volume identity method conflicts with existing relational identity")
	}
	return id, nil
}

func projectContentHashes(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.ContentHashObservation) error {
	var bytesHashed any
	var md5, sha1, sha256 []byte
	var err error
	if string(value.State) == "Present" {
		bytesHashed = value.BytesHashed
		if md5, err = decodeHex(value.MD5, 16, true, "content_hashes.md5"); err != nil {
			return err
		}
		if sha1, err = decodeHex(value.SHA1, 20, true, "content_hashes.sha1"); err != nil {
			return err
		}
		if sha256, err = decodeHex(value.SHA256, 32, true, "content_hashes.sha256"); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.content_hash_observation (
 source_record_id,state,bytes_hashed,md5,sha1,sha256,reason_code,detail
) VALUES ($1,$2,$3::text::numeric,$4,$5,$6,$7,$8)
`, sourceRecordID, string(value.State), bytesHashed, md5, sha1, sha256, nullString(value.ReasonCode), nullString(value.Detail))
	if err != nil {
		return fmt.Errorf("insert FI content hash observation: %w", err)
	}
	return nil
}

func prepareContentPrefixProjection(
	value records.ContentPrefixObservation,
) (
	any,
	[]byte,
	error,
) {
	if err := records.ValidateContentPrefixObservation(value); err != nil {
		return nil, nil, err
	}

	if value.State != records.ContentPrefixPresent {
		return nil, nil, nil
	}

	parsed, err := parseUint(
		value.BytesObserved,
		8,
		"content_prefix.bytes_observed",
	)
	if err != nil {
		return nil, nil, err
	}

	prefix, err := decodeBase64URL(
		value.PrefixBase64URL,
		false,
		"content_prefix.prefix",
	)
	if err != nil {
		return nil, nil, err
	}

	if uint64(len(prefix)) != parsed {
		return nil, nil, fmt.Errorf(
			"content_prefix.prefix byte count %d does not match content_prefix.bytes_observed %d",
			len(prefix),
			parsed,
		)
	}

	if prefix == nil {
		prefix = []byte{}
	}

	return int16(parsed), prefix, nil
}

func projectContentPrefix(
	ctx context.Context,
	tx pgx.Tx,
	sourceRecordID int64,
	value records.ContentPrefixObservation,
) error {
	bytesObserved, prefix, err :=
		prepareContentPrefixProjection(value)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
INSERT INTO fi.content_prefix_observation (
 source_record_id,state,bytes_observed,prefix_bytes,reason_code,detail
) VALUES ($1,$2,$3,$4,$5,$6)
`,
		sourceRecordID,
		string(value.State),
		bytesObserved,
		prefix,
		nullString(value.ReasonCode),
		nullString(value.Detail),
	)
	if err != nil {
		return fmt.Errorf(
			"insert FI content prefix observation: %w",
			err,
		)
	}

	return nil
}

func projectFileMetadata(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.MetadataObservation) error {
	creation, err := parseRFC3339(value.CreationTime, "metadata.creation_time")
	if err != nil {
		return err
	}
	lastWrite, err := parseRFC3339(value.LastWriteTime, "metadata.last_write_time")
	if err != nil {
		return err
	}
	change, err := parseRFC3339(value.ChangeTime, "metadata.change_time")
	if err != nil {
		return err
	}
	lastAccess, err := parseRFC3339(value.LastAccessTime, "metadata.last_access_time")
	if err != nil {
		return err
	}
	attributes, err := parseUint(value.RawAttributes, 32, "metadata.raw_attributes")
	if err != nil {
		return err
	}
	links, err := parseUint(value.LinkCount, 32, "metadata.link_count")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.file_metadata_observation (
 source_record_id,logical_size,allocated_size,creation_time,last_write_time,change_time,last_access_time,raw_attributes,link_count
) VALUES ($1,$2::text::numeric,$3::text::numeric,$4,$5,$6,$7,$8,$9)
`, sourceRecordID, value.LogicalSize, value.AllocatedSize, creation, lastWrite, change, lastAccess, int64(attributes), int64(links))
	if err != nil {
		return fmt.Errorf("insert FI file metadata observation: %w", err)
	}
	return nil
}

func projectNTFSObservation(ctx context.Context, tx pgx.Tx, sourceID string, sourceRecordID int64, value ntfs.Observation, hashes *records.ContentHashObservation) error {
	if value.VolumeIdentity != value.GovernedRoot.VolumeIdentity {
		return errors.New("FI NTFS observation volume identity does not match governed-root volume")
	}

	volumeID, err := ensureNTFSVolume(ctx, tx, sourceID, value.VolumeIdentity)
	if err != nil {
		return err
	}
	objectID, err := ensureNTFSObject(ctx, tx, volumeID, value.ObjectIdentity)
	if err != nil {
		return err
	}
	governedRootID, err := ensureGovernedRoot(ctx, tx, sourceID, value.GovernedRoot)
	if err != nil {
		return err
	}

	var parentObjectID any
	if value.ParentBinding.ObjectIdentity != nil {
		id, err := ensureNTFSObject(ctx, tx, volumeID, *value.ParentBinding.ObjectIdentity)
		if err != nil {
			return err
		}
		parentObjectID = id
	}
	requested, err := decodeBase64URL(value.PathBinding.RequestedPathUTF16LEBase64URL, true, "path_binding.requested_path")
	if err != nil {
		return err
	}
	resolved, err := decodeBase64URL(value.PathBinding.ResolvedPathUTF16LEBase64URL, true, "path_binding.resolved_path")
	if err != nil {
		return err
	}
	observedAt, err := parseRFC3339(value.ObservedAt, "ntfs.observed_at")
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
INSERT INTO fi.file_observation (
 source_record_id,governed_root_id,ntfs_object_id,parent_state,parent_ntfs_object_id,parent_reason_code,
 subject_kind,requested_path_utf16le,resolved_path_utf16le,observed_at,containment_method_version,
 collection_entry_method,collection_method,observation_status
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
`, sourceRecordID, governedRootID, objectID, string(value.ParentBinding.State), parentObjectID,
		nullString(value.ParentBinding.ReasonCode), string(value.SubjectKind), requested, resolved, observedAt,
		value.Containment.MethodVersion, string(value.CollectionEntryMethod), string(value.CollectionMethod), string(value.ObservationStatus))
	if err != nil {
		return fmt.Errorf("insert FI file observation: %w", err)
	}

	if err := projectFileMetadata(ctx, tx, sourceRecordID, value.Metadata); err != nil {
		return err
	}
	if hashes != nil {
		if err := projectContentHashes(ctx, tx, sourceRecordID, *hashes); err != nil {
			return err
		}
	}
	if value.ContentPrefix != nil {
		if err := projectContentPrefix(ctx, tx, sourceRecordID, *value.ContentPrefix); err != nil {
			return err
		}
	}
	if err := projectReparseObservation(ctx, tx, sourceRecordID, value.Reparse); err != nil {
		return err
	}
	if err := projectStreamInventory(ctx, tx, sourceRecordID, value.StreamInventory); err != nil {
		return err
	}
	if err := projectSecurityObservation(ctx, tx, sourceRecordID, value.Security); err != nil {
		return err
	}
	if err := projectSACLObservation(ctx, tx, sourceRecordID, value.SACL); err != nil {
		return err
	}
	for i, warning := range value.Warnings {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.observation_warning (source_record_id,warning_ordinal,code,detail) VALUES ($1,$2,$3,$4)`, sourceRecordID, i+1, warning.Code, nullString(warning.Detail)); err != nil {
			return fmt.Errorf("insert FI observation warning: %w", err)
		}
	}
	return nil
}

func projectReparseObservation(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.ReparseObservation) error {
	raw, err := decodeBase64URL(value.RawBufferBase64URL, false, "reparse.raw_buffer")
	if err != nil {
		return err
	}
	substitute, err := decodeBase64URL(value.SubstituteNameUTF16LEBase64URL, false, "reparse.substitute_name")
	if err != nil {
		return err
	}
	printName, err := decodeBase64URL(value.PrintNameUTF16LEBase64URL, false, "reparse.print_name")
	if err != nil {
		return err
	}
	var tag any
	if value.Tag != "" {
		parsed, e := parseUintFlexible(value.Tag, 32, "reparse.tag")
		if e != nil {
			return e
		}
		tag = int64(parsed)
	}
	var flags any
	if value.SymbolicLinkFlags != "" {
		parsed, e := parseUintFlexible(value.SymbolicLinkFlags, 32, "reparse.symbolic_link_flags")
		if e != nil {
			return e
		}
		flags = int64(parsed)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.reparse_observation (
 source_record_id,state,data_state,data_format,tag,tag_name,raw_buffer,substitute_name_utf16le,print_name_utf16le,symbolic_link_flags,reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
`, sourceRecordID, string(value.State), string(value.DataState), string(value.DataFormat), tag, nullString(value.TagName), raw, substitute, printName, flags, nullString(value.ReasonCode))
	if err != nil {
		return fmt.Errorf("insert FI reparse observation: %w", err)
	}
	return nil
}

func projectSACLObservation(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.SACLObservation) error {
	raw, err := decodeBase64URL(value.RawDescriptorBase64URL, false, "sacl.raw_descriptor")
	if err != nil {
		return err
	}
	revision, err := optionalUintValue(value.Revision, 8, "sacl.revision")
	if err != nil {
		return err
	}
	control, err := optionalUintValue(value.Control, 16, "sacl.control")
	if err != nil {
		return err
	}
	aclRevision, err := optionalUintValue(value.ACL.Revision, 8, "sacl.acl_revision")
	if err != nil {
		return err
	}
	aclSize, err := optionalUintValue(value.ACL.Size, 32, "sacl.acl_size")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.sacl_observation (
 source_record_id,state,data_format,raw_descriptor,revision,control,acl_state,acl_revision,acl_size,reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
`, sourceRecordID, string(value.State), string(value.DataFormat), raw, revision, control, nullString(string(value.ACL.State)), aclRevision, aclSize, nullString(value.ReasonCode))
	if err != nil {
		return fmt.Errorf("insert FI SACL observation: %w", err)
	}
	for _, ace := range value.ACL.ACEs {
		if err := projectSecurityACE(ctx, tx, "fi.sacl_ace", sourceRecordID, ace); err != nil {
			return err
		}
	}
	return nil
}

func projectSecurityACE(ctx context.Context, tx pgx.Tx, table string, sourceRecordID int64, value records.ACEObservation) error {
	ordinal, err := parseUint(value.Index, 32, "ace.index")
	if err != nil {
		return err
	}
	aceType, err := parseUint(value.Type, 8, "ace.type")
	if err != nil {
		return err
	}
	flags, err := parseUint(value.Flags, 8, "ace.flags")
	if err != nil {
		return err
	}
	size, err := parseUint(value.Size, 16, "ace.size")
	if err != nil {
		return err
	}
	raw, err := decodeBase64URL(value.RawBase64URL, true, "ace.raw")
	if err != nil {
		return err
	}
	mask, err := optionalUintValue(value.Mask, 32, "ace.mask")
	if err != nil {
		return err
	}
	objectFlags, err := optionalUintValue(value.ObjectFlags, 32, "ace.object_flags")
	if err != nil {
		return err
	}
	query := fmt.Sprintf(`INSERT INTO %s (
 source_record_id,ace_ordinal,ace_type,type_name,flags,ace_size,raw_ace,access_mask,object_flags,object_type_guid,inherited_object_type_guid,sid
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::uuid,$11::text::uuid,$12)`, table)
	_, err = tx.Exec(ctx, query, sourceRecordID, int(ordinal), int(aceType), value.TypeName, int(flags), int(size), raw, mask, objectFlags, nullString(value.ObjectTypeGUID), nullString(value.InheritedObjectTypeGUID), nullString(value.SID))
	if err != nil {
		return fmt.Errorf("insert FI security ACE: %w", err)
	}
	return nil
}

func projectSecurityObservation(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.SecurityObservation) error {
	raw, err := decodeBase64URL(value.RawDescriptorBase64URL, false, "security.raw_descriptor")
	if err != nil {
		return err
	}
	revision, err := optionalUintValue(value.Revision, 8, "security.revision")
	if err != nil {
		return err
	}
	control, err := optionalUintValue(value.Control, 16, "security.control")
	if err != nil {
		return err
	}
	aclRevision, err := optionalUintValue(value.DACL.Revision, 8, "security.acl_revision")
	if err != nil {
		return err
	}
	aclSize, err := optionalUintValue(value.DACL.Size, 32, "security.acl_size")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.security_observation (
 source_record_id,state,data_format,raw_descriptor,revision,control,owner_sid,primary_group_sid,acl_state,acl_revision,acl_size,reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, sourceRecordID, string(value.State), string(value.DataFormat), raw, revision, control, nullString(value.OwnerSID), nullString(value.PrimaryGroupSID), nullString(string(value.DACL.State)), aclRevision, aclSize, nullString(value.ReasonCode))
	if err != nil {
		return fmt.Errorf("insert FI security observation: %w", err)
	}
	for _, ace := range value.DACL.ACEs {
		if err := projectSecurityACE(ctx, tx, "fi.security_ace", sourceRecordID, ace); err != nil {
			return err
		}
	}
	return nil
}

func projectStreamInventory(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.StreamInventory) error {
	if _, err := tx.Exec(ctx, `INSERT INTO fi.stream_inventory (source_record_id,state,reason_code) VALUES ($1,$2,$3)`, sourceRecordID, string(value.State), nullString(value.ReasonCode)); err != nil {
		return fmt.Errorf("insert FI stream inventory: %w", err)
	}
	for i, stream := range value.Streams {
		name, err := decodeBase64URL(stream.Identity.NameUTF16LEBase64URL, false, "stream.name")
		if err != nil {
			return err
		}
		rawName, err := decodeBase64URL(stream.Identity.RawNameUTF16LEBase64URL, true, "stream.raw_name")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.stream_observation (
 source_record_id,stream_ordinal,kind,name_utf16le,stream_type,raw_name_utf16le,logical_size,allocated_size
) VALUES ($1,$2,$3,$4,$5,$6,$7::text::numeric,$8::text::numeric)
`, sourceRecordID, i+1, string(stream.Identity.Kind), name, nullString(stream.Identity.StreamType), rawName, stream.LogicalSize, stream.AllocatedSize)
		if err != nil {
			return fmt.Errorf("insert FI stream observation: %w", err)
		}
	}
	return nil
}

func optionalUintValue(value string, bits int, field string) (any, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := parseUint(value, bits, field)
	if err != nil {
		return nil, err
	}
	return int64(parsed), nil
}
