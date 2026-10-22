// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// Each group is already bounded by the existing 1,024-record/8-MiB file
// projection envelope. Stream rows can outnumber file observations, so each
// COPY call is independently bounded as well. All writes remain in the caller's
// original generation transaction.
const fileChildCopyMaxRows = 1024

type fileChildBulkTable struct {
	name    string
	columns []string
	rows    [][]any
}

func (t *fileChildBulkTable) copy(ctx context.Context, tx pgx.Tx) error {
	if len(t.rows) == 0 {
		return nil
	}
	if ctx == nil || tx == nil {
		return fmt.Errorf("FI %s child COPY requires transaction and context", t.name)
	}
	for offset := 0; offset < len(t.rows); offset += fileChildCopyMaxRows {
		end := offset + fileChildCopyMaxRows
		if end > len(t.rows) {
			end = len(t.rows)
		}
		rows := t.rows[offset:end]
		count, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", t.name}, t.columns, pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("FI %s child COPY rows %d-%d: %w", t.name, offset+1, end, err)
		}
		if count != int64(len(rows)) {
			return fmt.Errorf("FI %s child COPY rows %d-%d: copied %d of %d", t.name, offset+1, end, count, len(rows))
		}
	}
	return nil
}

type fileChildBulkTables struct {
	prefix    fileChildBulkTable
	reparse   fileChildBulkTable
	inventory fileChildBulkTable
	streams   fileChildBulkTable
	security  fileChildBulkTable
	sacl      fileChildBulkTable
	warnings  fileChildBulkTable
}

func newFileChildBulkTables() fileChildBulkTables {
	return fileChildBulkTables{
		prefix: fileChildBulkTable{"content_prefix_observation", []string{
			"source_record_id", "state", "bytes_observed", "prefix_bytes", "reason_code", "detail",
		}, nil},
		reparse: fileChildBulkTable{"reparse_observation", []string{
			"source_record_id", "state", "data_state", "data_format", "tag", "tag_name", "raw_buffer",
			"substitute_name_utf16le", "print_name_utf16le", "symbolic_link_flags", "reason_code",
		}, nil},
		inventory: fileChildBulkTable{"stream_inventory", []string{
			"source_record_id", "state", "reason_code",
		}, nil},
		streams: fileChildBulkTable{"stream_observation", []string{
			"source_record_id", "stream_ordinal", "kind", "name_utf16le", "stream_type", "raw_name_utf16le",
			"logical_size", "allocated_size",
		}, nil},
		security: fileChildBulkTable{"security_observation", []string{
			"source_record_id", "state", "data_format", "raw_descriptor", "revision", "control", "owner_sid",
			"primary_group_sid", "acl_state", "acl_revision", "acl_size", "reason_code",
		}, nil},
		sacl: fileChildBulkTable{"sacl_observation", []string{
			"source_record_id", "state", "data_format", "raw_descriptor", "revision", "control",
			"acl_state", "acl_revision", "acl_size", "reason_code",
		}, nil},
		warnings: fileChildBulkTable{"observation_warning", []string{
			"source_record_id", "warning_ordinal", "code", "detail",
		}, nil},
	}
}

// copyFileObservationBulkChildren prepares *all* child projections before
// publishing rows. Parent file_observation/metadata rows have already crossed
// their COPY boundary. These tables have the following FK ordering:
// file -> child parent -> stream/ACE child. ACE and hash COPY states are
// deliberately invoked only after their own FK parents exist.
func copyFileObservationBulkChildren(ctx context.Context, tx pgx.Tx, pending []fileObservationBulkPrepared, counters *ntfsStageTimingCounters) error {
	tables := newFileChildBulkTables()
	for _, p := range pending {
		err := appendFileChildBulkRows(&tables, p.record)
		if err != nil {
			return fmt.Errorf("FI file child source record %d (ordinal %d): %w", p.record.sourceRecordID, p.record.ordinal, err)
		}
	}

	stages := []*fileChildBulkTable{
		&tables.prefix,
		&tables.reparse,
		&tables.inventory,
		&tables.streams,
		&tables.security,
		&tables.sacl,
		&tables.warnings,
	}
	for i := range stages {
		started := time.Now()
		if err := stages[i].copy(ctx, tx); err != nil {
			return err
		}
		elapsed := time.Since(started)
		if counters != nil {
			switch i {
			case 0:
				counters.Prefix += elapsed
			case 1:
				counters.Reparse += elapsed
			case 2, 3:
				counters.Streams += elapsed
			case 4:
				counters.Security += elapsed
			case 5:
				counters.SACL += elapsed
			case 6:
				counters.Warnings += elapsed
			}
		}
	}

	// Content hash and ACE writers are already bounded COPY implementations.
	// Their states are retained, rather than introducing competing writers.
	// All required file/security/SACL parent rows now exist.
	for _, p := range pending {
		record := p.record
		if record.hashes != nil {
			started := time.Now()
			if err := projectContentHashes(ctx, tx, record.sourceRecordID, *record.hashes); err != nil {
				return fmt.Errorf("FI file child hash source record %d: %w", record.sourceRecordID, err)
			}
			if counters != nil {
				counters.Hashes += time.Since(started)
			}
		}
		started := time.Now()
		if err := projectSecurityACEs(ctx, tx, "fi.security_ace", record.sourceRecordID, record.value.Security.DACL.ACEs); err != nil {
			return fmt.Errorf("FI file child DACL source record %d: %w", record.sourceRecordID, err)
		}
		if counters != nil {
			counters.Security += time.Since(started)
		}
		started = time.Now()
		if err := projectSecurityACEs(ctx, tx, "fi.sacl_ace", record.sourceRecordID, record.value.SACL.ACL.ACEs); err != nil {
			return fmt.Errorf("FI file child SACL source record %d: %w", record.sourceRecordID, err)
		}
		if counters != nil {
			counters.SACL += time.Since(started)
		}
	}
	if counters != nil {
		counters.Observations += int64(len(pending))
	}
	return nil
}

func appendFileChildBulkRows(t *fileChildBulkTables, p fileObservationBulkRecord) error {
	id := p.sourceRecordID
	v := p.value
	if v.ContentPrefix != nil {
		observed, prefix, err := prepareContentPrefixProjection(*v.ContentPrefix)
		if err != nil {
			return err
		}
		t.prefix.rows = append(t.prefix.rows, []any{id, string(v.ContentPrefix.State), observed, prefix,
			nullString(v.ContentPrefix.ReasonCode), nullString(v.ContentPrefix.Detail)})
	}

	raw, err := decodeBase64URL(v.Reparse.RawBufferBase64URL, false, "reparse.raw_buffer")
	if err != nil {
		return err
	}
	substitute, err := decodeBase64URL(v.Reparse.SubstituteNameUTF16LEBase64URL, false, "reparse.substitute_name")
	if err != nil {
		return err
	}
	printName, err := decodeBase64URL(v.Reparse.PrintNameUTF16LEBase64URL, false, "reparse.print_name")
	if err != nil {
		return err
	}
	var tag any
	if v.Reparse.Tag != "" {
		parsed, e := parseUintFlexible(v.Reparse.Tag, 32, "reparse.tag")
		if e != nil {
			return e
		}
		tag = int64(parsed)
	}
	var flags any
	if v.Reparse.SymbolicLinkFlags != "" {
		parsed, e := parseUintFlexible(v.Reparse.SymbolicLinkFlags, 32, "reparse.symbolic_link_flags")
		if e != nil {
			return e
		}
		flags = int64(parsed)
	}
	t.reparse.rows = append(t.reparse.rows, []any{id, string(v.Reparse.State), string(v.Reparse.DataState),
		string(v.Reparse.DataFormat), tag, nullString(v.Reparse.TagName), raw, substitute, printName,
		flags, nullString(v.Reparse.ReasonCode)})

	t.inventory.rows = append(t.inventory.rows, []any{id, string(v.StreamInventory.State),
		nullString(v.StreamInventory.ReasonCode)})
	for i, stream := range v.StreamInventory.Streams {
		name, err := decodeBase64URL(stream.Identity.NameUTF16LEBase64URL, false, "stream.name")
		if err != nil {
			return err
		}
		rawName, err := decodeBase64URL(stream.Identity.RawNameUTF16LEBase64URL, true, "stream.raw_name")
		if err != nil {
			return err
		}
		logical, err := fileBulkNumeric(stream.LogicalSize)
		if err != nil {
			return fmt.Errorf("stream.logical_size: %w", err)
		}
		allocated, err := fileBulkNumeric(stream.AllocatedSize)
		if err != nil {
			return fmt.Errorf("stream.allocated_size: %w", err)
		}
		t.streams.rows = append(t.streams.rows, []any{id, i + 1, string(stream.Identity.Kind), name,
			nullString(stream.Identity.StreamType), rawName, logical, allocated})
	}

	sec, err := prepareFileChildSecurityRow(id, v.Security)
	if err != nil {
		return err
	}
	t.security.rows = append(t.security.rows, sec)
	sacl, err := prepareFileChildSACLRow(id, v.SACL)
	if err != nil {
		return err
	}
	t.sacl.rows = append(t.sacl.rows, sacl)
	for i, warning := range v.Warnings {
		t.warnings.rows = append(t.warnings.rows, []any{id, i + 1, warning.Code, nullString(warning.Detail)})
	}
	return nil
}

func prepareFileChildSecurityRow(id int64, value records.SecurityObservation) ([]any, error) {
	raw, err := decodeBase64URL(value.RawDescriptorBase64URL, false, "security.raw_descriptor")
	if err != nil {
		return nil, err
	}
	revision, err := optionalUintValue(value.Revision, 8, "security.revision")
	if err != nil {
		return nil, err
	}
	control, err := optionalUintValue(value.Control, 16, "security.control")
	if err != nil {
		return nil, err
	}
	aclRevision, err := optionalUintValue(value.DACL.Revision, 8, "security.acl_revision")
	if err != nil {
		return nil, err
	}
	aclSize, err := optionalUintValue(value.DACL.Size, 32, "security.acl_size")
	if err != nil {
		return nil, err
	}
	return []any{id, string(value.State), string(value.DataFormat), raw, revision, control,
		nullString(value.OwnerSID), nullString(value.PrimaryGroupSID), nullString(string(value.DACL.State)),
		aclRevision, aclSize, nullString(value.ReasonCode)}, nil
}

func prepareFileChildSACLRow(id int64, value records.SACLObservation) ([]any, error) {
	raw, err := decodeBase64URL(value.RawDescriptorBase64URL, false, "sacl.raw_descriptor")
	if err != nil {
		return nil, err
	}
	revision, err := optionalUintValue(value.Revision, 8, "sacl.revision")
	if err != nil {
		return nil, err
	}
	control, err := optionalUintValue(value.Control, 16, "sacl.control")
	if err != nil {
		return nil, err
	}
	aclRevision, err := optionalUintValue(value.ACL.Revision, 8, "sacl.acl_revision")
	if err != nil {
		return nil, err
	}
	aclSize, err := optionalUintValue(value.ACL.Size, 32, "sacl.acl_size")
	if err != nil {
		return nil, err
	}
	return []any{id, string(value.State), string(value.DataFormat), raw, revision, control,
		nullString(string(value.ACL.State)), aclRevision, aclSize, nullString(value.ReasonCode)}, nil
}
