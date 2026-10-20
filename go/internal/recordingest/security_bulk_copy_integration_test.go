//go:build fi_security_copy_integration

package recordingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

func TestSecurityBulkCopyPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_SECURITY_COPY_TEST_DSN")
	expected := os.Getenv("FI_SECURITY_COPY_TEST_DATA")
	if dsn == "" || expected == "" {
		t.Fatal("isolated PostgreSQL configuration required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var directory, listen string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&directory); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(directory) != filepath.Clean(expected) || listen != "" {
		t.Fatalf("STOP: unexpected PostgreSQL server: %q %q", directory, listen)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.source_batch (
source_batch_id bigint PRIMARY KEY
)`,
		`CREATE TABLE fi.source_record (
source_record_id bigint GENERATED ALWAYS AS IDENTITY
    (START WITH 101 INCREMENT BY 7) PRIMARY KEY,
source_batch_id bigint NOT NULL REFERENCES fi.source_batch,
record_ordinal bigint NOT NULL,
version text NOT NULL,
record_kind text NOT NULL,
scope_id text NOT NULL,
written_at timestamptz NOT NULL,
record_bytes integer NOT NULL,
record_sha256 bytea NOT NULL,
ingest_version text NOT NULL,
UNIQUE (source_batch_id, record_ordinal)
)`,
		`CREATE TABLE fi.windows_security_event (
source_record_id bigint PRIMARY KEY REFERENCES fi.source_record,
observed_at timestamptz NOT NULL,
collection_method text NOT NULL,
channel text NOT NULL,
provider text NOT NULL,
event_id bigint NOT NULL,
version text,
event_record_id numeric NOT NULL,
time_created timestamptz NOT NULL,
computer text NOT NULL,
keywords text,
audit_result text NOT NULL,
scope_basis text NOT NULL,
subject_user_sid text,
subject_user_name text,
subject_domain_name text,
subject_logon_id text,
object_server text,
object_type text,
object_name text,
handle_id text,
process_id text,
process_name text,
access_mask text,
access_list text,
access_reason text,
transaction_id text,
file_name text,
link_name text,
source_ip text,
source_port text,
share_name text,
share_local_path text,
relative_target_name text,
old_security_descriptor text,
new_security_descriptor text,
subcategory_guid text,
audit_policy_changes text,
raw_xml_bytes integer NOT NULL,
raw_xml_sha256 bytea NOT NULL
)`,
		`CREATE TABLE fi.windows_security_event_scope (
source_record_id bigint NOT NULL
    REFERENCES fi.windows_security_event,
scope_ordinal integer NOT NULL,
scope_id text NOT NULL,
governed_root text NOT NULL,
PRIMARY KEY (source_record_id, scope_ordinal),
UNIQUE (source_record_id, scope_id)
)`,
		`CREATE TABLE fi.windows_security_event_field (
source_record_id bigint NOT NULL
    REFERENCES fi.windows_security_event,
field_ordinal integer NOT NULL,
name text NOT NULL,
value text NOT NULL,
PRIMARY KEY (source_record_id, field_ordinal)
)`,
		`INSERT INTO fi.source_batch VALUES (41)`,
	}

	for _, statement := range ddl {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	value := records.WindowsSecurityEventObservation{
		ObservedAt:       now,
		CollectionMethod: records.WindowsSecurityCollectionMethod,
		Channel:          "Security",
		Provider:         "Microsoft-Windows-Security-Auditing",
		EventID:          "4663",
		EventRecordID:    "18446744073709551615",
		TimeCreated:      now,
		Computer:         "fi-test.local",
		AuditResult:      records.WindowsSecurityAuditSuccess,
		ScopeBasis:       records.WindowsSecurityScopePathMatched,
		MatchedScopes: []records.WindowsSecurityMatchedScope{
			{ScopeID: "test-a", GovernedRoot: `C:\FI`},
		},
		Fields: []records.WindowsSecurityEventField{
			{Name: "AccessMask", Value: "0x1"},
			{Name: "ObjectName", Value: `C:\FI\test.txt`},
		},
		RawXML: "<Event><Test>first</Test></Event>",
	}

	pending := make([]securityBulkRecord, 0, 2)

	for i := 0; i < 2; i++ {
		current := value
		if i == 1 {
			current.EventRecordID = "18446744073709551614"
			current.RawXML = "<Event><Test>second</Test></Event>"
			current.MatchedScopes = []records.WindowsSecurityMatchedScope{
				{ScopeID: "test-a", GovernedRoot: `C:\FI`},
				{ScopeID: "test-b", GovernedRoot: `D:\FI`},
			}
			current.Fields = []records.WindowsSecurityEventField{
				{Name: "AccessMask", Value: "0x2"},
			}
		}

		payload, err := json.Marshal(current)
		if err != nil {
			t.Fatal(err)
		}
		envelope := spool.Record{
			Version:    SpoolRecordVersion,
			RecordKind: "WindowsSecurityEvent",
			ScopeID:    "test-a",
			WrittenAt:  now,
			Payload:    payload,
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')

		prepared, err := PrepareSourceRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := decodeHex(prepared.RecordSHA256, 32, true, "test.record_sha256")
		if err != nil {
			t.Fatal(err)
		}
		item, err := prepareSecurityBulkRecord(int64(i+1), prepared, digest)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, item)
	}

	if err := copySecurityBulk(
		ctx, tx, 41, pending, &ingestStageProfile{},
	); err != nil {
		t.Fatal(err)
	}

	var sources, events, scopes, fields int64
	err = tx.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.source_record),
 (SELECT count(*) FROM fi.windows_security_event),
 (SELECT count(*) FROM fi.windows_security_event_scope),
 (SELECT count(*) FROM fi.windows_security_event_field)
`).Scan(&sources, &events, &scopes, &fields)
	if err != nil {
		t.Fatal(err)
	}
	if sources != 2 || events != 2 || scopes != 3 || fields != 3 {
		t.Fatalf("COPY counts: sources=%d events=%d scopes=%d fields=%d",
			sources, events, scopes, fields)
	}

	var firstID, secondID int64
	err = tx.QueryRow(ctx, `
SELECT min(source_record_id), max(source_record_id)
FROM fi.source_record
`).Scan(&firstID, &secondID)
	if err != nil {
		t.Fatal(err)
	}
	if firstID != 101 || secondID != 108 {
		t.Fatalf("generated identity mapping: %d %d", firstID, secondID)
	}

	var numericCount int64
	err = tx.QueryRow(ctx, `
SELECT count(*)
FROM fi.windows_security_event
WHERE event_record_id::text IN (
 '18446744073709551615',
 '18446744073709551614'
)
AND octet_length(raw_xml_sha256) = 32
`).Scan(&numericCount)
	if err != nil || numericCount != 2 {
		t.Fatalf("numeric/hash preservation: %d %v", numericCount, err)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var absent bool
	if err := conn.QueryRow(ctx,
		"SELECT to_regclass('fi.source_record') IS NULL",
	).Scan(&absent); err != nil {
		t.Fatal(err)
	}
	if !absent {
		t.Fatal("rollback failed")
	}

	t.Log("PASS: binary COPY, generated IDs, numeric, scopes, fields, hashes, rollback")
}
