//go:build fi_bootstrap_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "context"
 "crypto/md5"
 "crypto/sha1"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
 "time"
 "unicode/utf16"

 "github.com/Iron-Signal-Systems/fi/go/internal/records"
 "github.com/Iron-Signal-Systems/fi/go/internal/spool"
 "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
 "github.com/jackc/pgx/v5"
)

const ciPromoteFileScope = "fi-backlog-file-scope"

func ciPromoteFileUTF16Path(path string) string {
	u := utf16.Encode([]rune(path))
	data := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(data[i*2:], v)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// A production-shaped observation, with repeatable volume/root/object keys,
// independent file metadata and the normal content hash and child families.
func ciPromoteFileObservation(index int, observed string) (fileObservationPayload, error) {
	const rootPath = `C:\FI-Backlog-File`
	const volumeGUID = `\\?\Volume{12345678-1234-1234-1234-123456789abc}\`
	volume := records.VolumeIdentity{
		MethodVersion: ntfs.IdentityMethodVersion, VolumeGUID: volumeGUID, VolumeSerial: "123456789",
	}
	rootObj := records.NTFSObjectIdentity{
		MethodVersion: ntfs.IdentityMethodVersion, FileReferenceNumber: "5", SequenceNumber: "1",
	}
	obj := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: strconv.Itoa(1000 + index), SequenceNumber: "1",
	}
	path := fmt.Sprintf(`%s\file-%06d.bin`, rootPath, index)
	content := []byte(fmt.Sprintf("%016d", index))
	md5sum := md5.Sum(content)
	sha1sum := sha1.Sum(content)
	sha256sum := sha256.Sum256(content)
	hashes := records.ContentHashObservation{
		State: records.ContentHashPresent, BytesHashed: "16",
		MD5: hex.EncodeToString(md5sum[:]), SHA1: hex.EncodeToString(sha1sum[:]),
		SHA256: hex.EncodeToString(sha256sum[:]),
	}
	prefix := records.ContentPrefixObservation{
		State: records.ContentPrefixPresent, BytesObserved: "16",
		PrefixBase64URL: base64.RawURLEncoding.EncodeToString(content),
	}
	sd := make([]byte, 20)
	sd[0] = 1
	sd[3] = 0x80
	security, err := records.ParseSecurityDescriptor(sd)
	if err != nil {
		return fileObservationPayload{}, err
	}
	sacl, err := records.ParseSACLDescriptor(sd)
	if err != nil {
		return fileObservationPayload{}, err
	}
	stream := records.StreamIdentityFromRawUTF16(utf16.Encode([]rune(`::$DATA`)))
	obs := ntfs.Observation{
		GovernedRoot: records.GovernedRootIdentity{
			ScopeID:                       ciPromoteFileScope,
			RequestedPathUTF16LEBase64URL: ciPromoteFileUTF16Path(rootPath),
			ResolvedPathUTF16LEBase64URL:  ciPromoteFileUTF16Path(rootPath),
			MethodVersion:                 ntfs.ContainmentMethodVersion, VolumeIdentity: volume, ObjectIdentity: rootObj,
		},
		Containment:    records.PathContainment{MethodVersion: ntfs.ContainmentMethodVersion},
		VolumeIdentity: volume, ObjectIdentity: obj,
		ParentBinding: records.ParentObjectBindingFor(rootObj),
		SubjectKind:   records.SubjectFile,
		PathBinding: records.PathBinding{
			RequestedPathUTF16LEBase64URL: ciPromoteFileUTF16Path(path),
			ResolvedPathUTF16LEBase64URL:  ciPromoteFileUTF16Path(path),
		},
		ObservedAt: observed,
		Metadata: records.MetadataObservation{
			LogicalSize: "16", AllocatedSize: "4096", CreationTime: observed,
			LastWriteTime: observed, ChangeTime: observed, LastAccessTime: observed,
			RawAttributes: "32", LinkCount: "1",
		},
		Security: security, SACL: sacl,
		Reparse: records.ReparseObservation{
			State:      records.ReparseStateNotPresent,
			DataState:  records.ReparseDataStateNotApplicable,
			DataFormat: records.ReparseDataFormatNotApplicable,
		},
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
			Streams: []records.StreamObservation{{
				Identity: stream, LogicalSize: "16", AllocatedSize: "4096",
			}},
		},
		ContentHashes: &hashes, ContentPrefix: &prefix,
		CollectionEntryMethod: ntfs.CollectionEntryPath,
		CollectionMethod:      records.CollectionDirectWindowsNTFS,
		ObservationStatus:     records.ObservationComplete,
	}
	return fileObservationPayload{NTFS: obs, ContentHashes: hashes}, nil
}

func ciPromoteFileFixture(t *testing.T, source string, badLate bool) *PreparedGeneration {
	t.Helper()
	g := bootstrapCIFixture(t, source, false)
	g.Receipt.Descriptor.GenerationID = "20261101T140000.000000000Z-file"
	g.Receipt.TransferSHA256 = strings.Repeat("9", 64)
	g.ReceiptSHA256 = strings.Repeat("a", 64)
	if badLate {
		g.Receipt.Descriptor.GenerationID = "20261101T140001.000000000Z-file-reject"
		g.Receipt.TransferSHA256 = strings.Repeat("b", 64)
		g.ReceiptSHA256 = strings.Repeat("c", 64)
	}
	g.Receipt.DataBytes = 0
	const observed = "2026-11-01T14:00:00.123456789Z"
	for bi := range g.Batches {
		b := &g.Batches[bi]
		var data []byte
		for n := 0; n < b.Manifest.RecordCount; n++ {
			index := bi*3 + n
			if bi == 1 && n == 0 {
				index = 0
			} // reobserve original object after restart
			value, err := ciPromoteFileObservation(index, observed)
			if err != nil {
				t.Fatal(err)
			}
			if badLate && bi == 1 && n == 2 {
				// Envelope and batch digests remain valid; the typed file
				// observation must reject this after first-batch COPY.
				value.NTFS.ObservationStatus = "invalid-synthetic-status"
			}
			payload, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			envelope := spool.Record{
				Version: SpoolRecordVersion, RecordKind: "FileObservation",
				ScopeID: ciPromoteFileScope, WrittenAt: observed, Payload: payload,
			}
			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, encoded...)
			data = append(data, '\n')
		}
		path := filepath.Join(t.TempDir(), "file.jsonl")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		b.DataPath = path
		b.Manifest.DataBytes = int64(len(data))
		dataSHA := sha256.Sum256(data)
		b.Manifest.DataSHA256 = hex.EncodeToString(dataSHA[:])
		raw, err := json.Marshal(b.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		b.ManifestRawBytes = raw
		b.ManifestBytes = len(raw)
		manifestSHA := sha256.Sum256(raw)
		b.ManifestSHA256 = hex.EncodeToString(manifestSHA[:])
		g.Receipt.DataBytes += uint64(len(data))
	}
	return g
}


func ciPromoteSecurityFixture(t *testing.T, source string, invalidLate bool) *PreparedGeneration {
	t.Helper()
	g := bootstrapCIFixture(t, source, false)
	if invalidLate {
		g.Receipt.Descriptor.GenerationID = "20261101T130002.000000000Z-security-reject"
		g.Receipt.TransferSHA256 = strings.Repeat("a", 64)
		g.ReceiptSHA256 = strings.Repeat("b", 64)
	}
	g.Receipt.DataBytes = 0
	for bi := range g.Batches {
		b := &g.Batches[bi]
		var data []byte
		for n := 0; n < b.Manifest.RecordCount; n++ {
			num := bi*3 + n
			scopes := []records.WindowsSecurityMatchedScope{
				{ScopeID: "security-window", GovernedRoot: `C:\FI-Window`},
			}
			if num%2 == 0 {
				scopes = append(scopes, records.WindowsSecurityMatchedScope{
					ScopeID: "security-secondary", GovernedRoot: `D:\FI-Window`,
				})
			}
			fields := []records.WindowsSecurityEventField{
				{Name: "AccessMask", Value: "0x2"},
				{Name: "ObjectName", Value: fmt.Sprintf(`C:\FI-Window\object-%d.txt`, num)},
			}
			if num%2 == 1 {
				fields = append(fields, records.WindowsSecurityEventField{
					Name: "HandleId", Value: fmt.Sprintf("0x%x", num+1),
				})
			}
			event := records.WindowsSecurityEventObservation{
				ObservedAt:       "2026-11-01T13:00:00.123456789Z",
				CollectionMethod: records.WindowsSecurityCollectionMethod,
				Channel:          "Security",
				Provider:         "Microsoft-Windows-Security-Auditing",
				EventID:          "4663",
				EventRecordID:    strconv.Itoa(100000 + num),
				TimeCreated:      "2026-11-01T13:00:00.123456789Z",
				Computer:         "fi-security-window-test.iss.local",
				AuditResult:      records.WindowsSecurityAuditSuccess,
				ScopeBasis:       records.WindowsSecurityScopePathMatched,
				MatchedScopes:    scopes,
				Fields:           fields,
				RawXML:           fmt.Sprintf("<Event><EventRecordID>%d</EventRecordID></Event>", 100000+num),
			}
			if invalidLate && bi == 1 && n == 2 {
				event.EventRecordID = "invalid-event-record-id"
			} else if err := records.ValidateWindowsSecurityEventObservation(event); err != nil {
				t.Fatalf("invalid synthetic event %d: %v", num, err)
			}
			payload, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			envelope := spool.Record{
				Version: SpoolRecordVersion, RecordKind: "WindowsSecurityEvent",
				ScopeID:   "security-window",
				WrittenAt: "2026-11-01T13:00:00.123456789Z",
				Payload:   payload,
			}
			record, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, record...)
			data = append(data, '\n')
		}
		path := filepath.Join(t.TempDir(), "security.jsonl")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		b.DataPath = path
		b.Manifest.DataBytes = int64(len(data))
		h := sha256.Sum256(data)
		b.Manifest.DataSHA256 = hex.EncodeToString(h[:])
		manifest, err := json.Marshal(b.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		b.ManifestRawBytes = manifest
		b.ManifestBytes = len(manifest)
		mh := sha256.Sum256(manifest)
		b.ManifestSHA256 = hex.EncodeToString(mh[:])
		g.Receipt.DataBytes += uint64(len(data))
	}
	return g
}


const ciPromoteUSNScope = "usn-recovery-scope"
const ciPromoteUSNObservedAt = "2026-11-01T14:00:00.123456789Z"

func ciPromoteUSNBoundary(sourceBound bool, expectedObjects int) usnReadBoundaryPayload {
	b := usnReadBoundaryPayload{
		ObservedAt:       ciPromoteUSNObservedAt,
		CollectionMethod: records.WindowsUSNCollectionMethod,
		VolumeIdentity: records.VolumeIdentity{
			MethodVersion: ntfs.IdentityMethodVersion,
			VolumeGUID:    `\\?\Volume{12345678-1234-1234-1234-123456789abc}\`,
			VolumeSerial:  "123456789",
		},
		JournalID: "7", StartUSN: "100", NextUSN: "200",
		SourceRecordCount:          expectedObjects,
		SourceDistinctObjectCount:  expectedObjects,
		SelectedRecordCount:        expectedObjects,
		SelectedObjectCount:        expectedObjects,
		ScopeUnresolvedObjectCount: expectedObjects,
		ReObservationOperationID:   "fi-recovery-reobserve",
		USNReadOperationID:         "fi-recovery-legacy-read",
	}
	if sourceBound {
		b.SourceBatchSHA256 = strings.Repeat("a", 64)
		b.CorrelationSHA256 = strings.Repeat("b", 64)
		root := records.NTFSObjectIdentity{
			MethodVersion:       ntfs.IdentityMethodVersion,
			FileReferenceNumber: "5", SequenceNumber: "1",
		}
		b.RootIdentity = &root
		b.USNReadOperationID = ""
	}
	return b
}

func ciPromoteUSNObject(frn int, sourceBound bool, invalidChange bool) usnObjectObservationPayload {
	file := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: fmt.Sprint(frn), SequenceNumber: "1",
	}
	parent := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "5", SequenceNumber: "1",
	}
	change := records.USNChangeObservation{
		MajorVersion: "2", MinorVersion: "0", FileIdentity: file, ParentIdentity: parent,
		USN: fmt.Sprint(frn * 10), Timestamp: ciPromoteUSNObservedAt,
		ReasonRaw: "2", ReasonNames: []string{"CLOSE", "FILE_CREATE"},
		SourceInfoRaw: "0", SecurityID: "0", FileAttributesRaw: "32",
		FileNameUTF16LEBase64URL: "ZgA",
	}
	if invalidChange {
		change.FileIdentity.FileReferenceNumber = "999999"
	}
	v := usnObjectObservationPayload{
		FileIdentity: file, ScopeBasis: "ScopeUnresolvedIncluded",
		Status: "Unavailable", ReasonCode: "TEST_UNAVAILABLE",
		Changes: []records.USNChangeObservation{change},
	}
	if sourceBound {
		v.SourceBatchSHA256 = strings.Repeat("a", 64)
	}
	return v
}

func ciPromoteUSNGap() records.USNContinuityGapObservation {
	return records.USNContinuityGapObservation{
		ObservedAt:       ciPromoteUSNObservedAt,
		CollectionMethod: records.WindowsUSNCollectionMethod,
		ScopeID:          ciPromoteUSNScope, GovernedRoot: `C:\FI-USN`,
		ReasonCode:          "TEST_JOURNAL_GAP",
		CheckpointJournalID: "7", CheckpointNextUSN: "100",
		CurrentJournalID: "8", CurrentFirstUSN: "200",
		CurrentLowestValidUSN: "200", CurrentNextUSN: "300",
		CoverageState:        records.USNContinuityGapCoverageIncomplete,
		ReconciliationAction: records.USNContinuityGapReconcileBaselineAndCatchUp,
	}
}

// The first committed window contains a legacy boundary/object and a
// continuity gap. The second contains an M6.1 source-bound boundary/object,
// plus a legacy object that must resolve the older legacy boundary in SQL.
// "late-invalid" fails after earlier valid USN changes and reason COPY.
// "incomplete" has a source-bound capture count that cannot close.
func ciPromoteUSNFixture(t *testing.T, source, scenario string) *PreparedGeneration {
	t.Helper()
	g := bootstrapCIFixture(t, source, false)
	hash := sha256.Sum256([]byte(source))
	g.Receipt.Descriptor.GenerationID = "20261101T140000.000000000Z-" + hex.EncodeToString(hash[:8])
	g.Receipt.TransferSHA256 = hex.EncodeToString(ciPromoteUSNSHA256String(source + "/transfer"))
	g.ReceiptSHA256 = hex.EncodeToString(ciPromoteUSNSHA256String(source + "/receipt"))
	g.Receipt.DataBytes = 0
	for bi := range g.Batches {
		b := &g.Batches[bi]
		var data []byte
		for n := 0; n < b.Manifest.RecordCount; n++ {
			var kind string
			var payload any
			if bi == 0 {
				switch n {
				case 0:
					kind = "USNReadBoundary"
					payload = ciPromoteUSNBoundary(false, 1)
				case 1:
					kind = "USNObjectObservation"
					payload = ciPromoteUSNObject(1000, false, false)
				case 2:
					if scenario == "split" || scenario == "split-overflow" || scenario == "split-missing" {
						kind = "USNReadBoundary"
						payload = ciPromoteUSNBoundary(true, 1)
					} else {
						kind = "USNContinuityGap"
						payload = ciPromoteUSNGap()
					}
				}
			} else {
				switch n {
				case 0:
					if scenario == "split" || scenario == "split-overflow" || scenario == "split-missing" {
						kind = "USNObjectObservation"
						payload = ciPromoteUSNObject(1001, scenario != "split-missing", false)
					} else {
						kind = "USNReadBoundary"
						expected := 1
						if scenario == "incomplete" {
							expected = 2
						}
						payload = ciPromoteUSNBoundary(true, expected)
					}
				case 1:
					kind = "USNObjectObservation"
					payload = ciPromoteUSNObject(1001, scenario != "split" && scenario != "split-missing", false)
				case 2:
					kind = "USNObjectObservation"
					payload = ciPromoteUSNObject(1002, false, scenario == "late-invalid")
				}
			}
			encodedPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			env := spool.Record{
				Version: SpoolRecordVersion, RecordKind: kind,
				ScopeID: ciPromoteUSNScope, WrittenAt: ciPromoteUSNObservedAt,
				Payload: encodedPayload,
			}
			encoded, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, encoded...)
			data = append(data, '\n')
		}
		path := filepath.Join(t.TempDir(), "usn.jsonl")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		b.DataPath = path
		b.Manifest.DataBytes = int64(len(data))
		batchDigest := sha256.Sum256(data)
		b.Manifest.DataSHA256 = hex.EncodeToString(batchDigest[:])
		manifestRaw, err := json.Marshal(b.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		b.ManifestRawBytes = manifestRaw
		b.ManifestBytes = len(manifestRaw)
		manifestDigest := sha256.Sum256(manifestRaw)
		b.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
		g.Receipt.DataBytes += uint64(len(data))
	}
	return g
}

func ciPromoteUSNSHA256String(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}


func TestPopulatedSoRSQLPromotionRemapsFIIdentitiesAndRollsBack(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("FI_BOOTSTRAP_CI_ALLOW_ISOLATED_WRITES")!="1"{
  t.Skip("requires disposable CI PostgreSQL 18")
 }
 ctx,done:=context.WithTimeout(context.Background(),7*time.Minute)
 defer done()
 aDSN:=os.Getenv("FI_BOOTSTRAP_CI_PG_ADMIN_DSN")
 iDSN:=os.Getenv("FI_BOOTSTRAP_CI_PG_INGEST_DSN")
 if aDSN==""||iDSN==""{t.Fatal("STOP: fresh CI DSNs required")}
 admin,err:=pgx.Connect(ctx,aDSN)
 if err!=nil{t.Fatal(err)}
 defer admin.Close(context.Background())
 var role,db,port string
 var version int
 var fiPresent bool
 if err=admin.QueryRow(ctx,`SELECT current_user,current_database(),current_setting('port'),
current_setting('server_version_num')::int,to_regnamespace('fi') IS NOT NULL`).Scan(
 &role,&db,&port,&version,&fiPresent);err!=nil{t.Fatal(err)}
 if role!="fi_m1_admin" || db!="fi" || port!="5432" || version<180000 || fiPresent{
  t.Fatalf("STOP: not fresh PostgreSQL CI: %s/%s/%s %d fi_present=%v",role,db,port,version,fiPresent)
 }
 for _,ddl:=range []string{
  `CREATE ROLE fi_owner NOLOGIN`,
  `CREATE ROLE fi_ingest LOGIN PASSWORD 'isolated-only-test'`,
 } {
  if _,err=admin.Exec(ctx,ddl);err!=nil{t.Fatal(err)}
 }
 for _,name:=range []string{"0001_relational.sql","0002_source_families.sql",
  "0003_usn_relational_identity.sql","0004_security_field_name_index.sql","0005_usn_capture_binding.sql"}{
  raw,e:=os.ReadFile(filepath.Join("..","..","..","database","schema",name))
  if e!=nil{t.Fatal(e)}
  if _,e=admin.Exec(ctx,string(raw),pgx.QueryExecModeSimpleProtocol);e!=nil{t.Fatalf("%s: %v",name,e)}
 }
 openIngester:=func()(*pgx.Conn,*pgx.Conn){
  t.Helper()
  writer,e:=pgx.Connect(ctx,iDSN);if e!=nil{t.Fatal(e)}
  reader,e:=pgx.Connect(ctx,iDSN);if e!=nil{t.Fatal(e)}
  return reader,writer
 }
 reader,writer:=openIngester()
 defer func(){_ = reader.Close(context.Background());_ = writer.Close(context.Background())}()
 resetPrivate:=func(){
  t.Helper()
  // This is an EMPTY, one-use CI container only. Never do this to
  // real custody, fi-m1, or a production/private backlog database.
  if _,e:=admin.Exec(ctx,"DROP SCHEMA IF EXISTS fi_recovery_projection CASCADE");e!=nil{t.Fatal(e)}
  if _,e:=admin.Exec(ctx,"DROP SCHEMA IF EXISTS fi_recovery CASCADE");e!=nil{t.Fatal(e)}
  if _,e:=admin.Exec(ctx,bootstrapCILedgerSchema,pgx.QueryExecModeSimpleProtocol);e!=nil{t.Fatal(e)}
  for _,name:=range []string{"0001_relational.sql","0002_source_families.sql",
   "0003_usn_relational_identity.sql","0004_security_field_name_index.sql","0005_usn_capture_binding.sql"}{
   raw,e:=os.ReadFile(filepath.Join("..","..","..","database","schema",name));if e!=nil{t.Fatal(e)}
   ddl,e:=RewritePrivateProjectionMigration(name,string(raw));if e!=nil{t.Fatal(e)}
   if _,e=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);e!=nil{t.Fatalf("private DDL %s: %v",name,e)}
  }
 }
 limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
 stage:=func(g *PreparedGeneration){
  t.Helper()
  privateRoot:=privateBacklogTestRoot(t)
  for i:=0;i<2;i++{
   if _,e:=MaterializeBacklogWindow(ctx,g,limits,i,privateRoot);e!=nil{t.Fatal(e)}
   if e:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,privateRoot);e!=nil{t.Fatal(e)}
   if e:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,privateRoot);e!=nil{t.Fatal(e)}
   if e:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,i,privateRoot);e!=nil{t.Fatal(e)}
  }
 }
 sourceID:="fi-multi-generation-file-security.iss.local"
 // FIRST signed FILE generation: canonical SoR starts empty.
 resetPrivate()
 first:=ciPromoteFileFixture(t,sourceID,false)
 first.Receipt.Descriptor.GenerationID="20261103T150000.000000000Z-files-one"
 stage(first)
 acceptedFirst,e:=BootstrapPromoteVerifiedBacklogToEmptySoR(ctx,reader,admin,first,limits,"fi-promote-seed")
 if e!=nil||acceptedFirst.Outcome!="Accepted"{t.Fatalf("first accepted: %+v err=%v",acceptedFirst,e)}
 var v1,obj1,root1,files1 int64
 if e=reader.QueryRow(ctx,`SELECT
  (SELECT count(*) FROM fi.ntfs_volume),
  (SELECT count(*) FROM fi.ntfs_object),
  (SELECT count(*) FROM fi.governed_root),
  (SELECT count(*) FROM fi.file_observation)`).Scan(&v1,&obj1,&root1,&files1);e!=nil{t.Fatal(e)}
 if v1<1 || obj1<2 || root1<1 || files1!=6{
  t.Fatalf("invalid first FI file generation volumes=%d objects=%d roots=%d files=%d",v1,obj1,root1,files1)
 }
 // SECOND signed FILE generation: exactly the same volume/root/objects.
 // Private IDs restart at 1; canonical IDs must be NEW for generation,
 // batch and source records while NTFS identities must be REUSED.
 _=reader.Close(ctx);_=writer.Close(ctx)
 resetPrivate()
 reader,writer=openIngester()
 second:=ciPromoteFileFixture(t,sourceID,false)
 second.Receipt.Descriptor.GenerationID="20261103T150001.000000000Z-files-two"
 second.Receipt.TransferSHA256=strings.Repeat("b",64)
 second.ReceiptSHA256=strings.Repeat("c",64)
 stage(second)
 if _,e=admin.Exec(ctx,`ALTER TABLE fi.content_prefix_observation
 ADD CONSTRAINT fi_populated_test_fail CHECK(false) NOT VALID`);e!=nil{t.Fatal(e)}
 // A late SQL failure must roll back every new source/child/NTFS row,
 // preserving the already accepted FIRST generation.
 if _,e=PromoteVerifiedBacklogToPopulatedSoR(ctx,reader,admin,second,limits,"fi-promote-late-fail");e==nil{
  t.Fatal("late canonical error erroneously accepted")
 }
 var afterFailed int64
 if e=reader.QueryRow(ctx,`SELECT count(*) FROM fi.source_record`).Scan(&afterFailed);e!=nil{t.Fatal(e)}
 if afterFailed!=6{t.Fatalf("late rollback changed authoritative source rows: %d",afterFailed)}
 if _,e=admin.Exec(ctx,`ALTER TABLE fi.content_prefix_observation DROP CONSTRAINT fi_populated_test_fail`);e!=nil{t.Fatal(e)}
 acceptedSecond,e:=PromoteVerifiedBacklogToPopulatedSoR(ctx,reader,admin,second,limits,"fi-promote-second")
 if e!=nil||acceptedSecond.Outcome!="Accepted" || acceptedSecond.RecordedGenerationID==acceptedFirst.RecordedGenerationID{
  t.Fatalf("second promotion not remapped: %+v err=%v",acceptedSecond,e)
 }
 var v2,obj2,root2,files2,records2 int64
 if e=reader.QueryRow(ctx,`SELECT
  (SELECT count(*) FROM fi.ntfs_volume),
  (SELECT count(*) FROM fi.ntfs_object),
  (SELECT count(*) FROM fi.governed_root),
  (SELECT count(*) FROM fi.file_observation),
  (SELECT count(*) FROM fi.source_record)`).Scan(&v2,&obj2,&root2,&files2,&records2);e!=nil{t.Fatal(e)}
 if v2!=v1 || obj2!=obj1 || root2!=root1 || files2!=12 || records2!=12{
  t.Fatalf("NTFS identity reuse failed: vols %d/%d objects %d/%d roots %d/%d files=%d records=%d",
   v1,v2,obj1,obj2,root1,root2,files2,records2)
 }
 retry,e:=PromoteVerifiedBacklogToPopulatedSoR(ctx,reader,admin,second,limits,"fi-promote-retry")
 if e!=nil || retry.Outcome!="AlreadyAccepted" {t.Fatalf("exact retry failed: %+v %v",retry,e)}
 // THIRD signed generation: Security events with multi-row scopes + fields.
 // This catches source-record FK remapping in the largest real-data tables.
 _=reader.Close(ctx);_=writer.Close(ctx)
 resetPrivate()
 reader,writer=openIngester()
 third:=ciPromoteSecurityFixture(t,sourceID,false)
 third.Receipt.Descriptor.GenerationID="20261103T150002.000000000Z-security-three"
 third.Receipt.TransferSHA256=strings.Repeat("d",64)
 third.ReceiptSHA256=strings.Repeat("e",64)
 stage(third)
 acceptedThird,e:=PromoteVerifiedBacklogToPopulatedSoR(ctx,reader,admin,third,limits,"fi-promote-security")
 if e!=nil||acceptedThird.Outcome!="Accepted"{t.Fatalf("third Security promotion: %+v %v",acceptedThird,e)}
 var sources,securityEvents,securityFields,securityScopes,acceptedJournals int64
 if e=reader.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.source_record),
 (SELECT count(*) FROM fi.windows_security_event),
 (SELECT count(*) FROM fi.windows_security_event_field),
 (SELECT count(*) FROM fi.windows_security_event_scope),
 (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).Scan(
 &sources,&securityEvents,&securityFields,&securityScopes,&acceptedJournals);e!=nil{t.Fatal(e)}
 if sources!=18||securityEvents!=6||securityFields!=15||securityScopes!=9||acceptedJournals!=3{
  t.Fatalf("remapped Security fields lost: source=%d events=%d fields=%d scopes=%d Accepted=%d",
   sources,securityEvents,securityFields,securityScopes,acceptedJournals)
 }
 // Verify exact source digest, kind, scope, original timestamp and
 // record ordinal, not merely table counts. Compare both directions so
 // additional or omitted authoritative rows cannot go unnoticed.
 pSource:=`SELECT sb.batch_id,sr.record_ordinal,sr.record_sha256,
sr.record_kind,sr.scope_id,sr.written_at,sr.record_bytes
FROM fi_recovery_projection.source_record sr
JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)`
 cSource:=`SELECT sb.batch_id,sr.record_ordinal,sr.record_sha256,
sr.record_kind,sr.scope_id,sr.written_at,sr.record_bytes
FROM fi.source_record sr
JOIN fi.source_batch sb USING(source_batch_id)
WHERE sb.recorded_generation_id=$1`
 assertSame:=func(name,p,c string){
  t.Helper()
  // Both generated statements have identical number/type of columns.
  q:="SELECT (SELECT count(*) FROM ("+p+" EXCEPT ALL "+c+") unmatched),"+
   "(SELECT count(*) FROM ("+c+" EXCEPT ALL "+p+") unexpected)"
  var missed,unexpected int64
  if e:=reader.QueryRow(ctx,q,acceptedThird.RecordedGenerationID).Scan(&missed,&unexpected);e!=nil{t.Fatalf("%s lineage SQL: %v",name,e)}
  if missed!=0||unexpected!=0{t.Fatalf("%s changed signed lineage: missing=%d unexpected=%d",name,missed,unexpected)}
 }
 assertSame("signed source records",pSource,cSource)
 pField:=`SELECT sb.batch_id,sr.record_ordinal,
 f.field_ordinal,f.name,f.value
 FROM fi_recovery_projection.windows_security_event_field f
 JOIN fi_recovery_projection.source_record sr USING(source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)`
 cField:=`SELECT sb.batch_id,sr.record_ordinal,
 f.field_ordinal,f.name,f.value
 FROM fi.windows_security_event_field f
 JOIN fi.source_record sr USING(source_record_id)
 JOIN fi.source_batch sb USING(source_batch_id)
 WHERE sb.recorded_generation_id=$1`
 assertSame("Security event fields",pField,cField)
 pScope:=`SELECT sb.batch_id,sr.record_ordinal,
 f.scope_ordinal,f.scope_id,f.governed_root
 FROM fi_recovery_projection.windows_security_event_scope f
 JOIN fi_recovery_projection.source_record sr USING(source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)`
 cScope:=`SELECT sb.batch_id,sr.record_ordinal,
 f.scope_ordinal,f.scope_id,f.governed_root
 FROM fi.windows_security_event_scope f
 JOIN fi.source_record sr USING(source_record_id)
 JOIN fi.source_batch sb USING(source_batch_id)
 WHERE sb.recorded_generation_id=$1`
 assertSame("Security event scopes",pScope,cScope)
 var identicalNumericIDs bool
 if e=reader.QueryRow(ctx,`SELECT EXISTS(
 SELECT 1 FROM fi_recovery_projection.source_record p
 JOIN fi_recovery_projection.source_batch pb ON pb.source_batch_id=p.source_batch_id
 JOIN fi.source_batch cb ON cb.batch_id=pb.batch_id AND cb.recorded_generation_id=$1
 JOIN fi.source_record c ON c.source_batch_id=cb.source_batch_id
   AND c.record_ordinal=p.record_ordinal
 WHERE p.source_record_id=c.source_record_id)`,
 acceptedThird.RecordedGenerationID).Scan(&identicalNumericIDs);e!=nil{t.Fatal(e)}
 if identicalNumericIDs{t.Fatal("private numeric source ID leaked unchanged into populated SoR")}
 // FOURTH signed generation contains a legacy USNReadBoundary,
 // an M6.1 source-bound boundary, changes and reason rows that span windows.
 // It reuses the earlier File family's NTFS volume/root objects.
 _=reader.Close(ctx);_=writer.Close(ctx)
 resetPrivate()
 reader,writer=openIngester()
 fourth:=ciPromoteUSNFixture(t,sourceID,"normal")
 fourth.Receipt.Descriptor.GenerationID="20261103T150003.000000000Z-usn-four"
 fourth.Receipt.TransferSHA256=strings.Repeat("7",64)
 fourth.ReceiptSHA256=strings.Repeat("8",64)
 stage(fourth)
 acceptedFourth,e:=PromoteVerifiedBacklogToPopulatedSoR(ctx,reader,admin,fourth,limits,"fi-promote-usn")
 if e!=nil || acceptedFourth.Outcome!="Accepted" {
  t.Fatalf("USN bound cross-window promotion: %+v err=%v",acceptedFourth,e)
 }
 var usnBoundary,usnObject,usnChange,usnReason,usnGap,totalRecords,acceptedTotal int64
 if e=reader.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.usn_read_boundary),
 (SELECT count(*) FROM fi.usn_object_observation),
 (SELECT count(*) FROM fi.usn_object_change),
 (SELECT count(*) FROM fi.usn_object_change_reason),
 (SELECT count(*) FROM fi.usn_continuity_gap),
 (SELECT count(*) FROM fi.source_record),
 (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).Scan(
  &usnBoundary,&usnObject,&usnChange,&usnReason,&usnGap,&totalRecords,&acceptedTotal);e!=nil{t.Fatal(e)}
 if usnBoundary!=2 || usnObject!=3 || usnChange!=3 || usnReason!=6 ||
  usnGap!=1 || totalRecords!=24 || acceptedTotal!=4{
  t.Fatalf("remapped USN lineage broken: boundary=%d objects=%d changes=%d reasons=%d gaps=%d source=%d Accepted=%d",
   usnBoundary,usnObject,usnChange,usnReason,usnGap,totalRecords,acceptedTotal)
 }
 var orphanedUSN int64
 if e=reader.QueryRow(ctx,`SELECT count(*) FROM fi.usn_object_observation u
LEFT JOIN fi.usn_read_boundary b ON b.source_record_id=u.usn_read_boundary_source_record_id
LEFT JOIN fi.ntfs_object n ON n.ntfs_object_id=u.ntfs_object_id
WHERE b.source_record_id IS NULL OR n.ntfs_object_id IS NULL`).Scan(&orphanedUSN);e!=nil{t.Fatal(e)}
 if orphanedUSN!=0{t.Fatalf("source-bound USN FK remap produced %d orphans",orphanedUSN)}
 t.Log("PASS: populated SoR 4 generations, signed lineage, shared NTFS, legacy+M6.1 USN references, fields/scopes, late rollback, retry and atomic Accepted")
}
