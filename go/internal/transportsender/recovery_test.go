package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
)

func TestHalveRecoveryIndexGeometric(t *testing.T) {
	members := make([]transportrecovery.Member, 100000)
	for i := range members {
		members[i].BatchID = "unused"
	}
	index := transportrecovery.Index{Version: transportrecovery.MemberIndexVersion, Members: members}
	first, ok := HalveRecoveryIndex(index)
	if !ok || len(first.Members) != 50000 {
		t.Fatalf("first halving = %d, want 50000", len(first.Members))
	}
	second, ok := HalveRecoveryIndex(first)
	if !ok || len(second.Members) != 25000 {
		t.Fatalf("second halving = %d, want 25000", len(second.Members))
	}
}

func TestAdvanceRecoveryQueueRequiresOldestPrefix(t *testing.T) {
	spoolDir := t.TempDir()
	batchA := "20260915T000001.000000000Z-0000000000000001"
	batchB := "20260915T000002.000000000Z-0000000000000002"
	batchC := "20260915T000003.000000000Z-0000000000000003"
	if err := os.WriteFile(
		filepath.Join(spoolDir, "batch-"+batchC+".manifest.json"),
		[]byte("placeholder"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	queue := &PublishedBatchQueue{
		spoolDir: spoolDir,
		manifestPaths: []string{
			filepath.Join(spoolDir, "batch-"+batchA+".manifest.json"),
			filepath.Join(spoolDir, "batch-"+batchB+".manifest.json"),
			filepath.Join(spoolDir, "batch-"+batchC+".manifest.json"),
		},
	}
	prepared := transportrecovery.PreparedFrame{
		Index: transportrecovery.Index{Version: transportrecovery.MemberIndexVersion, Members: []transportrecovery.Member{
			{BatchID: batchA},
			{BatchID: batchB},
		}},
	}
	if err := AdvanceRecoveryQueue(queue, prepared); err != nil {
		t.Fatal(err)
	}
	if len(queue.manifestPaths) != 1 || filepath.Base(queue.manifestPaths[0]) != "batch-"+batchC+".manifest.json" {
		t.Fatal("queue did not advance exact oldest recovery prefix")
	}
}

func TestRetireRecoveryMembersResumesAndPreflightsWholeSet(t *testing.T) {
	t.Run("resumes after manifest removal", func(t *testing.T) {
		spoolDir := t.TempDir()
		prepared, authorization := testRecoveryRetirementSet(t, spoolDir)

		first := prepared.Index.Members[0]
		if err := os.Remove(first.ManifestPath); err != nil {
			t.Fatal(err)
		}

		result, err := RetireRecoveryMembers(spoolDir, prepared, authorization)
		if err != nil {
			t.Fatal(err)
		}
		if result.Members != 2 || result.ManifestsRemoved != 1 || result.DataRemoved != 2 {
			t.Fatalf("unexpected retirement result: %+v", result)
		}
		for _, member := range prepared.Index.Members {
			for _, path := range []string{member.ManifestPath, member.DataPath} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("retired recovery artifact still exists: %s", path)
				}
			}
		}
	})

	t.Run("missing data with published manifest fail-stops before removal", func(t *testing.T) {
		spoolDir := t.TempDir()
		prepared, authorization := testRecoveryRetirementSet(t, spoolDir)

		first := prepared.Index.Members[0]
		if err := os.Remove(first.DataPath); err != nil {
			t.Fatal(err)
		}
		if _, err := RetireRecoveryMembers(spoolDir, prepared, authorization); err == nil {
			t.Fatal("recovery retirement unexpectedly accepted manifest-without-data state")
		}
		for _, member := range prepared.Index.Members {
			if _, err := os.Stat(member.ManifestPath); err != nil {
				t.Fatalf("preflight failure removed manifest %s: %v", member.ManifestPath, err)
			}
		}
		if _, err := os.Stat(prepared.Index.Members[1].DataPath); err != nil {
			t.Fatalf("preflight failure removed unaffected data: %v", err)
		}
	})
}

func testRecoveryRetirementSet(
	t *testing.T,
	spoolDir string,
) (transportrecovery.PreparedFrame, RecoveryAuthorization) {
	t.Helper()
	batchIDs := []string{
		"20260915T000011.000000000Z-0000000000000011",
		"20260915T000012.000000000Z-0000000000000012",
	}
	paths := make([]string, 0, len(batchIDs))
	for position, batchID := range batchIDs {
		data := []byte("{\"record\":" + string(rune('1'+position)) + "}\n")
		paths = append(paths, writeSenderRecoveryBatch(t, spoolDir, batchID, data))
	}
	members := make([]transportrecovery.Member, 0, len(paths))
	for _, path := range paths {
		member, err := transportrecovery.MemberFromPublishedManifest(path)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, member)
	}
	index := transportrecovery.Index{
		Version: transportrecovery.MemberIndexVersion,
		Members: members,
	}
	indexBytes, err := transportrecovery.MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	indexSHA, err := transportrecovery.IndexSHA256(indexBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes, err := index.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	recordCount, err := index.RecordCount()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := transportrecovery.Descriptor{
		Version:           transportrecovery.DescriptorVersion,
		SourceID:          "iss-fs-01.iss.local",
		RecoveryID:        "20260915T000100.000000000Z-0011223344556677",
		MemberCount:       uint64(len(members)),
		RecordCount:       recordCount,
		CanonicalBytes:    canonicalBytes,
		CanonicalSHA256:   "11" + repeatSenderHex("00", 31),
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  123,
		EncodedDataSHA256: "22" + repeatSenderHex("00", 31),
		IndexSHA256:       indexSHA,
		FirstBatchID:      members[0].BatchID,
		LastBatchID:       members[len(members)-1].BatchID,
	}
	prepared := transportrecovery.PreparedFrame{
		Descriptor:  descriptor,
		FrameBytes:  456,
		FramePath:   filepath.Join(spoolDir, "unused.firb"),
		FrameSHA256: "33" + repeatSenderHex("00", 31),
		Index:       index,
		IndexBytes:  indexBytes,
	}
	ack := transportrecovery.Acknowledgement{
		Version:           "fi-recovery-ack/0.1",
		Outcome:           transportrecovery.AcknowledgementDurableNew,
		SourceID:          descriptor.SourceID,
		RecoveryID:        descriptor.RecoveryID,
		MemberCount:       descriptor.MemberCount,
		CanonicalBytes:    descriptor.CanonicalBytes,
		CanonicalSHA256:   descriptor.CanonicalSHA256,
		EncodedDataBytes:  descriptor.EncodedDataBytes,
		EncodedDataSHA256: descriptor.EncodedDataSHA256,
		IndexSHA256:       descriptor.IndexSHA256,
		FirstBatchID:      descriptor.FirstBatchID,
		LastBatchID:       descriptor.LastBatchID,
		FrameBytes:        prepared.FrameBytes,
		FrameSHA256:       prepared.FrameSHA256,
	}
	if err := ack.Validate(); err != nil {
		t.Fatal(err)
	}
	return prepared, RecoveryAuthorization{acknowledgement: ack}
}

func writeSenderRecoveryBatch(t *testing.T, dir, batchID string, data []byte) string {
	t.Helper()
	dataName := "batch-" + batchID + ".jsonl"
	dataPath := filepath.Join(dir, dataName)
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: 1,
		RecordCount:     1,
		DataBytes:       int64(len(data)),
		DataSHA256:      hex.EncodeToString(digest[:]),
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: "44" + repeatSenderHex("00", 31),
		},
		CreatedAt:   "2026-09-15T00:00:00.000000000Z",
		CompletedAt: "2026-09-15T00:00:01.000000000Z",
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	manifestPath := filepath.Join(dir, "batch-"+batchID+".manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

func repeatSenderHex(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
