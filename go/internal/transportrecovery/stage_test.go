package transportrecovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestPrepareFrameExactReuseAndEncodedLimit(t *testing.T) {
	spoolDir := t.TempDir()
	stageDir := t.TempDir()
	first := writeTestPublishedBatch(t, spoolDir, "20260915T000001.000000000Z-0000000000000001", []byte("{}\n{}\n"))
	second := writeTestPublishedBatch(t, spoolDir, "20260915T000002.000000000Z-0000000000000002", []byte("{}\n{}\n"))
	index, _, err := BuildIndex([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	key, cert := testSigningCertificate(t, "iss-fs-01.iss.local")
	config := PrepareConfig{
		BatchSigner:             key,
		BatchSigningCertificate: cert,
		Index:                   index,
		MaxEncodedBytes:         1 << 20,
		RecoveryID:              "20260915T000003.000000000Z-0011223344556677",
		SourceID:                "iss-fs-01.iss.local",
		StageDir:                stageDir,
	}
	firstPrepared, err := PrepareFrame(config)
	if err != nil {
		t.Fatal(err)
	}
	secondPrepared, err := PrepareFrame(config)
	if err != nil {
		t.Fatal(err)
	}
	if firstPrepared.FramePath != secondPrepared.FramePath || firstPrepared.FrameSHA256 != secondPrepared.FrameSHA256 {
		t.Fatal("exact staged recovery frame was not reused")
	}

	config.RecoveryID = "20260915T000004.000000000Z-0011223344556677"
	config.MaxEncodedBytes = 1
	if _, err := PrepareFrame(config); !errors.Is(err, ErrEncodedLimitExceeded) {
		t.Fatalf("expected encoded limit error, got %v", err)
	}
}

func writeTestPublishedBatch(t *testing.T, dir, batchID string, data []byte) string {
	t.Helper()
	dataName := "batch-" + batchID + ".jsonl"
	dataPath := filepath.Join(dir, dataName)
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	records := 0
	for _, value := range data {
		if value == '\n' {
			records++
		}
	}
	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: records,
		RecordCount:     records,
		DataBytes:       int64(len(data)),
		DataSHA256:      hex.EncodeToString(digest[:]),
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath:   `C:\\Program Files\\FI\\fi.exe`,
			ExecutableSHA256: "55" + repeatHex("00", 31),
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
