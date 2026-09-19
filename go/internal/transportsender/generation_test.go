package transportsender

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestRolloverPublishedSpoolMovesEntireDirectoryAndReopensActivePath(t *testing.T) {
	parent := t.TempDir()
	spoolDir := filepath.Join(parent, "spool")
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	batchID := "20260916T100201.000000000Z-0000000000000001"
	manifestPath, dataPath := writeGenerationTestBatch(t, spoolDir, batchID, []byte("{\"record\":1}\n"))

	raw, found, err := RolloverPublishedSpool(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("non-empty FI spool was not rolled")
	}
	if filepath.Base(raw.GenerationDir) != generationDirectoryPrefix+raw.GenerationID {
		t.Fatal("raw generation directory identity is inconsistent")
	}
	if info, err := os.Stat(spoolDir); err != nil || !info.IsDir() {
		t.Fatalf("replacement active spool is missing: %v", err)
	}
	if entries, err := os.ReadDir(spoolDir); err != nil || len(entries) != 0 {
		t.Fatalf("replacement active spool is not empty: entries=%d err=%v", len(entries), err)
	}
	for _, oldPath := range []string{manifestPath, dataPath} {
		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Fatalf("old active-spool path still resolves after rollover: %s", oldPath)
		}
		if _, err := os.Stat(filepath.Join(raw.GenerationDir, filepath.Base(oldPath))); err != nil {
			t.Fatalf("frozen raw generation is missing %s: %v", filepath.Base(oldPath), err)
		}
	}
}

func generationTestSigningCertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func writeGenerationTestBatch(t *testing.T, dir string, batchID string, data []byte) (string, string) {
	t.Helper()
	dataName := "batch-" + batchID + ".jsonl"
	dataPath := filepath.Join(dir, dataName)
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	recordCount := 0
	for _, value := range data {
		if value == '\n' {
			recordCount++
		}
	}
	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: recordCount,
		RecordCount:     recordCount,
		DataBytes:       int64(len(data)),
		DataSHA256:      hex.EncodeToString(digest[:]),
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: "44" + generationRepeatHex("00", 31),
		},
		CreatedAt:   "2026-09-16T10:00:00.000000000Z",
		CompletedAt: "2026-09-16T10:00:01.000000000Z",
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
	return manifestPath, dataPath
}

func generationRepeatHex(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
