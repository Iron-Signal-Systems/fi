// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func m5dSignedFixture(t *testing.T) (*Store, Segment, Correlation, string, transportgeneration.PublishedGeneration) {
	t.Helper()
	s, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	if _, err := s.RecordSourceManifestLedger(seg, corr, dir); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "m5d-source"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	published, err := transportgeneration.CreateSealedGeneration(
		context.Background(), transportgeneration.CreateConfig{
			FrozenDir: raw, GenerationID: "m5a-test", SourceID: "m5d-source",
			SealedRoot:  filepath.Join(t.TempDir(), "seals"),
			BatchSigner: key, BatchSigningCertificate: cert,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return s, seg, corr, raw, published
}

func TestM5DSealedSourceHandoffSurvivesRestartWithoutCommitting(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	actual, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source")
	if err != nil {
		t.Fatal(err)
	}
	if actual.SourceBatchSHA256 != seg.SHA256 || actual.CorrelationSHA256 != corr.SHA256 ||
		actual.GenerationID != "m5a-test" || actual.EncodedSHA256 != published.Signed.Descriptor.EncodedDataSHA256 ||
		actual.CanonicalSHA256 != published.Signed.Descriptor.CanonicalSHA256 || actual.SourceLedgerSHA256 == "" {
		t.Fatalf("wrong handoff identity %+v", actual)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("handoff moved processing cursor")
	}
	other, err := Open(s.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := other.ReadSealedSourceHandoff(seg, corr)
	if err != nil || !found || loaded != actual {
		t.Fatalf("restart handoff=%+v found=%v err=%v", loaded, found, err)
	}
	if other.ProcessingCursor().NextUSN != "100" {
		t.Fatal("restart handoff advanced processing")
	}
	again, err := other.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source")
	if err != nil || again != actual {
		t.Fatalf("handoff not idempotent: %v", err)
	}
}

func TestM5DRejectsTamperedSealedBytesAndOriginalSource(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	if err := os.WriteFile(published.PayloadPath, []byte("broken zstd payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); err == nil {
		t.Fatal("altered sealed payload accepted")
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("handoff published after invalid sealed payload found=%v err=%v", found, err)
	}
}

func TestM5DRejectsWrongIdentityAndMutatedLedger(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "wrong-source"); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong FI source accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(raw, "unrelated"), []byte("injection"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); err == nil {
		t.Fatal("unrelated frozen artifact accepted")
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("unverified handoff written found=%v err=%v", found, err)
	}
}

func TestM5DTamperedHandoffRejectedAndCapacityAccounted(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	used, err := s.pendingBytesLocked()
	if err != nil {
		t.Fatal(err)
	}
	s.maxBytes = used + 1
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("handoff escaped shared capacity: %v", err)
	}
	s.maxBytes = DefaultMaxPendingBytes
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.sealedHandoffPath(seg), []byte(`{"version":"tampered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadSealedSourceHandoff(seg, corr); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mutated handoff accepted: %v", err)
	}
}

func TestM5DDecodedCanonicalMismatch(t *testing.T) {
	original := []byte("FI canonical payload immutable content")
	hash := sha256.Sum256(original)
	expected := hex.EncodeToString(hash[:])
	for _, tc := range []struct {
		name  string
		bytes []byte
		ok    bool
	}{
		{"valid", original, true},
		{"different", []byte("FI canonical payload immutablE content"), false},
		{"truncated", original[:len(original)-1], false},
		{"extra", append(append([]byte(nil), original...), '!'), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := verifyCanonicalStream(bytes.NewReader(tc.bytes), uint64(len(original)), expected)
			if err != nil || ok != tc.ok {
				t.Fatalf("verified=%v err=%v", ok, err)
			}
		})
	}
	data := filepath.Join(t.TempDir(), "sample.figz")
	file, err := os.Create(data)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := transportencoding.NewZstdEncoder(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write([]byte("different canonical data")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyDecodedSealedCanonical(data, uint64(len(original)), expected); !errors.Is(err, ErrConflict) {
		t.Fatalf("valid zstd but wrong canonical content accepted: %v", err)
	}
}

func TestM5DHandoffRemainsReadOnlyAfterOriginalsDisappear(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(raw); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || !found {
		t.Fatalf("historical handoff unavailable: found=%v err=%v", found, err)
	}
	if _, err := s.VerifyAndRecordSealedHandoff(seg, corr, raw, published.DirectoryPath, "m5d-source"); err == nil {
		t.Fatal("missing raw source incorrectly verified again")
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("historical handoff authorized cursor progression")
	}
}
