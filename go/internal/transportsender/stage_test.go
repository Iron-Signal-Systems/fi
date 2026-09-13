// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

type outboundStageFixture struct {
	config OutboundFrameConfig
	data   []byte
}

func TestPrepareOutboundFrame(t *testing.T) {
	fixture := newOutboundStageFixture(t)

	result, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}
	if result.Disposition != OutboundFrameDispositionNew {
		t.Fatalf("Disposition = %q, want %q", result.Disposition, OutboundFrameDispositionNew)
	}
	if result.Sent.Descriptor.SourceID != fixture.config.SourceID {
		t.Fatalf("SourceID = %q, want %q", result.Sent.Descriptor.SourceID, fixture.config.SourceID)
	}
	stored, err := os.ReadFile(result.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if uint64(len(stored)) != result.Sent.FrameBytes {
		t.Fatalf("stored bytes = %d, sent frame bytes = %d", len(stored), result.Sent.FrameBytes)
	}
	info, err := os.Stat(result.FramePath)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("staged frame mode = %04o, want read-only", info.Mode().Perm())
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameConcurrentPreparationConverges(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	type response struct {
		result OutboundFrame
		err    error
	}
	start := make(chan struct{})
	responses := make(chan response, 2)
	for range 2 {
		go func() {
			<-start
			result, err := PrepareOutboundFrame(fixture.config)
			responses <- response{result: result, err: err}
		}()
	}
	close(start)

	first := <-responses
	second := <-responses
	for index, value := range []response{first, second} {
		if value.err != nil {
			t.Fatalf("concurrent result %d error = %v", index, value.err)
		}
	}
	if first.result.FramePath != second.result.FramePath {
		t.Fatalf("concurrent frame paths differ: %q vs %q", first.result.FramePath, second.result.FramePath)
	}
	if first.result.Sent != second.result.Sent {
		t.Fatalf("concurrent sent-frame facts differ: %#v vs %#v", first.result.Sent, second.result.Sent)
	}
	newCount := 0
	existingCount := 0
	for _, value := range []OutboundFrameDisposition{first.result.Disposition, second.result.Disposition} {
		switch value {
		case OutboundFrameDispositionNew:
			newCount++
		case OutboundFrameDispositionExisting:
			existingCount++
		default:
			t.Fatalf("unexpected disposition %q", value)
		}
	}
	if newCount != 1 || existingCount != 1 {
		t.Fatalf("NEW=%d EXISTING=%d, want 1 each", newCount, existingCount)
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameRejectsCorruptExistingStageWithoutReplacingIt(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	first, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("first PrepareOutboundFrame() error = %v", err)
	}

	corrupt, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	corrupt[0] ^= 0xff
	if err := os.Chmod(first.FramePath, 0o600); err != nil {
		t.Fatalf("os.Chmod() writable error = %v", err)
	}
	if err := os.WriteFile(first.FramePath, corrupt, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Chmod(first.FramePath, 0o400); err != nil {
		t.Fatalf("os.Chmod() read-only error = %v", err)
	}

	_, err = PrepareOutboundFrame(fixture.config)
	if err == nil {
		t.Fatal("PrepareOutboundFrame() error = nil, want corrupt-stage rejection")
	}
	if !strings.Contains(err.Error(), "validate existing FI outbound frame") {
		t.Fatalf("PrepareOutboundFrame() error = %q, want existing-stage rejection", err)
	}
	stored, readErr := os.ReadFile(first.FramePath)
	if readErr != nil {
		t.Fatalf("os.ReadFile() after rejection error = %v", readErr)
	}
	if !bytes.Equal(stored, corrupt) {
		t.Fatal("corrupt existing outbound frame was overwritten")
	}
}

func TestPrepareOutboundFrameSignalsSigningIdentityRequirement(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	fixture.config.BatchSigner = nil
	fixture.config.BatchSigningCertificate = nil

	_, err := PrepareOutboundFrame(fixture.config)
	if err == nil {
		t.Fatal("PrepareOutboundFrame() error = nil, want signing identity requirement")
	}
	if !errors.Is(err, ErrOutboundSigningIdentityRequired) {
		t.Fatalf(
			"PrepareOutboundFrame() error = %q, want ErrOutboundSigningIdentityRequired",
			err,
		)
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameRejectsNewFrameWithoutSigner(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	fixture.config.BatchSigner = nil

	_, err := PrepareOutboundFrame(fixture.config)
	if err == nil {
		t.Fatal("PrepareOutboundFrame() error = nil, want missing signer rejection")
	}
	if !strings.Contains(err.Error(), "batch signer is required") {
		t.Fatalf("PrepareOutboundFrame() error = %q, want missing signer rejection", err)
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameRejectsTamperedPublishedDataBeforeReuse(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	first, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("first PrepareOutboundFrame() error = %v", err)
	}

	dataPath := filepath.Join(
		filepath.Dir(fixture.config.ManifestPath),
		"batch-"+first.Sent.Descriptor.BatchID+".jsonl",
	)
	bad := append([]byte(nil), fixture.data...)
	bad[0] ^= 0x01
	if err := os.WriteFile(dataPath, bad, 0o600); err != nil {
		t.Fatalf("os.WriteFile() tampered data error = %v", err)
	}

	_, err = PrepareOutboundFrame(OutboundFrameConfig{
		ManifestPath: fixture.config.ManifestPath,
		SourceID:     fixture.config.SourceID,
		StageDir:     fixture.config.StageDir,
	})
	if err == nil {
		t.Fatal("PrepareOutboundFrame() error = nil, want published-data rejection")
	}
	if !strings.Contains(err.Error(), "verify published FI batch manifest") {
		t.Fatalf("PrepareOutboundFrame() error = %q, want published-batch verification rejection", err)
	}
	if _, statErr := os.Stat(first.FramePath); statErr != nil {
		t.Fatalf("durable outbound frame changed after source tamper: %v", statErr)
	}
}

func TestPrepareOutboundFrameReusesExactStageWithoutSigner(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	first, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("first PrepareOutboundFrame() error = %v", err)
	}
	before, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() before retry error = %v", err)
	}

	retry, err := PrepareOutboundFrame(OutboundFrameConfig{
		ManifestPath: fixture.config.ManifestPath,
		SourceID:     fixture.config.SourceID,
		StageDir:     fixture.config.StageDir,
	})
	if err != nil {
		t.Fatalf("retry PrepareOutboundFrame() error = %v", err)
	}
	if retry.Disposition != OutboundFrameDispositionExisting {
		t.Fatalf("retry disposition = %q, want %q", retry.Disposition, OutboundFrameDispositionExisting)
	}
	if retry.Sent != first.Sent {
		t.Fatalf("retry sent frame = %#v, want %#v", retry.Sent, first.Sent)
	}
	after, err := os.ReadFile(retry.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() after retry error = %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("exact staged frame changed during signer-free retry preparation")
	}
}

func TestValidateOutboundFrameConfigRejectsRelativePaths(t *testing.T) {
	fixture := newOutboundStageFixture(t)

	manifestRelative := fixture.config
	manifestRelative.ManifestPath = "batch.manifest.json"
	if err := validateOutboundFrameConfig(manifestRelative); err == nil ||
		!strings.Contains(err.Error(), "manifest path must be absolute") {
		t.Fatalf("manifest relative-path error = %v", err)
	}

	stageRelative := fixture.config
	stageRelative.StageDir = "outbound"
	if err := validateOutboundFrameConfig(stageRelative); err == nil ||
		!strings.Contains(err.Error(), "stage directory must be absolute") {
		t.Fatalf("stage relative-path error = %v", err)
	}
}

func assertNoOutboundOpenFiles(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".open") {
			t.Fatalf("provisional outbound file remains: %s", entry.Name())
		}
	}
}

func newOutboundStageFixture(t *testing.T) outboundStageFixture {
	t.Helper()
	const sourceID = "iss-fs-01.iss.local"

	spoolDir := t.TempDir()
	writer, err := spool.NewWriter(
		spoolDir,
		2,
		spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("a", 64),
		},
	)
	if err != nil {
		t.Fatalf("spool.NewWriter() error = %v", err)
	}
	if err := writer.Append("test", "scope", map[string]int{"value": 1}); err != nil {
		t.Fatalf("first spool Append() error = %v", err)
	}
	if err := writer.Append("test", "scope", map[string]int{"value": 2}); err != nil {
		t.Fatalf("second spool Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("spool Close() error = %v", err)
	}
	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf("finalized batches = %d, want 1", len(batches))
	}
	data, err := os.ReadFile(batches[0].DataPath)
	if err != nil {
		t.Fatalf("os.ReadFile() spool data error = %v", err)
	}

	key, certificate := newOutboundStageIdentity(t, sourceID)
	return outboundStageFixture{
		config: OutboundFrameConfig{
			BatchSigner:             key,
			BatchSigningCertificate: certificate,
			ManifestPath:            batches[0].ManifestPath,
			SourceID:                sourceID,
			StageDir:                t.TempDir(),
		},
		data: data,
	}
}

func newOutboundStageIdentity(t *testing.T, sourceID string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 9, 12, 22, 30, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         sourceID,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return key, certificate
}
