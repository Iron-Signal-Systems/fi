// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
)

func TestCleanupRetiredOutboundFrame(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)
	retireCleanupSpool(t, fixture.config.ManifestPath, authorization)

	result, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	)
	if err != nil {
		t.Fatalf("CleanupRetiredOutboundFrame() error = %v", err)
	}
	if result.Disposition != OutboundCleanupDispositionRemoved {
		t.Fatalf(
			"cleanup disposition = %q, want %q",
			result.Disposition,
			OutboundCleanupDispositionRemoved,
		)
	}
	if result.SourceID != outbound.Sent.Descriptor.SourceID ||
		result.BatchID != outbound.Sent.Descriptor.BatchID {
		t.Fatalf(
			"cleanup identity = (%q, %q), want (%q, %q)",
			result.SourceID,
			result.BatchID,
			outbound.Sent.Descriptor.SourceID,
			outbound.Sent.Descriptor.BatchID,
		)
	}
	if _, err := os.Stat(outbound.FramePath); !os.IsNotExist(err) {
		t.Fatalf("staged outbound frame still exists after cleanup: %v", err)
	}
}

func TestCleanupRetiredOutboundFrameAlreadyRemoved(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)
	retireCleanupSpool(t, fixture.config.ManifestPath, authorization)

	if _, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	); err != nil {
		t.Fatalf("first CleanupRetiredOutboundFrame() error = %v", err)
	}

	result, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	)
	if err != nil {
		t.Fatalf("retry CleanupRetiredOutboundFrame() error = %v", err)
	}
	if result.Disposition != OutboundCleanupDispositionAlreadyRemoved {
		t.Fatalf(
			"retry cleanup disposition = %q, want %q",
			result.Disposition,
			OutboundCleanupDispositionAlreadyRemoved,
		)
	}
}

func TestCleanupRetiredOutboundFrameRejectsBeforeSpoolRetirement(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)

	_, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	)
	if err == nil {
		t.Fatal("CleanupRetiredOutboundFrame() error = nil, want retained spool rejection")
	}
	if !strings.Contains(err.Error(), "must be retained") {
		t.Fatalf(
			"CleanupRetiredOutboundFrame() error = %q, want retention requirement",
			err,
		)
	}
	if _, statErr := os.Stat(outbound.FramePath); statErr != nil {
		t.Fatalf("staged outbound frame changed after rejected cleanup: %v", statErr)
	}
}

func TestCleanupRetiredOutboundFrameRejectsPartialSpoolRetirement(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)

	if err := os.Remove(fixture.config.ManifestPath); err != nil {
		t.Fatalf("remove manifest fixture: %v", err)
	}
	dataPath := filepath.Join(
		filepath.Dir(fixture.config.ManifestPath),
		"batch-"+outbound.Sent.Descriptor.BatchID+".jsonl",
	)
	if _, err := os.Stat(dataPath); err != nil {
		t.Fatalf("expected data fixture before partial cleanup test: %v", err)
	}

	_, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	)
	if err == nil {
		t.Fatal("CleanupRetiredOutboundFrame() error = nil, want partial retirement rejection")
	}
	if !strings.Contains(err.Error(), "published FI batch data still exists") {
		t.Fatalf(
			"CleanupRetiredOutboundFrame() error = %q, want remaining data rejection",
			err,
		)
	}
	if _, statErr := os.Stat(outbound.FramePath); statErr != nil {
		t.Fatalf("staged outbound frame changed after partial retirement rejection: %v", statErr)
	}
}

func TestCleanupRetiredOutboundFrameRejectsMismatchedAuthorization(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)
	retireCleanupSpool(t, fixture.config.ManifestPath, authorization)

	acknowledgement, err := authorization.Acknowledgement()
	if err != nil {
		t.Fatalf("authorization.Acknowledgement() error = %v", err)
	}
	acknowledgement.FrameSHA256 = strings.Repeat("0", 64)
	mismatched := RetirementAuthorization{acknowledgement: acknowledgement}

	_, err = CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		mismatched,
	)
	if err == nil {
		t.Fatal("CleanupRetiredOutboundFrame() error = nil, want authorization mismatch")
	}
	if !strings.Contains(err.Error(), "frame SHA-256") {
		t.Fatalf(
			"CleanupRetiredOutboundFrame() error = %q, want frame mismatch",
			err,
		)
	}
	if _, statErr := os.Stat(outbound.FramePath); statErr != nil {
		t.Fatalf("staged outbound frame changed after authorization rejection: %v", statErr)
	}
}

func TestCleanupRetiredOutboundFrameRejectsTamperedStage(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)
	authorization := authorizeCleanupOutbound(t, outbound)
	retireCleanupSpool(t, fixture.config.ManifestPath, authorization)

	frame, err := os.ReadFile(outbound.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() stage error = %v", err)
	}
	frame[0] ^= 0xff
	if err := os.Chmod(outbound.FramePath, 0o600); err != nil {
		t.Fatalf("os.Chmod() writable error = %v", err)
	}
	if err := os.WriteFile(outbound.FramePath, frame, 0o600); err != nil {
		t.Fatalf("os.WriteFile() tampered stage error = %v", err)
	}
	if err := os.Chmod(outbound.FramePath, 0o400); err != nil {
		t.Fatalf("os.Chmod() read-only error = %v", err)
	}

	_, err = CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		authorization,
	)
	if err == nil {
		t.Fatal("CleanupRetiredOutboundFrame() error = nil, want tampered-stage rejection")
	}
	if !strings.Contains(err.Error(), "validate exact FI outbound frame") {
		t.Fatalf(
			"CleanupRetiredOutboundFrame() error = %q, want stage validation rejection",
			err,
		)
	}
	if _, statErr := os.Stat(outbound.FramePath); statErr != nil {
		t.Fatalf("tampered stage was removed after rejection: %v", statErr)
	}
}

func TestCleanupRetiredOutboundFrameRejectsZeroAuthorization(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareCleanupOutbound(t, fixture)

	_, err := CleanupRetiredOutboundFrame(
		outbound,
		fixture.config.ManifestPath,
		RetirementAuthorization{},
	)
	if err == nil {
		t.Fatal("CleanupRetiredOutboundFrame() error = nil, want zero authorization rejection")
	}
	if !strings.Contains(err.Error(), "cleanup authorization") {
		t.Fatalf(
			"CleanupRetiredOutboundFrame() error = %q, want authorization rejection",
			err,
		)
	}
	if _, statErr := os.Stat(outbound.FramePath); statErr != nil {
		t.Fatalf("staged outbound frame changed after zero authorization rejection: %v", statErr)
	}
}

func authorizeCleanupOutbound(t *testing.T, outbound OutboundFrame) RetirementAuthorization {
	t.Helper()
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	authorization, err := VerifyDurableAcknowledgement(
		bytes.NewReader(encodeAcknowledgement(t, acknowledgement)),
		outbound.Sent,
	)
	if err != nil {
		t.Fatalf("VerifyDurableAcknowledgement() error = %v", err)
	}
	return authorization
}

func prepareCleanupOutbound(t *testing.T, fixture outboundStageFixture) OutboundFrame {
	t.Helper()
	outbound, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}
	return outbound
}

func retireCleanupSpool(
	t *testing.T,
	manifestPath string,
	authorization RetirementAuthorization,
) {
	t.Helper()
	result, err := RetirePublishedBatch(manifestPath, authorization)
	if err != nil {
		t.Fatalf("RetirePublishedBatch() error = %v", err)
	}
	if result.Disposition != RetirementDispositionComplete {
		t.Fatalf(
			"retirement disposition = %q, want %q",
			result.Disposition,
			RetirementDispositionComplete,
		)
	}
}
