// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

func m1MakeReleaseTestRequest(
	t *testing.T,
) m1QuarantineReleaseRequest {
	t.Helper()

	base := t.TempDir()

	for _, directory := range []string{
		"quarantine", "history", "lock",
	} {
		if err := os.Mkdir(
			filepath.Join(base, directory), 0700,
		); err != nil {
			t.Fatal(err)
		}
	}

	return m1QuarantineReleaseRequest{
		EnrolledSources: []string{m1FS19, m1FS22},
		HistoryRoot:     filepath.Join(base, "history"),
		LockFile:        filepath.Join(base, "lock", "worker.lock"),
		Operator:        "m1-test-operator",
		QuarantineRoot:  filepath.Join(base, "quarantine"),
		Reason:          "Controlled test conflict reviewed and resolved",
		Reference:       "M1-RELEASE-TEST",
		SourceID:        m1FS19,
	}
}

func TestM1QuarantineReleaseAuditedAndRestorable(
	t *testing.T,
) {
	request := m1MakeReleaseTestRequest(t)
	store := m1QuarantineStore{Root: request.QuarantineRoot}

	if err := store.Persist(
		m1FS19,
		"RELATIONAL_CONFLICT",
		"m1-conflict-generation",
		"controlled fixture conflict",
	); err != nil {
		t.Fatal(err)
	}

	markerPath := filepath.Join(
		request.QuarantineRoot,
		m1FS19+".json",
	)

	originalRaw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(originalRaw)

	auditPath, err := m1ReleaseQuarantinedSource(request)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(markerPath); !errors.Is(
		err, os.ErrNotExist,
	) {
		t.Fatalf("quarantine marker still present: %v", err)
	}

	auditInfo, err := os.Lstat(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	if !auditInfo.Mode().IsRegular() ||
		auditInfo.Mode().Perm() != 0400 {
		t.Fatal("release audit has unsafe file permissions")
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	var release m1QuarantineReleaseRecord

	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatal(err)
	}

	if release.Version != m1ReleaseVersion ||
		release.SourceID != m1FS19 ||
		release.Marker.SourceID != m1FS19 ||
		release.Marker.Reason != "RELATIONAL_CONFLICT" ||
		release.MarkerSHA256 != hex.EncodeToString(digest[:]) ||
		release.Operator != request.Operator ||
		release.Reference != request.Reference ||
		release.Reason != request.Reason {
		t.Fatalf("release audit mismatch: %+v", release)
	}

	// Reopening durable quarantine after release must not
	// restore the reviewed source's old marker.
	reloaded := m1QuarantineStore{Root: request.QuarantineRoot}

	markers, err := reloaded.Load(request.EnrolledSources)
	if err != nil {
		t.Fatal(err)
	}

	if len(markers) != 0 {
		t.Fatalf("released source still quarantined: %+v", markers)
	}

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); err == nil {
		t.Fatal("second release without a marker was accepted")
	}

	t.Log("PASS: Audited release preserves original marker identity")
	t.Log("PASS: Release requires an existing quarantine marker")
	t.Log("PASS: New store instance observes deliberate release")
}

func TestM1QuarantineReleaseCannotBypassWorkerLock(
	t *testing.T,
) {
	request := m1MakeReleaseTestRequest(t)
	store := m1QuarantineStore{Root: request.QuarantineRoot}

	if err := store.Persist(
		m1FS19,
		"RECORDED_RECEIPT_INVALID",
		"",
		"controlled bad receipt",
	); err != nil {
		t.Fatal(err)
	}

	singleton, err := workerlock.Acquire(request.LockFile)
	if err != nil {
		t.Fatal(err)
	}
	defer singleton.Close()

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); !errors.Is(err, workerlock.ErrAlreadyHeld) {
		t.Fatalf(
			"release while worker lock held was not rejected: %v",
			err,
		)
	}

	markers, err := store.Load(request.EnrolledSources)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := markers[m1FS19]; !exists {
		t.Fatal("quarantine disappeared while lock was held")
	}

	entries, err := os.ReadDir(request.HistoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("release created an audit while worker lock held")
	}

	t.Log("PASS: Active worker lock prevents quarantine release")
}

func TestM1QuarantineReleaseFailsBeforeMarkerRemoval(
	t *testing.T,
) {
	request := m1MakeReleaseTestRequest(t)
	store := m1QuarantineStore{Root: request.QuarantineRoot}

	if err := store.Persist(
		m1FS19,
		"RELATIONAL_CONFLICT",
		"m1-conflict-generation",
		"controlled relational conflict",
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		request.HistoryRoot, 0755,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); err == nil {
		t.Fatal("unsafe audit directory allowed release")
	}

	markers, err := store.Load(request.EnrolledSources)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := markers[m1FS19]; !exists {
		t.Fatal("release failure cleared quarantine")
	}

	t.Log("PASS: Audit storage failure preserves quarantine")
}

func TestM1QuarantineReleaseRequiresExplicitReview(
	t *testing.T,
) {
	request := m1MakeReleaseTestRequest(t)

	request.Reference = ""

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); err == nil {
		t.Fatal("release accepted without review reference")
	}

	request.Reference = "M1-RELEASE-TEST"
	request.Reason = ""

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); err == nil {
		t.Fatal("release accepted without justification")
	}

	request.Reason = "Controlled review completed"
	request.SourceID = "../other-source"

	if _, err := m1ReleaseQuarantinedSource(
		request,
	); err == nil {
		t.Fatal("release accepted source traversal")
	}

	t.Log("PASS: Source, reference and justification required")
}
