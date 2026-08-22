// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathObservedAt(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("time"), 0o600); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC()
	observation, err := CollectPath(context.Background(), "scope-test", root, target)
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}

	observedAt, err := time.Parse("2006-01-02T15:04:05.000000000Z", observation.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if observedAt.Before(before) || observedAt.After(after) {
		t.Fatalf("observed_at = %s outside [%s, %s]", observedAt, before, after)
	}
}

// This is a native Windows integration test. It creates a real NTFS file and a
// real ADS, runs the production collector, and verifies the returned facts.
func TestCollectPathOnWindowsNTFS(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")

	if err := os.WriteFile(target, []byte("file intelligence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+`:payload`, []byte("hidden stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}

	if observation.SubjectKind != records.SubjectFile {
		t.Fatalf("subject kind = %s", observation.SubjectKind)
	}
	if observation.Metadata.LogicalSize != strconv.Itoa(len("file intelligence")) {
		t.Fatalf("logical size = %s", observation.Metadata.LogicalSize)
	}
	if observation.VolumeIdentity.VolumeGUID == "" ||
		observation.ObjectIdentity.FileReferenceNumber == "" {
		t.Fatalf("identity is incomplete: %+v %+v", observation.VolumeIdentity, observation.ObjectIdentity)
	}
	if observation.GovernedRoot.ScopeID != "scope-test" ||
		observation.GovernedRoot.ObjectIdentity.FileReferenceNumber == "" ||
		observation.Containment.MethodVersion == "" {
		t.Fatalf("scope result is incomplete: %+v %+v", observation.GovernedRoot, observation.Containment)
	}
	if observation.ObservedAt == "" {
		t.Fatal("observed_at is empty")
	}

	switch observation.ObservationStatus {
	case records.ObservationComplete:
		if observation.SACL.State != records.ObservationStatePresent {
			t.Fatalf("complete observation has SACL state %q", observation.SACL.State)
		}
	case records.ObservationPartial:
		if observation.SACL.State != records.ObservationStateError {
			t.Fatalf("partial observation has unexpected SACL state %q", observation.SACL.State)
		}
		if observation.SACL.ReasonCode != "SACLPrivilegeUnavailable" &&
			observation.SACL.ReasonCode != "SACLDescriptorReadFailed" {
			t.Fatalf("partial observation has unexpected SACL reason %q", observation.SACL.ReasonCode)
		}
	default:
		t.Fatalf("status = %s", observation.ObservationStatus)
	}

	foundDefault := false
	foundADS := false
	for _, stream := range observation.StreamInventory.Streams {
		if stream.Identity.Kind == records.StreamDefaultData {
			foundDefault = true
		}
		if stream.Identity.Kind == records.StreamNamedData {
			foundADS = true
		}
	}
	if !foundDefault || !foundADS {
		t.Fatalf("stream inventory missing default or named data stream: %+v", observation.StreamInventory.Streams)
	}
}

func TestCollectPathRejectsFileGovernedRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-root.txt")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := CollectPath(context.Background(), "scope-test", file, file)
	if !errors.Is(err, ErrGovernedRootNotDirectory) {
		t.Fatalf("error = %v, want ErrGovernedRootNotDirectory", err)
	}
}

func TestCollectPathRejectsSiblingEscape(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	target := filepath.Join(outsideRoot, "outside.txt")

	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := CollectPath(context.Background(), "scope-test", root, target)
	if !errors.Is(err, ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want ErrOutsideGovernedRoot", err)
	}
}
