// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBaselineRootStreamsContextBeforeObjects(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample.txt"), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := writeBaselineRoot(context.Background(), &output, root); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	events := []baselineEvent{}
	for scanner.Scan() {
		var event baselineEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode baseline line: %v\n%s", err, scanner.Text())
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(events) < 5 {
		t.Fatalf("baseline emitted %d events, want at least 5", len(events))
	}

	if events[0].Kind != baselineKindCollectorIdentity || events[0].CollectorIdentity == nil {
		t.Fatalf("first event = %+v, want collector identity", events[0])
	}

	if events[1].Kind != baselineKindSMBShareSnapshot {
		t.Fatalf("second event kind = %q, want %q", events[1].Kind, baselineKindSMBShareSnapshot)
	}
	if events[1].SMBShareSnapshot == nil && events[1].Error == "" {
		t.Fatal("SMB share event contains neither snapshot nor explicit error")
	}

	if events[2].Kind != baselineKindLocalPrincipals {
		t.Fatalf("third event kind = %q, want %q", events[2].Kind, baselineKindLocalPrincipals)
	}
	if events[2].LocalPrincipals == nil && events[2].Error == "" {
		t.Fatal("local principal event contains neither snapshot nor explicit error")
	}

	if events[3].Kind != baselineKindDirectoryPrincipals {
		t.Fatalf("fourth event kind = %q, want %q", events[3].Kind, baselineKindDirectoryPrincipals)
	}
	if events[3].DirectoryPrincipals == nil && events[3].Error == "" {
		t.Fatal("directory principal event contains neither snapshot nor explicit error")
	}

	foundObject := false
	for _, event := range events[4:] {
		if event.Kind != baselineKindNTFSObservation {
			t.Fatalf("unexpected event kind %q after baseline context", event.Kind)
		}
		if event.PathDisplay == "" || event.PathUTF16LEBase64URL == "" {
			t.Fatalf("NTFS event missing path identity: %+v", event)
		}
		if event.Observation != nil {
			foundObject = true
		}
	}
	if !foundObject {
		t.Fatal("baseline emitted no successful NTFS observations")
	}
}
