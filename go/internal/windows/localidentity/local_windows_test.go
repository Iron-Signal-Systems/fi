// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package localidentity

import (
	"context"
	"os"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectLocalPrincipals(t *testing.T) {
	name, err := os.Hostname()
	if err != nil || name == "" {
		t.Fatalf("hostname: %v", err)
	}
	snapshot, err := CollectLocalPrincipals(context.Background(), name)
	if err != nil {
		t.Fatalf("CollectLocalPrincipals: %v", err)
	}
	if err := records.ValidateLocalPrincipalSnapshot(snapshot); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(snapshot.Groups) == 0 {
		t.Fatal("expected at least one local group")
	}
}
