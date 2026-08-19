// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package ntfs

import (
	"context"
	"errors"
	"testing"
)

func TestNonWindowsCollectorIsExplicitlyUnsupported(t *testing.T) {
	_, err := CollectPath(context.Background(), "scope-test", `C:\approved`, `C:\approved\example`)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("error = %v", err)
	}
}
