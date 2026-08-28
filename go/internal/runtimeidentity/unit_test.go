// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package runtimeidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func TestCurrentExecutableMatchesIndependentSHA256(t *testing.T) {
	first, err := CurrentExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if first.Path == "" {
		t.Fatal("current executable path is empty")
	}
	if len(first.SHA256) != sha256.Size*2 {
		t.Fatalf("SHA-256 length = %d, want %d", len(first.SHA256), sha256.Size*2)
	}
	if _, err := hex.DecodeString(first.SHA256); err != nil {
		t.Fatalf("SHA-256 is not hexadecimal: %v", err)
	}

	file, err := os.Open(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(hasher.Sum(nil))
	if first.SHA256 != want {
		t.Fatalf("current executable SHA-256 = %q, want %q", first.SHA256, want)
	}

	second, err := CurrentExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("cached executable identity changed: first=%+v second=%+v", first, second)
	}
}
