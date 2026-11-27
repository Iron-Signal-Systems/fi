// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectComplete(t *testing.T) {
	paths := newTestPathSet(t)

	status, err := inspect(paths)
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}

	states := []struct {
		name  string
		state PathState
	}{
		{
			name:  "BatchCRL",
			state: status.BatchCRL,
		},
		{
			name:  "BatchIssuer",
			state: status.BatchIssuer,
		},
		{
			name:  "ReceiverCert",
			state: status.ReceiverCert,
		},
		{
			name:  "ReceiverKey",
			state: status.ReceiverKey,
		},
		{
			name:  "RootCA",
			state: status.RootCA,
		},
		{
			name:  "SourceRegistry",
			state: status.SourceRegistry,
		},
		{
			name:  "TransportCRL",
			state: status.TransportCRL,
		},
		{
			name:  "TransportIssuer",
			state: status.TransportIssuer,
		},
	}

	for _, check := range states {
		if !check.state.Present {
			t.Errorf("%s.Present = false, want true", check.name)
		}
	}

	if !status.Complete {
		t.Fatal("Status.Complete = false, want true")
	}
}

func TestInspectIncompleteWhenRequiredPathMissing(t *testing.T) {
	tests := []struct {
		name string
		path func(pathSet) string
	}{
		{
			name: "BatchCRL",
			path: func(paths pathSet) string {
				return paths.BatchCRL
			},
		},
		{
			name: "BatchIssuer",
			path: func(paths pathSet) string {
				return paths.BatchIssuer
			},
		},
		{
			name: "ReceiverCert",
			path: func(paths pathSet) string {
				return paths.ReceiverCert
			},
		},
		{
			name: "ReceiverKey",
			path: func(paths pathSet) string {
				return paths.ReceiverKey
			},
		},
		{
			name: "RootCA",
			path: func(paths pathSet) string {
				return paths.RootCA
			},
		},
		{
			name: "SourceRegistry",
			path: func(paths pathSet) string {
				return paths.SourceRegistry
			},
		},
		{
			name: "TransportCRL",
			path: func(paths pathSet) string {
				return paths.TransportCRL
			},
		},
		{
			name: "TransportIssuer",
			path: func(paths pathSet) string {
				return paths.TransportIssuer
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newTestPathSet(t)

			if err := os.Remove(test.path(paths)); err != nil {
				t.Fatalf("os.Remove() error = %v", err)
			}

			status, err := inspect(paths)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}

			if status.Complete {
				t.Fatal("Status.Complete = true, want false")
			}
		})
	}
}

func TestPathExists(t *testing.T) {
	root := t.TempDir()

	existing := filepath.Join(root, "existing")
	if err := os.WriteFile(existing, []byte("FI"), 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	present, err := pathExists(existing)
	if err != nil {
		t.Fatalf("pathExists() error = %v", err)
	}

	if !present {
		t.Fatal("pathExists() = false, want true")
	}
}

func TestPathExistsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")

	present, err := pathExists(path)
	if err != nil {
		t.Fatalf("pathExists() error = %v", err)
	}

	if present {
		t.Fatal("pathExists() = true, want false")
	}
}

func newTestPathSet(t *testing.T) pathSet {
	t.Helper()

	root := t.TempDir()

	paths := pathSet{
		BatchCRL:        filepath.Join(root, "batch.crl"),
		BatchIssuer:     filepath.Join(root, "batch.crt"),
		ReceiverCert:    filepath.Join(root, "receiver.crt"),
		ReceiverKey:     filepath.Join(root, "receiver.key"),
		RootCA:          filepath.Join(root, "root.crt"),
		SourceRegistry:  filepath.Join(root, "sources"),
		TransportCRL:    filepath.Join(root, "transport.crl"),
		TransportIssuer: filepath.Join(root, "transport.crt"),
	}

	files := []string{
		paths.BatchCRL,
		paths.BatchIssuer,
		paths.ReceiverCert,
		paths.ReceiverKey,
		paths.RootCA,
		paths.TransportCRL,
		paths.TransportIssuer,
	}

	for _, path := range files {
		if err := os.WriteFile(path, []byte("FI"), 0600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
	}

	if err := os.Mkdir(paths.SourceRegistry, 0700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}

	return paths
}
