// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectParsingComplete(t *testing.T) {
	paths := newTestParsingPathSet(t)

	status := inspectParsing(paths)

	states := []struct {
		name  string
		state ParseState
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
			name:  "RootCA",
			state: status.RootCA,
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
		if !check.state.Parsed {
			t.Errorf(
				"%s.Parsed = false, want true: %s",
				check.name,
				check.state.Detail,
			)
		}

		if check.state.Detail != "" {
			t.Errorf(
				"%s.Detail = %q, want empty",
				check.name,
				check.state.Detail,
			)
		}
	}

	if !status.Complete {
		t.Fatal("ParseStatus.Complete = false, want true")
	}
}

func TestInspectParsingIncompleteWhenRequiredObjectInvalid(t *testing.T) {
	tests := []struct {
		name  string
		path  func(pathSet) string
		state func(ParseStatus) ParseState
	}{
		{
			name: "BatchCRL",
			path: func(paths pathSet) string {
				return paths.BatchCRL
			},
			state: func(status ParseStatus) ParseState {
				return status.BatchCRL
			},
		},
		{
			name: "BatchIssuer",
			path: func(paths pathSet) string {
				return paths.BatchIssuer
			},
			state: func(status ParseStatus) ParseState {
				return status.BatchIssuer
			},
		},
		{
			name: "ReceiverCert",
			path: func(paths pathSet) string {
				return paths.ReceiverCert
			},
			state: func(status ParseStatus) ParseState {
				return status.ReceiverCert
			},
		},
		{
			name: "RootCA",
			path: func(paths pathSet) string {
				return paths.RootCA
			},
			state: func(status ParseStatus) ParseState {
				return status.RootCA
			},
		},
		{
			name: "TransportCRL",
			path: func(paths pathSet) string {
				return paths.TransportCRL
			},
			state: func(status ParseStatus) ParseState {
				return status.TransportCRL
			},
		},
		{
			name: "TransportIssuer",
			path: func(paths pathSet) string {
				return paths.TransportIssuer
			},
			state: func(status ParseStatus) ParseState {
				return status.TransportIssuer
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newTestParsingPathSet(t)
			invalidPath := test.path(paths)

			if err := os.WriteFile(
				invalidPath,
				[]byte("not PEM"),
				0600,
			); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}

			status := inspectParsing(paths)

			if status.Complete {
				t.Fatal("ParseStatus.Complete = true, want false")
			}

			state := test.state(status)

			if state.Parsed {
				t.Fatal("ParseState.Parsed = true, want false")
			}

			if state.Detail == "" {
				t.Fatal("ParseState.Detail is empty, want parse error detail")
			}

			if state.Path != invalidPath {
				t.Fatalf(
					"ParseState.Path = %q, want %q",
					state.Path,
					invalidPath,
				)
			}
		})
	}
}

func newTestParsingPathSet(t *testing.T) pathSet {
	t.Helper()

	root := t.TempDir()

	certificatePEM, crlPEM := newTestCertificateAndCRL(t)

	paths := pathSet{
		BatchCRL:        filepath.Join(root, "batch.crl"),
		BatchIssuer:     filepath.Join(root, "batch.crt"),
		ReceiverCert:    filepath.Join(root, "receiver-fullchain.crt"),
		ReceiverKey:     filepath.Join(root, "receiver.key"),
		RootCA:          filepath.Join(root, "root.crt"),
		SourceRegistry:  filepath.Join(root, "sources"),
		TransportCRL:    filepath.Join(root, "transport.crl"),
		TransportIssuer: filepath.Join(root, "transport.crt"),
	}

	certificates := []string{
		paths.BatchIssuer,
		paths.RootCA,
		paths.TransportIssuer,
	}

	for _, path := range certificates {
		if err := os.WriteFile(path, certificatePEM, 0600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
	}

	receiverChain := make([]byte, 0, len(certificatePEM)*3)
	receiverChain = append(receiverChain, certificatePEM...)
	receiverChain = append(receiverChain, certificatePEM...)
	receiverChain = append(receiverChain, certificatePEM...)

	if err := os.WriteFile(
		paths.ReceiverCert,
		receiverChain,
		0600,
	); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", paths.ReceiverCert, err)
	}

	crls := []string{
		paths.BatchCRL,
		paths.TransportCRL,
	}

	for _, path := range crls {
		if err := os.WriteFile(path, crlPEM, 0600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
	}

	return paths
}
