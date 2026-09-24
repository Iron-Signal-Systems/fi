// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSenderConfigRejectsUnauthorizedSenderOverride(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		false,
		false,
		false,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-poll-interval",
		"6s",
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want sender override rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI sender overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSenderConfigRejectsUnauthorizedStorageOverride(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		false,
		false,
		false,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-spool-dir",
		`D:\FI\alternate-spool`,
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want storage override rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI storage overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSenderConfigRejectsUnauthorizedTrustOverride(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		false,
		false,
		false,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-root-cert-sha256",
		strings.Repeat("a", 64),
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want trust override rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI transport-trust overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSenderConfigManifestRequiresStorageAuthority(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		true,
		true,
		false,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-manifest",
		`C:\FI\batch-1.manifest.json`,
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want storage authority rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI storage overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSenderConfigManifestRequiresSenderAuthority(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		true,
		false,
		true,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-manifest",
		`C:\FI\batch-1.manifest.json`,
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want sender authority rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI sender overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSenderConfigManifestUsesExactInputWhenAuthorized(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		true,
		true,
		true,
		false,
		false,
	)

	value, err := parseSenderConfigWithArgs(
		t,
		"-manifest",
		`C:\FI\batch-1.manifest.json`,
	)
	if err != nil {
		t.Fatal(err)
	}

	if value.ManifestPath != `C:\FI\batch-1.manifest.json` {
		t.Fatalf("manifest path = %q", value.ManifestPath)
	}
	if value.SpoolDir != "" {
		t.Fatalf(
			"spool dir = %q, want empty exact-manifest mode",
			value.SpoolDir,
		)
	}
}

func parseSenderConfigWithArgs(
	t *testing.T,
	args ...string,
) (senderConfig, error) {
	t.Helper()

	previous := os.Args
	os.Args = append([]string{"fi-sender"}, args...)
	t.Cleanup(func() {
		os.Args = previous
	})

	return parseSenderConfig()
}

func prepareSenderAuthorityTestConfig(
	t *testing.T,
	troubleshootEnabled bool,
	allowSender bool,
	allowStorage bool,
	allowTrust bool,
	allowCollector bool,
) {
	t.Helper()

	programData := t.TempDir()
	t.Setenv("ProgramData", programData)

	configDir := filepath.Join(
		programData,
		"FI",
		"config",
	)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	operational := `version_id: 1.1
governed_root: D:\Shares\Finance
collector.collection_every = 1m
collector.supporting_refresh_every = 30m
collector.usn_every = 10m
collector.windows_security_every = 1m
spool.target_batch_bytes = 33554432
spool.max_record_bytes = 67108864
spool.max_batch_records = 262144
storage.spool_dir = D:\FI\spool
storage.stage_dir = C:\ProgramData\FI\transport\stage
storage.state_dir = C:\ProgramData\FI\state
source.id = file-server-01.example.local
sender.poll_interval = 5s
sender.retry_backoff = 5s
sender.generation_interval = 10m
sender.generation_max_encoded_bytes = 68719476736
sender.generation_transfer_timeout = 2h
receiver.address = 10.0.0.50:8443
receiver.name = fi-receiver-01.example.local
receiver.timeout = 30s
troubleshoot.enabled = ` + boolText(troubleshootEnabled) + `
troubleshoot.allow_collector_cli_override = ` + boolText(allowCollector) + `
troubleshoot.allow_sender_cli_override = ` + boolText(allowSender) + `
troubleshoot.allow_storage_cli_override = ` + boolText(allowStorage) + `
troubleshoot.allow_trust_cli_override = ` + boolText(allowTrust) + `
`

	trust := `version_id: 1.0
trust.root_cert_sha256 = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
trust.transport_cert_sha256 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
trust.transport_issuer_sha256 = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
trust.batch_signing_cert_sha256 = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
trust.transport_crl = C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem
`

	if err := os.WriteFile(
		filepath.Join(configDir, "fi.conf"),
		[]byte(operational),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(configDir, "fi-transport-trust.conf"),
		[]byte(trust),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestParseSenderConfigManifestRejectsExplicitGenerationMode(t *testing.T) {
	prepareSenderAuthorityTestConfig(
		t,
		true,
		true,
		true,
		false,
		false,
	)

	_, err := parseSenderConfigWithArgs(
		t,
		"-manifest",
		`C:\FI\batch-1.manifest.json`,
		"-generation-interval",
		"1m",
	)
	if err == nil {
		t.Fatal("parseSenderConfig() error = nil, want contradictory mode rejection")
	}
	if !strings.Contains(
		err.Error(),
		"-generation-interval requires -spool-dir queue mode",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestWriteAuthorizedOverrideWarning(t *testing.T) {
	var output bytes.Buffer

	writeAuthorizedOverrideWarning(
		&output,
		[]string{"poll-interval"},
		[]string{"manifest"},
		[]string{"root-cert-sha256"},
	)

	got := output.String()

	for _, expected := range []string{
		"WARNING:",
		"poll-interval",
		"manifest",
		"root-cert-sha256",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("warning %q does not contain %q", got, expected)
		}
	}
}
