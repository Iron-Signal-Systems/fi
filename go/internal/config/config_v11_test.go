// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseVersion11OperationalConfiguration(t *testing.T) {
	input := `# FI configuration
version_id: 1.1

governed_root: D:\Shares\Finance

collector.collection_every = 1m
collector.supporting_refresh_every = 30m
collector.usn_every = 10m
collector.windows_security_every = 1m

spool.target_batch_bytes = 33554432 # 32 MiB
spool.max_record_bytes = 67108864 # 64 MiB
spool.max_batch_records = 262144

storage.spool_dir = D:\FI\spool
storage.stage_dir = C:\ProgramData\FI\transport-v2-drain\stage
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

troubleshoot.enabled = false
troubleshoot.allow_collector_cli_override = false
troubleshoot.allow_sender_cli_override = false
troubleshoot.allow_storage_cli_override = false
troubleshoot.allow_trust_cli_override = false
`

	value, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if value.VersionID != Version11 {
		t.Fatalf("version = %q", value.VersionID)
	}
	if value.Collector.CollectionEvery != time.Minute {
		t.Fatalf("collection interval = %s", value.Collector.CollectionEvery)
	}
	if value.Collector.USNEvery != 10*time.Minute {
		t.Fatalf("USN interval = %s", value.Collector.USNEvery)
	}
	if value.Collector.WindowsSecurityEvery != time.Minute {
		t.Fatalf("Windows Security interval = %s", value.Collector.WindowsSecurityEvery)
	}
	if value.Sender.GenerationInterval != 10*time.Minute {
		t.Fatalf("generation interval = %s", value.Sender.GenerationInterval)
	}
	if value.Sender.RecoveryTimeout != 2*time.Hour {
		t.Fatalf("recovery timeout = %s", value.Sender.RecoveryTimeout)
	}
	if value.Spool.TargetBatchBytes != 32*1024*1024 {
		t.Fatalf("target batch bytes = %d", value.Spool.TargetBatchBytes)
	}
	if value.Storage.SpoolDir != `D:\FI\spool` {
		t.Fatalf("spool dir = %q", value.Storage.SpoolDir)
	}
	if value.Storage.StateDir != `C:\ProgramData\FI\state` {
		t.Fatalf("state dir = %q", value.Storage.StateDir)
	}
	if value.Troubleshoot.Enabled {
		t.Fatal("troubleshooting unexpectedly enabled")
	}
}

func TestParseVersion11RejectsUnknownSetting(t *testing.T) {
	input := `version_id: 1.1
governed_root: D:\Shares\Finance
collector.collection_every = 1m
collector.supporting_refresh_every = 30m
collector.usn_every = 10m
collector.windows_security_every = 1m
spool.target_batch_bytes = 33554432
spool.max_record_bytes = 67108864
spool.max_batch_records = 262144
storage.spool_dir = D:\FI\spool
storage.stage_dir = C:\ProgramData\FI\stage
storage.state_dir = C:\ProgramData\FI\state
source.id = source.example
sender.poll_interval = 5s
sender.retry_backoff = 5s
sender.generation_interval = 10m
sender.generation_max_encoded_bytes = 68719476736
sender.generation_transfer_timeout = 2h
receiver.address = 127.0.0.1:8443
receiver.name = receiver.example
receiver.timeout = 30s
sender.generation_intervel = 1m
`
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "unknown setting") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseTransportTrust(t *testing.T) {
	input := `version_id: 1.0
trust.root_cert_sha256 = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
trust.transport_cert_sha256 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
trust.transport_issuer_sha256 = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
trust.batch_signing_cert_sha256 = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
trust.transport_crl = C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem
`

	value, err := ParseTransportTrust(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	if value.RootCertificateSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("root SHA-256 = %q", value.RootCertificateSHA256)
	}
	if value.TransportCertificateSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("transport SHA-256 = %q", value.TransportCertificateSHA256)
	}
	if value.TransportIssuerSHA256 != strings.Repeat("c", 64) {
		t.Fatalf("issuer SHA-256 = %q", value.TransportIssuerSHA256)
	}
	if value.BatchSigningCertificateSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("batch-signing SHA-256 = %q", value.BatchSigningCertificateSHA256)
	}
}

func TestParseTransportTrustRejectsMalformedFingerprint(t *testing.T) {
	input := `version_id: 1.0
trust.root_cert_sha256 = ROOT
trust.transport_cert_sha256 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
trust.transport_issuer_sha256 = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
trust.batch_signing_cert_sha256 = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
trust.transport_crl = C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem
`

	_, err := ParseTransportTrust(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected malformed SHA-256 fingerprint to be rejected")
	}
	if !strings.Contains(err.Error(), "exactly 64 hexadecimal characters") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseVersion11RejectsDuplicateSetting(t *testing.T) {
	input := validVersion11OperationalConfiguration() +
		"sender.poll_interval = 6s\n"

	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "duplicate setting") {
		t.Fatalf("error = %v, want duplicate setting rejection", err)
	}
}

func TestParseVersion11RejectsMissingRequiredSetting(t *testing.T) {
	input := strings.Replace(
		validVersion11OperationalConfiguration(),
		"storage.spool_dir = D:\\FI\\spool\n",
		"",
		1,
	)

	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want missing required setting rejection")
	}
}

func TestParseVersion11RejectsMalformedDuration(t *testing.T) {
	input := strings.Replace(
		validVersion11OperationalConfiguration(),
		"collector.collection_every = 1m",
		"collector.collection_every = not-a-duration",
		1,
	)

	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want malformed duration rejection")
	}
}

func TestParseVersion11RejectsMalformedNumber(t *testing.T) {
	input := strings.Replace(
		validVersion11OperationalConfiguration(),
		"spool.max_batch_records = 262144",
		"spool.max_batch_records = not-a-number",
		1,
	)

	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want malformed numeric setting rejection")
	}
}

func validVersion11OperationalConfiguration() string {
	return `version_id: 1.1
governed_root: D:\Shares\Finance
collector.collection_every = 1m
collector.supporting_refresh_every = 30m
collector.usn_every = 10m
collector.windows_security_every = 1m
spool.target_batch_bytes = 33554432
spool.max_record_bytes = 67108864
spool.max_batch_records = 262144
storage.spool_dir = D:\FI\spool
storage.stage_dir = C:\ProgramData\FI\stage
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
troubleshoot.enabled = false
troubleshoot.allow_collector_cli_override = false
troubleshoot.allow_sender_cli_override = false
troubleshoot.allow_storage_cli_override = false
troubleshoot.allow_trust_cli_override = false
`
}
