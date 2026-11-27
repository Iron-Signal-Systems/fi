// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(sum[:])
}

func testBackend(t *testing.T) (backend, string) {
	t.Helper()
	root := t.TempDir()
	b := backend{receiver: filepath.Join(root, "receiver"), ingest: filepath.Join(root, "ingest")}
	issuer, hash := testIssuer(t)
	for _, directory := range []string{b.receiver, b.ingest} {
		trustDir := filepath.Join(directory, "pki/trust")
		if err := os.MkdirAll(trustDir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(sourceRegistry(directory), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(trustDir, "fi-batch-signing-ca.crt.pem"), issuer, 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b.receiver, "pki/trust/fi-transport-ca.crt.pem"), issuer, 0640); err != nil {
		t.Fatal(err)
	}
	return b, hash
}

func testConfig(id, issuer, transport, batch string) []byte {
	return []byte(fmt.Sprintf(`version_id: 2.0
source_id: %s
enabled: true
transport_common_name: %s
transport_issuing_ca_sha256: %s
transport_certificate_sha256: %s
transport_template_oid: 1.2.3.4
batch_signing_common_name: %s
batch_signing_issuing_ca_sha256: %s
batch_signing_certificate_sha256: %s
batch_signing_template_oid: 1.2.3.5
`, id, id, issuer, transport, id, issuer, batch))
}

func testCandidate(t *testing.T, data []byte) sourceFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.conf")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readSourceFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func testFingerprint(ch byte) string { return strings.Repeat(string(ch), 64) }

func TestPlanAddBoth(t *testing.T) {
	b, issuer := testBackend(t)
	file := testCandidate(t, testConfig("iss-fs-a.example", issuer, testFingerprint('a'), testFingerprint('b')))
	p, err := b.plan(file)
	if err != nil {
		t.Fatal(err)
	}
	if !p.receiverNew || !p.ingestNew {
		t.Fatalf("unexpected plan: %+v", p)
	}
	if _, err := os.Stat(p.receiverPath); !os.IsNotExist(err) {
		t.Fatal("plan modified receiver")
	}
	if _, err := os.Stat(p.ingestPath); !os.IsNotExist(err) {
		t.Fatal("plan modified ingest")
	}
}

func TestPlanReconcileReceiverFirst(t *testing.T) {
	b, issuer := testBackend(t)
	file := testCandidate(t, testConfig("iss-fs-b.example", issuer, testFingerprint('c'), testFingerprint('d')))
	if err := os.WriteFile(filepath.Join(sourceRegistry(b.receiver), file.name), file.content, 0640); err != nil {
		t.Fatal(err)
	}
	p, err := b.plan(file)
	if err != nil {
		t.Fatal(err)
	}
	if p.receiverNew || !p.ingestNew {
		t.Fatalf("unexpected plan: %+v", p)
	}
}

func TestPlanIdempotent(t *testing.T) {
	b, issuer := testBackend(t)
	file := testCandidate(t, testConfig("iss-fs-c.example", issuer, testFingerprint('e'), testFingerprint('f')))
	for _, root := range []string{b.receiver, b.ingest} {
		if err := os.WriteFile(filepath.Join(sourceRegistry(root), file.name), file.content, 0640); err != nil {
			t.Fatal(err)
		}
	}
	p, err := b.plan(file)
	if err != nil {
		t.Fatal(err)
	}
	if p.receiverNew || p.ingestNew {
		t.Fatalf("idempotency failed: %+v", p)
	}
}

func TestPlanRejectsExistingConflict(t *testing.T) {
	b, issuer := testBackend(t)
	file := testCandidate(t, testConfig("iss-fs-d.example", issuer, testFingerprint('1'), testFingerprint('2')))
	conflict := testConfig("iss-fs-d.example", issuer, testFingerprint('3'), testFingerprint('4'))
	if err := os.WriteFile(filepath.Join(sourceRegistry(b.ingest), file.name), conflict, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := b.plan(file); err == nil {
		t.Fatal("replacement accepted")
	}
}

func TestPlanRejectsDuplicateCertificate(t *testing.T) {
	b, issuer := testBackend(t)
	existing := testCandidate(t, testConfig("iss-fs-e.example", issuer, testFingerprint('5'), testFingerprint('6')))
	if err := os.WriteFile(filepath.Join(sourceRegistry(b.receiver), existing.name), existing.content, 0640); err != nil {
		t.Fatal(err)
	}
	incoming := testCandidate(t, testConfig("iss-fs-f.example", issuer, testFingerprint('5'), testFingerprint('7')))
	if _, err := b.plan(incoming); err == nil {
		t.Fatal("duplicate transport cert accepted")
	}
}

func TestPlanRejectsWrongIssuer(t *testing.T) {
	b, _ := testBackend(t)
	incoming := testCandidate(t, testConfig("iss-fs-g.example", testFingerprint('8'), testFingerprint('9'), testFingerprint('a')))
	if _, err := b.plan(incoming); err == nil {
		t.Fatal("wrong issuing CA accepted")
	}
}

func TestTrustIsReadyExact(t *testing.T) {
	if !trustIsReady("Trust state            READY\n") {
		t.Fatal("READY rejected")
	}
	for _, value := range []string{"Trust state NOT READY", "Trust state INVALID", "Source registry READY"} {
		if trustIsReady(value) {
			t.Fatalf("unsafe trust status accepted: %q", value)
		}
	}
}

func TestStatusDetectsMissingIngest(t *testing.T) {
	b, issuer := testBackend(t)
	file := testCandidate(t, testConfig("iss-fs-h.example", issuer, testFingerprint('b'), testFingerprint('c')))
	if err := os.WriteFile(filepath.Join(sourceRegistry(b.receiver), file.name), file.content, 0640); err != nil {
		t.Fatal(err)
	}
	if err := b.status(file.config.Authorization.SourceID); err == nil {
		t.Fatal("incomplete registration accepted")
	}
}

func TestRejectsSymlinkSourceInput(t *testing.T) {
	_, issuer := testBackend(t)
	source := filepath.Join(t.TempDir(), "real.conf")
	if err := os.WriteFile(source, testConfig("iss-fs-i.example", issuer, testFingerprint('d'), testFingerprint('e')), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.conf")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSourceFile(link); err == nil {
		t.Fatal("symlink input accepted")
	}
}

// Activation selection is pure: tests never need to restart a live jail.
func TestActivationTargets(t *testing.T) {
	cases := []struct {
		name         string
		receiverNew  bool
		ingestNew    bool
		refresh      string
		receiverWant bool
		ingestWant   bool
		fail         bool
	}{
		{name: "no changes no restart"},
		{name: "receiver only", receiverNew: true, receiverWant: true},
		{name: "ingest only", ingestNew: true, ingestWant: true},
		{name: "both new", receiverNew: true, ingestNew: true, receiverWant: true, ingestWant: true},
		{name: "recover failed ingest restart", refresh: "ingest", ingestWant: true},
		{name: "recover failed receiver restart", refresh: "receiver", receiverWant: true},
		{name: "recover both", refresh: "both", receiverWant: true, ingestWant: true},
		{name: "new receiver and recover ingest", receiverNew: true, refresh: "ingest", receiverWant: true, ingestWant: true},
		{name: "invalid", refresh: "all", fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recv, ingest, err := activationTargets(enrollmentPlan{
				receiverNew: tc.receiverNew, ingestNew: tc.ingestNew,
			}, tc.refresh)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected err: %v", err)
			}
			if err == nil && (recv != tc.receiverWant || ingest != tc.ingestWant) {
				t.Fatalf("got receiver=%t ingest=%t, want receiver=%t ingest=%t", recv, ingest, tc.receiverWant, tc.ingestWant)
			}
		})
	}
}

func TestActivateServiceRecovery(t *testing.T) {
	for _, initialRunning := range []bool{true, false} {
		t.Run(fmt.Sprintf("initial-running=%t", initialRunning), func(t *testing.T) {
			running := initialRunning
			var verbs []string
			run := func(jail string, args ...string) (string, error) {
				if jail != "fi-ingest" || len(args) != 3 || args[0] != "service" || args[1] != "fi_ingest_worker" {
					return "", fmt.Errorf("unexpected command %v", args)
				}
				verb := args[2]
				verbs = append(verbs, verb)
				switch verb {
				case "onestatus":
					if !running {
						return "", fmt.Errorf("not running")
					}
					return "running", nil
				case "onestart":
					if running {
						return "", fmt.Errorf("unexpected onestart")
					}
					running = true
					return "started", nil
				case "restart":
					if !running {
						return "", fmt.Errorf("unexpected restart")
					}
					return "restarted", nil
				default:
					return "", fmt.Errorf("unexpected verb %q", verb)
				}
			}
			if err := activateServiceWith(run, "fi-ingest", "fi_ingest_worker"); err != nil {
				t.Fatal(err)
			}
			want := "onestart"
			if initialRunning {
				want = "restart"
			}
			if len(verbs) != 3 || verbs[0] != "onestatus" || verbs[1] != want || verbs[2] != "onestatus" {
				t.Fatalf("unexpected commands: %v", verbs)
			}
		})
	}
}

func TestActivateServiceRejectsFailedRecovery(t *testing.T) {
	run := func(jail string, args ...string) (string, error) {
		if args[2] == "onestatus" {
			return "", fmt.Errorf("not running")
		}
		return "", fmt.Errorf("start blocked")
	}
	if err := activateServiceWith(run, "fi-ingest", "fi_ingest_worker"); err == nil {
		t.Fatal("failed service start accepted")
	}
}
