// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumeconsent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

const (
	fiDataGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
	fiSystemGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`
)

type fixture struct {
	privateKey ed25519.PrivateKey
	expected Expected
	payload Payload
	requested config.VolumeConfig
	review volumereview.Review
	native []volumediscovery.Snapshot
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
`
	proposed, err := config.ParseVolumeV2(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	native := []volumediscovery.Snapshot{
		{GUID: fiDataGUID, Serial64: "15172277115761558407", Status: volumediscovery.Eligible, FileSystem: "NTFS"},
		{GUID: fiSystemGUID, Serial64: "14888954410052949637", Status: volumediscovery.Eligible, FileSystem: "NTFS"},
	}
	review, err := volumereview.Build(nil, proposed, native)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader) // TEST ONLY, never persisted
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 17, 0, 0, 0, time.UTC)
	machine := "S-1-5-21-100-200-300"
	instance := "bcdef01234567890abcdef0123456789"
	return fixture{
		privateKey: priv,
		expected: Expected{MachineSID: machine, InstallationID: instance, Sequence: 7, TrustedPublicKey: pub, Now: now},
		payload: Payload{
			Version: ReceiptVersion,
			Action: ApprovedAction,
			MachineSID: machine,
			InstallationID: instance,
			ApproverSID: "S-1-5-21-100-200-300-500",
			Sequence: 7,
			RequestedConfigSHA256: review.RequestedConfigSHA256,
			ReviewFingerprintSHA256: review.ReviewFingerprintSHA256,
			IssuedAtUTC: now.Add(-1*time.Minute).Format(time.RFC3339Nano),
			ExpiresAtUTC: now.Add(9*time.Minute).Format(time.RFC3339Nano),
		},
		requested: proposed, review: review, native: native,
	}
}

// In tests only, sign the exact domain-separated payload with a newly
// generated disposable in-memory Ed25519 private key. Production MUST NOT
// generate an ephemeral signing key and trust its own public half.
func (f fixture) signed(t *testing.T) []byte {
	t.Helper()
	msg, err := message(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Receipt{Payload: f.payload, SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(f.privateKey, msg))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func (f fixture) verify(t *testing.T) error {
	t.Helper()
	return Verify(f.signed(t), f.expected, nil, f.requested, f.review, f.native)
}

func TestSignedHostBoundVolumeConsent(t *testing.T) {
	f := makeFixture(t)
	if err := f.verify(t); err != nil {
		t.Fatalf("correct, current, signed review was rejected: %v", err)
	}
	if len(f.signed(t)) > maxReceiptSize {
		t.Fatal("test receipt exceeds bounded envelope")
	}
}

func TestSignedConsentRejectedAcrossHostsAndInstallations(t *testing.T) {
	tests := []struct {
		name string
		edit func(*fixture)
	}{
		{"different host machine SID", func(f *fixture) { f.expected.MachineSID = "S-1-5-21-101-200-300" }},
		{"different installation instance", func(f *fixture) { f.expected.InstallationID = "abcdef01234567890abcdef012345678" }},
		{"replayed sequence", func(f *fixture) { f.expected.Sequence = 8 }},
		{"changed installed baseline digest", func(f *fixture) { f.expected.PreviousConfigSHA256 = strings.Repeat("a", 64) }},
		{"after approval expiry", func(f *fixture) { f.expected.Now = f.expected.Now.Add(11*time.Minute) }},
		{"approval too far in future", func(f *fixture) { f.expected.Now = f.expected.Now.Add(-5*time.Minute) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			receipt := f.signed(t)
			tc.edit(&f)
			err := Verify(receipt, f.expected, nil, f.requested, f.review, f.native)
			if !errors.Is(err, ErrStaleApproval) {
				t.Fatalf("scope or host drift accepted, error: %v", err)
			}
		})
	}
}

func TestSignedConsentRejectsNativeIdentityAndPolicyChanges(t *testing.T) {
	tests := []struct {
		name string
		edit func(*fixture)
	}{
		{"changed NTFS full width serial", func(f *fixture) { f.native[0].Serial64 = "15172277115761558408" }},
		{"volume unavailable", func(f *fixture) {
			f.native[0].Status = volumediscovery.Unavailable
			f.native[0].Detail = "access denied"
			f.native[0].Serial64 = ""
		}},
		{"volume gone", func(f *fixture) { f.native = f.native[1:] }},
		{"governed-root policy widened", func(f *fixture) { f.requested.Policies[0].Depth = config.DepthContent }},
		{"governed-root moved", func(f *fixture) { f.requested.Policies[0].RelativeRoot = `\Shares\Other` }},
		{"review body changed but fingerprint kept", func(f *fixture) { f.review.RequiresExplicitApproval = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			receipt := f.signed(t)
			tc.edit(&f)
			err := Verify(receipt, f.expected, nil, f.requested, f.review, f.native)
			if !errors.Is(err, ErrStaleApproval) {
				t.Fatalf("stale/modified volume approval accepted: %v", err)
			}
		})
	}
}

func TestSignedConsentRejectsForgedOrMalformedReceipts(t *testing.T) {
	f := makeFixture(t)
	encoded := f.signed(t)
	tests := []struct {
		name string
		change func([]byte) []byte
		want error
	}{
		{"wrong signer public key", func(b []byte) []byte { _, private, _ := ed25519.GenerateKey(rand.Reader); f.expected.TrustedPublicKey = private.Public().(ed25519.PublicKey); return b }, ErrUnauthorizedReceipt},
		{"payload action tampered", func(b []byte) []byte {
			var receipt Receipt
			if err := json.Unmarshal(b, &receipt); err != nil { t.Fatal(err) }
			receipt.Payload.Action = "AllowAllVolumes"
			d, _ := json.Marshal(receipt); return d
		}, ErrInvalidReceipt},
		{"signature tampered", func(b []byte) []byte {
			var receipt Receipt
			if err := json.Unmarshal(b, &receipt); err != nil { t.Fatal(err) }
			receipt.SignatureBase64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x23}, ed25519.SignatureSize))
			d, _ := json.Marshal(receipt); return d
		}, ErrUnauthorizedReceipt},
		{"extra field", func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"allowed":true}`)... ) }, ErrInvalidReceipt},
		{"duplicate JSON key", func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"payload":{}}`)... ) }, ErrInvalidReceipt},
		{"trailing JSON", func(b []byte) []byte { return append(b, []byte("{}")...) }, ErrInvalidReceipt},
		{"noncanonical whitespace", func(b []byte) []byte { return append([]byte(" "), b...) }, ErrInvalidReceipt},
		{"oversized receipt", func([]byte) []byte { return bytes.Repeat([]byte{'x'}, maxReceiptSize+1) }, ErrInvalidReceipt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			current := makeFixture(t)
			data := current.signed(t)
			// The wrong-key case changes the expected trusted key separately.
			f = current
			mutated := tc.change(data)
			err := Verify(mutated, f.expected, nil, f.requested, f.review, f.native)
			if !errors.Is(err, tc.want) {
				t.Fatalf("malformed or forged receipt was accepted, error=%v expected=%v", err, tc.want)
			}
		})
	}
	_ = encoded
}

func TestSignedConsentInvalidTimeAndIdentityNeverAccepted(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Payload)
	}{
		{"invalid service identity", func(p *Payload) { p.ApproverSID = "admin" }},
		{"wrong action", func(p *Payload) { p.Action = "InstallEverything" }},
		{"zero sequence", func(p *Payload) { p.Sequence = 0 }},
		{"zero installation ID", func(p *Payload) { p.InstallationID = strings.Repeat("0", 32) }},
		{"uppercase config digest", func(p *Payload) { p.RequestedConfigSHA256 = strings.ToUpper(p.RequestedConfigSHA256) }},
		{"oversized lifetime", func(p *Payload) { p.ExpiresAtUTC = "2026-11-08T17:31:00Z" }},
		{"non-UTC timestamp", func(p *Payload) { p.IssuedAtUTC = "2026-11-08T12:59:00-04:00" }},
		{"invalid timestamp", func(p *Payload) { p.IssuedAtUTC = "now" }},
		{"missing source digest", func(p *Payload) { p.RequestedConfigSHA256 = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			tc.edit(&f.payload)
			err := f.verify(t)
			if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("invalid signed intent was accepted: %v", err)
			}
		})
	}
}

func TestConsentExpectedTrustCannotBeProvidedByReceipt(t *testing.T) {
	f := makeFixture(t)
	for _, tc := range []struct {
		name string
		edit func(*Expected)
	}{
		{"no trusted key", func(e *Expected) { e.TrustedPublicKey = nil }},
		{"no trusted host", func(e *Expected) { e.MachineSID = "" }},
		{"no sequence", func(e *Expected) { e.Sequence = 0 }},
		{"no installation instance", func(e *Expected) { e.InstallationID = "" }},
		{"no independently checked clock", func(e *Expected) { e.Now = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := f.expected
			tc.edit(&current)
			if err := Verify(f.signed(t), current, nil, f.requested, f.review, f.native); !errors.Is(err, ErrUnauthorizedReceipt) {
				t.Fatalf("missing independently trusted context accepted: %v", err)
			}
		})
	}
}

func TestCanonicalSIDAndDigestValidation(t *testing.T) {
	for _, sid := range []string{"", "S-2-5-32-544", "S-1-05-32-544", "S-1-5", "S-1-5-4294967296", "S-1-281474976710656-21", "S-1-5-01", "S-1-5-hello", "s-1-5-21"} {
		if validSID(sid) {
			t.Fatalf("noncanonical Windows SID accepted: %q", sid)
		}
	}
	if !validSID("S-1-5-21-100-200-300-500") || !validDigest(strings.Repeat("a", 64), false) {
		t.Fatal("canonical Windows SID or digest rejected")
	}
}
