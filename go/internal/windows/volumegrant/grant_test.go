// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumegrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

type signedFixture struct {
	key *ecdsa.PrivateKey
	manifest Manifest
	scope config.VolumeConfig
	trust TrustedState
}

func newSignedFixture(t *testing.T) signedFixture {
	t.Helper()
	scope, err := config.ParseVolumeV2(strings.NewReader(`version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
`))
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := config.CanonicalVolumeV2(scope)
	if err != nil {
		t.Fatal(err)
	}
	scopeDigest := sha256.Sum256(normalized)
	operationalDigest := sha256.Sum256([]byte("only a test, not a deployable operational configuration"))
	approvalDigest := sha256.Sum256([]byte("fixture: previously verified signed installer approval"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 18, 15, 0, 0, time.UTC)
	manifest := Manifest{
		Version: Version,
		Mode: Mode,
		MachineSID: "S-1-5-21-100-200-300",
		InstallationID: "bcdef01234567890abcdef0123456789",
		Generation: 1,
		CommitID: "abcdef01234567890abcdef012345678",
		ScopeConfigSHA256: hex.EncodeToString(scopeDigest[:]),
		OperationalConfigSHA256: hex.EncodeToString(operationalDigest[:]),
		ApprovalReceiptSHA256: hex.EncodeToString(approvalDigest[:]),
		CommittedAtUTC: now.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	return signedFixture{
		key: key,
		manifest: manifest,
		scope: scope,
		trust: TrustedState{
			MachineSID: manifest.MachineSID,
			InstallationID: manifest.InstallationID,
			Generation: manifest.Generation,
			ScopeConfigSHA256: manifest.ScopeConfigSHA256,
			OperationalConfigSHA256: manifest.OperationalConfigSHA256,
			TrustedPublicKey: &key.PublicKey,
			Now: now,
		},
	}
}

// Sign only with a disposable in-memory test key. No production signing API
// exists in this package. Pin the resulting exact grant digest independently
// in the fixture's simulated committed installation state.
func (f *signedFixture) sign(t *testing.T) []byte {
	t.Helper()
	msg, err := signatureMessage(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(SignedGrant{
		Manifest: f.manifest,
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(out)
	f.trust.GrantSHA256 = hex.EncodeToString(pin[:])
	return out
}

func TestInstalledGrantAcceptsExactSignedPinnedScope(t *testing.T) {
	fixture := newSignedFixture(t)
	data := fixture.sign(t)
	if err := Verify(data, fixture.trust, fixture.scope); err != nil {
		t.Fatalf("correct durable installed grant rejected: %v", err)
	}
	if len(data) > maxGrantBytes {
		t.Fatal("fixture grant exceeded bounded encoding")
	}
}

func TestInstalledGrantRequiresProtectedIndependentTrust(t *testing.T) {
	cases := []struct {
		name string
		change func(*TrustedState)
	}{
		{"wrong machine", func(e *TrustedState) { e.MachineSID = "S-1-5-21-100-200-301" }},
		{"wrong installation", func(e *TrustedState) { e.InstallationID = "abcdef01234567890abcdef012345678" }},
		{"wrong sequence", func(e *TrustedState) { e.Generation = 2; e.PreviousGrantSHA256 = strings.Repeat("a", 64) }},
		{"untrusted pin", func(e *TrustedState) { e.GrantSHA256 = strings.Repeat("b", 64) }},
		{"changed operational configuration", func(e *TrustedState) { e.OperationalConfigSHA256 = strings.Repeat("c", 64) }},
		{"changed scope digest", func(e *TrustedState) { e.ScopeConfigSHA256 = strings.Repeat("d", 64) }},
		{"missing exact signed-grant pin", func(e *TrustedState) { e.GrantSHA256 = "" }},
		{"missing trusted signer", func(e *TrustedState) { e.TrustedPublicKey = nil }},
		{"missing OS host", func(e *TrustedState) { e.MachineSID = "" }},
		{"missing independent clock", func(e *TrustedState) { e.Now = time.Time{} }},
		{"unsupported public-key curve", func(e *TrustedState) {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				panic(err)
			}
			e.TrustedPublicKey = &key.PublicKey
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSignedFixture(t)
			data := fixture.sign(t)
			e := fixture.trust
			tc.change(&e)
			err := Verify(data, e, fixture.scope)
			if err == nil {
				t.Fatal("untrusted/changed protected installation state was accepted")
			}
		})
	}
}

func TestInstalledGrantRejectsSignedButUncommittedScope(t *testing.T) {
	f := newSignedFixture(t)
	good := f.sign(t)
	// A valid ECDSA signature is not enough. A malicious administrator who
	// can supply a differently signed file must not be able to change the
	// already committed grant without changing independently protected state.
	f.manifest.CommitID = "1234567890abcdef1234567890abcdef"
	other := f.sign(t)
	if bytes.Equal(good, other) {
		t.Fatal("different signed commitment unexpectedly identical")
	}
	pinned := sha256.Sum256(good)
	f.trust.GrantSHA256 = hex.EncodeToString(pinned[:])
	if err := Verify(other, f.trust, f.scope); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("new signed but uncommitted grant was accepted: %v", err)
	}
	if err := Verify(good, f.trust, f.scope); err != nil {
		t.Fatalf("previously committed grant was rejected: %v", err)
	}
}

func TestInstalledGrantRejectsTamperAndUnknownJSON(t *testing.T) {
	f := newSignedFixture(t)
	good := f.sign(t)
	cases := []struct {
		name string
		modify func([]byte) []byte
	}{
		{"blank envelope", func([]byte) []byte { return nil }},
		{"oversized", func([]byte) []byte { return bytes.Repeat([]byte{'x'}, maxGrantBytes+1) }},
		{"unknown outer field", func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"allow_all":true}`)... ) }},
		{"duplicate manifest key", func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"manifest":{}}`)... ) }},
		{"trailing JSON", func(b []byte) []byte { return append(b, []byte("{}")...) }},
		{"leading whitespace", func(b []byte) []byte { return append([]byte(" "), b...) }},
		{"invalid signature", func(b []byte) []byte {
			var item SignedGrant
			if err := json.Unmarshal(b, &item); err != nil { t.Fatal(err) }
			item.SignatureBase64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 70))
			encoded, _ := json.Marshal(item)
			return encoded
		}},
		{"tampered scope", func(b []byte) []byte {
			var item SignedGrant
			if err := json.Unmarshal(b, &item); err != nil { t.Fatal(err) }
			item.Manifest.ScopeConfigSHA256 = strings.Repeat("a", 64)
			encoded, _ := json.Marshal(item)
			return encoded
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.modify(append([]byte(nil), good...))
			if err := Verify(data, f.trust, f.scope); err == nil {
				t.Fatal("forged or malformed grant was accepted")
			}
		})
	}
}

func TestInstalledGrantRejectsChangedSourcePolicy(t *testing.T) {
	f := newSignedFixture(t)
	grant := f.sign(t)
	changed := f.scope
	changed.Policies = append([]config.RootPolicy(nil), f.scope.Policies...)
	changed.Policies[0].Depth = config.DepthContent
	if err := Verify(grant, f.trust, changed); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("governed policy widening accepted: %v", err)
	}
	changed = f.scope
	changed.Volumes = append([]config.VolumeEnrollment(nil), f.scope.Volumes...)
	changed.Volumes[0].Serial = "15172277115761558408"
	if err := Verify(grant, f.trust, changed); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("changed volume identity accepted: %v", err)
	}
	changed = f.scope
	changed.Volumes = changed.Volumes[:1]
	changed.Policies = nil
	if err := Verify(grant, f.trust, changed); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("missing approved volume accepted: %v", err)
	}
}

func TestInstalledGrantGenerationChainAndRollback(t *testing.T) {
	f := newSignedFixture(t)
	generation1 := f.sign(t)
	gen1Digest := f.trust.GrantSHA256
	f.manifest.Generation = 2
	f.manifest.PreviousGrantSHA256 = gen1Digest
	f.manifest.CommitID = "1234567890abcdef1234567890abcdef"
	f.trust.Generation = 2
	f.trust.PreviousGrantSHA256 = gen1Digest
	generation2 := f.sign(t)
	if err := Verify(generation2, f.trust, f.scope); err != nil {
		t.Fatalf("correct committed generation 2 rejected: %v", err)
	}
	if err := Verify(generation1, f.trust, f.scope); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("rollback to generation 1 accepted: %v", err)
	}
	f.trust.PreviousGrantSHA256 = strings.Repeat("0", 64)
	if err := Verify(generation2, f.trust, f.scope); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("mismatched predecessor chain accepted: %v", err)
	}
}

func TestInstalledGrantRejectsImpossibleManifestAndTime(t *testing.T) {
	cases := []struct {
		name string
		change func(*Manifest)
	}{
		{"wrong version", func(m *Manifest) { m.Version = "fi-legacy" }},
		{"wrong mode", func(m *Manifest) { m.Mode = "AllDisks" }},
		{"zero generation", func(m *Manifest) { m.Generation = 0 }},
		{"zero commit ID", func(m *Manifest) { m.CommitID = strings.Repeat("0", 32) }},
		{"previous grant on first generation", func(m *Manifest) { m.PreviousGrantSHA256 = strings.Repeat("a", 64) }},
		{"missing receipt reference", func(m *Manifest) { m.ApprovalReceiptSHA256 = "" }},
		{"missing operational config", func(m *Manifest) { m.OperationalConfigSHA256 = "" }},
		{"invalid SID", func(m *Manifest) { m.MachineSID = "S-1-5-21-001" }},
		{"future timestamp not UTC", func(m *Manifest) { m.CommittedAtUTC = "2026-11-08T13:14:00-05:00" }},
		{"invalid timestamp", func(m *Manifest) { m.CommittedAtUTC = "yesterday" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSignedFixture(t)
			tc.change(&f.manifest)
			grant := f.sign(t)
			if err := Verify(grant, f.trust, f.scope); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("invalid signed manifest accepted: %v", err)
			}
		})
	}
	f := newSignedFixture(t)
	f.manifest.CommittedAtUTC = f.trust.Now.Add(4*time.Minute).Format(time.RFC3339Nano)
	grant := f.sign(t)
	if err := Verify(grant, f.trust, f.scope); !errors.Is(err, ErrGrantDrift) {
		t.Fatalf("future committed time beyond tolerance accepted: %v", err)
	}
}

func TestInstalledGrantRejectsUntrustedSignerEvenWithMatchingPin(t *testing.T) {
	f := newSignedFixture(t)
	grant := f.sign(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	f.trust.TrustedPublicKey = &other.PublicKey
	if err := Verify(grant, f.trust, f.scope); !errors.Is(err, ErrUntrustedGrant) {
		t.Fatalf("correct pin but untrusted signature accepted: %v", err)
	}
}
