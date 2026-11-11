// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumeconsent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func freshOperatorFixture(t *testing.T) fixture {
	t.Helper()
	f := makeFixture(t)
	f.expected.Sequence = 1
	f.payload.Sequence = 1
	return f
}

func TestFreshInstallerSignedApproverMatchesObservedProcessUser(t *testing.T) {
	f := freshOperatorFixture(t)
	if err := VerifyFreshInstallForOperator(
		f.signed(t), f.expected, f.requested, f.review, f.native, f.payload.ApproverSID,
	); err != nil {
		t.Fatalf("valid signed first-install receipt rejected for matching operator: %v", err)
	}

	// A different signed approver is not the running process, even if the
	// receipt is otherwise authentic and exactly matches host/scope/time.
	f.payload.ApproverSID = "S-1-5-21-100-200-300-501"
	if err := VerifyFreshInstallForOperator(
		f.signed(t), f.expected, f.requested, f.review, f.native,
		"S-1-5-21-100-200-300-500",
	); !errors.Is(err, ErrUnauthorizedReceipt) {
		t.Fatalf("valid receipt for a different administrator accepted: %v", err)
	}
}

func TestFreshInstallerOperatorBindingFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fixture, *string, *[]byte)
		want error
	}{
		{"no observed token identity", func(_ *fixture, sid *string, _ *[]byte) {
			*sid = ""
		}, ErrUnauthorizedReceipt},
		{"malformed observed identity", func(_ *fixture, sid *string, _ *[]byte) {
			*sid = "S-1-5-21-invalid"
		}, ErrUnauthorizedReceipt},
		{"other native user", func(_ *fixture, sid *string, _ *[]byte) {
			*sid = "S-1-5-21-100-200-300-999"
		}, ErrUnauthorizedReceipt},
		{"wrong trusted signer", func(f *fixture, _ *string, _ *[]byte) {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil { t.Fatal(err) }
			f.expected.TrustedPublicKey = &other.PublicKey
		}, ErrUnauthorizedReceipt},
		{"expired signed consent", func(f *fixture, _ *string, _ *[]byte) {
			f.expected.Now = f.expected.Now.Add(16 * time.Minute)
		}, ErrStaleApproval},
		{"wrong host", func(f *fixture, _ *string, _ *[]byte) {
			f.expected.MachineSID = "S-1-5-21-100-200-999"
		}, ErrStaleApproval},
		{"changed live NTFS volume", func(f *fixture, _ *string, _ *[]byte) {
			f.native[0].Serial64 = "15172277115761558408"
		}, ErrStaleApproval},
		{"untrusted altered approver", func(_ *fixture, _ *string, receipt *[]byte) {
			var decoded Receipt
			if err := json.Unmarshal(*receipt, &decoded); err != nil { t.Fatal(err) }
			decoded.Payload.ApproverSID = "S-1-5-21-100-200-300-999"
			altered, err := json.Marshal(decoded)
			if err != nil { t.Fatal(err) }
			*receipt = altered
		}, ErrUnauthorizedReceipt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := freshOperatorFixture(t)
			sid := f.payload.ApproverSID
			receipt := f.signed(t)
			tc.edit(&f, &sid, &receipt)
			if err := VerifyFreshInstallForOperator(
				receipt, f.expected, f.requested, f.review, f.native, sid,
			); !errors.Is(err, tc.want) {
				t.Fatalf("unqualified installer operator accepted: err=%v want=%v", err, tc.want)
			}
		})
	}
}
