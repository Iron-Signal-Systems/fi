// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
)

func TestValidateReceiverCertificateChain(t *testing.T) {
	root, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)

	tests := []struct {
		name  string
		chain []*x509.Certificate
	}{
		{
			name:  "leaf issuer",
			chain: []*x509.Certificate{leaf, issuer},
		},
		{
			name:  "leaf issuer root",
			chain: []*x509.Certificate{leaf, issuer, root},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReceiverCertificateChain(
				test.chain,
				root,
				issuer,
			); err != nil {
				t.Fatalf(
					"ValidateReceiverCertificateChain() error = %v",
					err,
				)
			}
		})
	}
}

func TestValidateReceiverCertificateChainFailures(t *testing.T) {
	root, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)
	otherRoot, otherIssuer, _, _, _ := newReceiverIdentityMaterial(t)

	tests := []struct {
		name   string
		chain  []*x509.Certificate
		root   *x509.Certificate
		issuer *x509.Certificate
	}{
		{
			name:   "nil root",
			chain:  []*x509.Certificate{leaf, issuer},
			root:   nil,
			issuer: issuer,
		},
		{
			name:   "nil issuer",
			chain:  []*x509.Certificate{leaf, issuer},
			root:   root,
			issuer: nil,
		},
		{
			name:   "empty chain",
			chain:  nil,
			root:   root,
			issuer: issuer,
		},
		{
			name:   "leaf only",
			chain:  []*x509.Certificate{leaf},
			root:   root,
			issuer: issuer,
		},
		{
			name:   "wrong issuer",
			chain:  []*x509.Certificate{leaf, otherIssuer},
			root:   root,
			issuer: issuer,
		},
		{
			name:   "wrong root",
			chain:  []*x509.Certificate{leaf, issuer, otherRoot},
			root:   root,
			issuer: issuer,
		},
		{
			name:   "reordered",
			chain:  []*x509.Certificate{leaf, root, issuer},
			root:   root,
			issuer: issuer,
		},
		{
			name: "extra certificate",
			chain: []*x509.Certificate{
				leaf,
				issuer,
				root,
				otherRoot,
			},
			root:   root,
			issuer: issuer,
		},
		{
			name:   "nil chain entry",
			chain:  []*x509.Certificate{leaf, nil},
			root:   root,
			issuer: issuer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReceiverCertificateChain(
				test.chain,
				test.root,
				test.issuer,
			); err == nil {
				t.Fatal(
					"ValidateReceiverCertificateChain() error = nil, want error",
				)
			}
		})
	}
}
