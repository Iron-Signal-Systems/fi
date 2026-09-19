// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

type generationReceiveFixture struct {
	Config ReceiveConfig
	Offer  Offer
	Result TransferResult
	Wire   []byte
}

func TestReadValidatedTransferAcceptsExactGeneration(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	result, err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			fixture.Config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if result !=
		fixture.Result {
		t.Fatalf(
			"receiver transfer result = %#v, want %#v",
			result,
			fixture.Result,
		)
	}
}

func TestReadValidatedTransferRejectsMetadataIdentityMismatch(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	offer :=
		fixture.Offer

	offer.MetadataSHA256 =
		strings.Repeat(
			"0",
			64,
		)

	if _,
		err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				fixture.Wire,
			),
			offer,
			fixture.Config,
		); err == nil {
		t.Fatal(
			"generation transfer with mismatched offered metadata identity was accepted",
		)
	}
}

func TestReadValidatedTransferRejectsPayloadMutation(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	wire :=
		append(
			[]byte(nil),
			fixture.Wire...,
		)

	wire[len(wire)-1] ^=
		0xff

	if _,
		err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				wire,
			),
			fixture.Offer,
			fixture.Config,
		); err == nil {
		t.Fatal(
			"mutated generation payload was accepted",
		)
	}
}

func TestReadValidatedTransferRejectsUnenrolledBatchSigner(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	config :=
		fixture.Config

	config.Source.BatchSigning.CertificateSHA256 =
		strings.Repeat(
			"0",
			64,
		)

	if _,
		err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			config,
		); err == nil {
		t.Fatal(
			"generation signed by certificate outside enrolled identity was accepted",
		)
	}
}

func TestReadValidatedTransferRejectsReceiverLimits(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	if fixture.Offer.Descriptor.EncodedDataBytes <= 1 {
		t.Fatal(
			"test generation encoded payload is unexpectedly small",
		)
	}

	encodedConfig :=
		fixture.Config

	encodedConfig.MaxEncodedBytes =
		fixture.Offer.Descriptor.EncodedDataBytes -
			1

	if _,
		err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			encodedConfig,
		); err == nil {
		t.Fatal(
			"generation exceeding receiver encoded limit was accepted",
		)
	}

	if fixture.Offer.Descriptor.CanonicalBytes <= 1 {
		t.Fatal(
			"test generation canonical payload is unexpectedly small",
		)
	}

	canonicalConfig :=
		fixture.Config

	canonicalConfig.MaxCanonicalBytes =
		fixture.Offer.Descriptor.CanonicalBytes -
			1

	if _,
		err :=
		ReadValidatedTransfer(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			canonicalConfig,
		); err == nil {
		t.Fatal(
			"generation exceeding receiver canonical limit was accepted",
		)
	}
}

func testGenerationReceiveFixture(
	t *testing.T,
) generationReceiveFixture {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"

	root,
		issuer,
		leaf,
		leafKey,
		crl,
		source :=
		testGenerationReceiveTrust(
			t,
			sourceID,
		)

	frozen :=
		filepath.Join(
			t.TempDir(),
			"frozen",
		)

	sealed :=
		filepath.Join(
			t.TempDir(),
			"sealed",
		)

	if err :=
		os.MkdirAll(
			frozen,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			sealed,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	files :=
		map[string][]byte{
			"batch-a.manifest.json": []byte(
				"{\"batch\":\"a\"}\n",
			),

			"batch-a.jsonl": []byte(
				"{\"record\":1}\n",
			),

			"batch-b.manifest.json": []byte(
				"{\"batch\":\"b\"}\n",
			),

			"batch-b.jsonl": []byte(
				"{\"record\":2}\n{\"record\":3}\n",
			),
		}

	for name, value := range files {
		if err :=
			os.WriteFile(
				filepath.Join(
					frozen,
					name,
				),
				value,
				0o600,
			); err != nil {
			t.Fatal(err)
		}
	}

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			CreateConfig{
				BatchSigner: leafKey,

				BatchSigningCertificate: leaf,

				FrozenDir: frozen,

				GenerationID: "20260918T153000.000000000Z-0123456789abcdef",

				SealedRoot: sealed,

				SourceID: sourceID,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	offer, err :=
		OfferFromPublished(
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer

	result, err :=
		WritePublishedGeneration(
			&wire,
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	return generationReceiveFixture{
		Config: ReceiveConfig{
			BatchCRL: crl,

			BatchIssuer: issuer,

			CurrentTime: time.Now(),

			MaxCanonicalBytes: 64 << 20,

			MaxEncodedBytes: 64 << 20,

			Root: root,

			Source: source,
		},

		Offer: offer,

		Result: result,

		Wire: append(
			[]byte(nil),
			wire.Bytes()...,
		),
	}
}

func testGenerationReceiveTrust(
	t *testing.T,
	sourceID string,
) (
	*x509.Certificate,
	*x509.Certificate,
	*x509.Certificate,
	*rsa.PrivateKey,
	*x509.RevocationList,
	transporttrust.SourceAuthorization,
) {
	t.Helper()

	now :=
		time.Now().
			UTC()

	rootKey, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				2001,
			),

			Subject: pkix.Name{
				CommonName: "FI Generation Root Test",
			},

			NotBefore: now.Add(
				-time.Hour,
			),

			NotAfter: now.Add(
				24 *
					time.Hour,
			),

			KeyUsage: x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign |
				x509.KeyUsageDigitalSignature,

			BasicConstraintsValid: true,

			IsCA: true,

			SubjectKeyId: []byte{
				1,
				2,
				3,
				4,
			},
		}

	root :=
		createGenerationReceiveCertificate(
			t,
			rootTemplate,
			rootTemplate,
			&rootKey.PublicKey,
			rootKey,
		)

	issuerKey, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	issuerTemplate :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				2002,
			),

			Subject: pkix.Name{
				CommonName: "FI Generation Batch Signing Test CA",
			},

			NotBefore: now.Add(
				-time.Hour,
			),

			NotAfter: now.Add(
				12 *
					time.Hour,
			),

			KeyUsage: x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign |
				x509.KeyUsageDigitalSignature,

			BasicConstraintsValid: true,

			IsCA: true,

			SubjectKeyId: []byte{
				5,
				6,
				7,
				8,
			},
		}

	issuer :=
		createGenerationReceiveCertificate(
			t,
			issuerTemplate,
			root,
			&issuerKey.PublicKey,
			rootKey,
		)

	leafKey, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				2003,
			),

			Subject: pkix.Name{
				CommonName: sourceID,

				OrganizationalUnit: []string{
					transporttrust.BatchSigningOrganizationalUnit,
				},
			},

			NotBefore: now.Add(
				-time.Hour,
			),

			NotAfter: now.Add(
				6 *
					time.Hour,
			),

			KeyUsage: x509.KeyUsageDigitalSignature,

			BasicConstraintsValid: true,
		}

	leaf :=
		createGenerationReceiveCertificate(
			t,
			leafTemplate,
			issuer,
			&leafKey.PublicKey,
			issuerKey,
		)

	crlDER, err :=
		x509.CreateRevocationList(
			rand.Reader,
			&x509.RevocationList{
				Number: big.NewInt(
					1,
				),

				ThisUpdate: now.Add(
					-time.Minute,
				),

				NextUpdate: now.Add(
					time.Hour,
				),
			},
			issuer,
			issuerKey,
		)
	if err != nil {
		t.Fatal(err)
	}

	crl, err :=
		x509.ParseRevocationList(
			crlDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	source :=
		transporttrust.SourceAuthorization{
			Enabled: true,

			SourceID: sourceID,

			BatchSigning: transporttrust.CertificateIdentity{
				CertificateSHA256: generationReceiveCertificateSHA256(
					leaf,
				),

				CommonName: sourceID,

				IssuingCASHA256: generationReceiveCertificateSHA256(
					issuer,
				),

				OrganizationalUnit: transporttrust.BatchSigningOrganizationalUnit,
			},
		}

	return root,
		issuer,
		leaf,
		leafKey,
		crl,
		source
}

func createGenerationReceiveCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *rsa.PublicKey,
	signer *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err :=
		x509.CreateCertificate(
			rand.Reader,
			template,
			parent,
			publicKey,
			signer,
		)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err :=
		x509.ParseCertificate(
			der,
		)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func generationReceiveCertificateSHA256(
	certificate *x509.Certificate,
) string {
	digest :=
		sha256.Sum256(
			certificate.Raw,
		)

	return hex.EncodeToString(
		digest[:],
	)
}
