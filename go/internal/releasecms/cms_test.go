// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releasecms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestSignDetachedProducesVerifiableRSASignature(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName: "FI CMS Test Signer",
		},
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(
		der,
	)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte(
		"FI detached CMS test content\n",
	)
	encoded, err := SignDetached(
		content,
		certificate,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	var outer contentInfo
	rest, err := asn1.Unmarshal(
		encoded,
		&outer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf(
			"trailing outer bytes=%d",
			len(rest),
		)
	}
	if !outer.ContentType.Equal(
		oidCMSSignedData,
	) {
		t.Fatalf(
			"content_type=%s",
			outer.ContentType.String(),
		)
	}

	var signed signedData
	rest, err = asn1.Unmarshal(
		outer.Content.Bytes,
		&signed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf(
			"trailing SignedData bytes=%d",
			len(rest),
		)
	}
	if len(signed.SignerInfos) != 1 {
		t.Fatalf(
			"signer_infos=%d",
			len(signed.SignerInfos),
		)
	}

	digest := sha256.Sum256(
		content,
	)
	if err := rsa.VerifyPKCS1v15(
		&key.PublicKey,
		crypto.SHA256,
		digest[:],
		signed.SignerInfos[0].Signature,
	); err != nil {
		t.Fatal(err)
	}
}
