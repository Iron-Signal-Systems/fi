// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestCertificateStateDifferenceTracksOnlyNewCertificates(
	t *testing.T,
) {
	t.Parallel()

	before := []localMachinePKICertificate{
		{
			CertificateSHA256: "aaaaaaaa",
			TemplateOID:       "1.2.3.4",
		},
		{
			CertificateSHA256: "bbbbbbbb",
			TemplateOID:       "1.2.3.5",
		},
	}

	after := []localMachinePKICertificate{
		{
			CertificateSHA256: "aaaaaaaa",
			TemplateOID:       "1.2.3.4",
		},
		{
			CertificateSHA256: "bbbbbbbb",
			TemplateOID:       "1.2.3.5",
		},
		{
			CertificateSHA256: "cccccccc",
			TemplateOID:       "1.2.3.4",
		},
	}

	added := certificateStateDifference(
		before,
		after,
	)

	if len(added) != 1 {
		t.Fatalf(
			"new certificate count=%d want=1",
			len(added),
		)
	}

	if added[0].CertificateSHA256 != "cccccccc" {
		t.Fatalf(
			"new certificate SHA256=%q want=cccccccc",
			added[0].CertificateSHA256,
		)
	}
}

func TestCertificateTemplateOIDParsesMicrosoftTemplateExtension(
	t *testing.T,
) {
	t.Parallel()

	want := asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 8,
		7189889, 13538943, 5063825, 61332,
		13006501, 227, 39227226, 61225164,
	}

	value, err := asn1.Marshal(
		certificateTemplateInformation{
			TemplateID:   want,
			MajorVersion: 100,
			MinorVersion: 0,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    certificateTemplateInformationOID,
				Value: value,
			},
		},
	}

	got, present, err := certificateTemplateOID(
		certificate,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !present {
		t.Fatal(
			"certificate template extension was not found",
		)
	}

	if got != want.String() {
		t.Fatalf(
			"template OID=%q want=%q",
			got,
			want.String(),
		)
	}
}

func TestCertificateTemplateOIDReportsAbsent(
	t *testing.T,
) {
	t.Parallel()

	got, present, err := certificateTemplateOID(
		&x509.Certificate{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if present {
		t.Fatalf(
			"unexpected template OID %q",
			got,
		)
	}
}
