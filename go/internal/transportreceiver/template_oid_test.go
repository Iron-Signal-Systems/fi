// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var receiverTestBatchSigningTemplateOID = asn1.ObjectIdentifier{
	1, 3, 6, 1, 4, 1, 311, 21, 8, 100, 2,
}

var receiverTestCertificateTemplateInformationOID = asn1.ObjectIdentifier{
	1, 3, 6, 1, 4, 1, 311, 21, 7,
}

type receiverTestCertificateTemplateInformation struct {
	TemplateID   asn1.ObjectIdentifier
	MajorVersion int
	MinorVersion int `asn1:"optional"`
}

func receiverTestCertificateTemplateExtension(
	t *testing.T,
	templateID asn1.ObjectIdentifier,
) pkix.Extension {
	t.Helper()

	encoded, err := asn1.Marshal(
		receiverTestCertificateTemplateInformation{
			TemplateID:   templateID,
			MajorVersion: 100,
			MinorVersion: 1,
		},
	)
	if err != nil {
		t.Fatalf("marshal certificate template information: %v", err)
	}

	return pkix.Extension{
		Id:    receiverTestCertificateTemplateInformationOID,
		Value: encoded,
	}
}
