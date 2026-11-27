// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var testBatchSigningTemplateOID = asn1.ObjectIdentifier{
	1, 3, 6, 1, 4, 1, 311, 21, 8, 100, 2,
}

var testTransportTemplateOID = asn1.ObjectIdentifier{
	1, 3, 6, 1, 4, 1, 311, 21, 8, 100, 1,
}

func testCertificateTemplateExtension(
	t *testing.T,
	templateID asn1.ObjectIdentifier,
) pkix.Extension {
	t.Helper()

	encoded, err := asn1.Marshal(adcsCertificateTemplateInformation{
		TemplateID:   templateID,
		MajorVersion: 100,
		MinorVersion: 1,
	})
	if err != nil {
		t.Fatalf("marshal test certificate template information: %v", err)
	}

	return pkix.Extension{
		Id:    adcsCertificateTemplateInformationOID,
		Value: encoded,
	}
}
