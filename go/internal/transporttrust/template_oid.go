// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var adcsCertificateTemplateInformationOID = asn1.ObjectIdentifier{
	1, 3, 6, 1, 4, 1, 311, 21, 7,
}

type adcsCertificateTemplateInformation struct {
	TemplateID   asn1.ObjectIdentifier
	MajorVersion int
	MinorVersion int `asn1:"optional"`
}

// CertificateTemplateOID returns the AD CS certificate-template object OID
// carried by the Microsoft Certificate Template Information extension.
func CertificateTemplateOID(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", errors.New("certificate is required")
	}

	matchCount := 0
	var encoded []byte

	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(adcsCertificateTemplateInformationOID) {
			continue
		}

		matchCount++
		encoded = extension.Value
	}

	switch matchCount {
	case 0:
		return "", errors.New(
			"certificate template information extension is required",
		)
	case 1:
	default:
		return "", fmt.Errorf(
			"certificate contains %d template information extensions",
			matchCount,
		)
	}

	var information adcsCertificateTemplateInformation

	rest, err := asn1.Unmarshal(encoded, &information)
	if err != nil {
		return "", fmt.Errorf(
			"parse certificate template information extension: %w",
			err,
		)
	}

	if len(rest) != 0 {
		return "", errors.New(
			"certificate template information extension contains trailing data",
		)
	}

	if len(information.TemplateID) == 0 {
		return "", errors.New("certificate template object OID is required")
	}

	return information.TemplateID.String(), nil
}
