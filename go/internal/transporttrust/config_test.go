// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"strings"
	"testing"
)

const validSourceConfig = `version_id: 1.0
source_id: iss-fs-01.iss.local
enabled: true
transport_common_name: iss-fs-01.iss.local
transport_organizational_unit: FI Shipper Transport
transport_issuing_ca_sha256: 5EB837ED1C71E057E3F17FFB3ECF8F84176C106FB5D9437487C2A89A2151A971
transport_certificate_sha256: B4377143A213BE00B977C2930265CD6A459F95B978B0713676A4153F51AF5092
batch_signing_common_name: iss-fs-01.iss.local
batch_signing_organizational_unit: FI Batch Signing
batch_signing_issuing_ca_sha256: A309F854C0F54B9B7C28ED27CDF32D4C65B699CEBA31F05BB0A942D2DEFCFC51
batch_signing_certificate_sha256: 73370BBEA681ABF0080E68E69B29C0B68129108A9106AD556CE8DA42D7944DC6
`

func TestParseSourceConfig(t *testing.T) {
	value, err := ParseSourceConfig(strings.NewReader(validSourceConfig))
	if err != nil {
		t.Fatalf("ParseSourceConfig() error = %v", err)
	}

	if value.VersionID != SourceConfigVersion1 {
		t.Fatalf(
			"VersionID = %q, want %q",
			value.VersionID,
			SourceConfigVersion1,
		)
	}

	if value.Authorization.SourceID != "iss-fs-01.iss.local" {
		t.Fatalf(
			"SourceID = %q, want %q",
			value.Authorization.SourceID,
			"iss-fs-01.iss.local",
		)
	}

	if !value.Authorization.Enabled {
		t.Fatal("Enabled = false, want true")
	}

	if value.Authorization.Transport.CertificateSHA256 !=
		"b4377143a213be00b977c2930265cd6a459f95b978b0713676a4153f51af5092" {
		t.Fatal("transport certificate SHA-256 was not normalized")
	}

	if value.Authorization.BatchSigning.CertificateSHA256 !=
		"73370bbea681abf0080e68e69b29c0b68129108a9106ad556ce8da42d7944dc6" {
		t.Fatal("batch-signing certificate SHA-256 was not normalized")
	}
}

func TestParseSourceConfigRejectsDuplicateDirective(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"enabled: true",
		"enabled: true\nenabled: false",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want duplicate rejection")
	}
}

func TestParseSourceConfigRejectsInvalidSHA256(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"B4377143A213BE00B977C2930265CD6A459F95B978B0713676A4153F51AF5092",
		"NOT-A-SHA256",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want SHA-256 rejection")
	}
}

func TestParseSourceConfigRejectsMissingDirective(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"transport_common_name: iss-fs-01.iss.local\n",
		"",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want missing-directive rejection")
	}
}

func TestParseSourceConfigRejectsNonCanonicalBoolean(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"enabled: true",
		"enabled: yes",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want boolean rejection")
	}
}

func TestParseSourceConfigRejectsSharedCertificate(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"73370BBEA681ABF0080E68E69B29C0B68129108A9106AD556CE8DA42D7944DC6",
		"B4377143A213BE00B977C2930265CD6A459F95B978B0713676A4153F51AF5092",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want certificate-separation rejection")
	}
}

func TestParseSourceConfigRejectsSourceIdentityMismatch(t *testing.T) {
	input := strings.Replace(
		validSourceConfig,
		"source_id: iss-fs-01.iss.local",
		"source_id: other-server.iss.local",
		1,
	)

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want source identity rejection")
	}
}

func TestParseSourceConfigRejectsUnknownDirective(t *testing.T) {
	input := validSourceConfig + "allow_any_certificate: true\n"

	if _, err := ParseSourceConfig(strings.NewReader(input)); err == nil {
		t.Fatal("ParseSourceConfig() error = nil, want unknown-directive rejection")
	}
}
