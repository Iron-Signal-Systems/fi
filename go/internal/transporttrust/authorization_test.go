// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import "testing"

func TestAuthorizeSource(t *testing.T) {
	source := SourceAuthorization{
		BatchSigning: CertificateIdentity{
			CertificateSHA256:  "73370BBEA681ABF0080E68E69B29C0B68129108A9106AD556CE8DA42D7944DC6",
			CommonName:         "iss-fs-01.iss.local",
			IssuingCASHA256:    "A309F854C0F54B9B7C28ED27CDF32D4C65B699CEBA31F05BB0A942D2DEFCFC51",
			OrganizationalUnit: "FI Batch Signing",
		},
		Enabled:  true,
		SourceID: "iss-fs-01.iss.local",
		Transport: CertificateIdentity{
			CertificateSHA256:  "B4377143A213BE00B977C2930265CD6A459F95B978B0713676A4153F51AF5092",
			CommonName:         "iss-fs-01.iss.local",
			IssuingCASHA256:    "5EB837ED1C71E057E3F17FFB3ECF8F84176C106FB5D9437487C2A89A2151A971",
			OrganizationalUnit: "FI Shipper Transport",
		},
	}

	tests := []struct {
		name      string
		source    SourceAuthorization
		use       CertificateUse
		presented CertificateIdentity
		want      AuthorizationOutcome
	}{
		{
			name:      "batch signing authorized",
			source:    source,
			use:       CertificateUseBatchSigning,
			presented: source.BatchSigning,
			want:      AuthorizationAuthorized,
		},
		{
			name:      "transport authorized",
			source:    source,
			use:       CertificateUseTransport,
			presented: source.Transport,
			want:      AuthorizationAuthorized,
		},
		{
			name: "disabled source rejected",
			source: SourceAuthorization{
				BatchSigning: source.BatchSigning,
				Enabled:      false,
				SourceID:     source.SourceID,
				Transport:    source.Transport,
			},
			use:       CertificateUseTransport,
			presented: source.Transport,
			want:      AuthorizationDisabled,
		},
		{
			name:   "wrong certificate rejected",
			source: source,
			use:    CertificateUseTransport,
			presented: CertificateIdentity{
				CertificateSHA256:  "A4377143A213BE00B977C2930265CD6A459F95B978B0713676A4153F51AF5092",
				CommonName:         source.Transport.CommonName,
				IssuingCASHA256:    source.Transport.IssuingCASHA256,
				OrganizationalUnit: source.Transport.OrganizationalUnit,
			},
			want: AuthorizationCertificateMismatch,
		},
		{
			name:   "wrong common name rejected",
			source: source,
			use:    CertificateUseTransport,
			presented: CertificateIdentity{
				CertificateSHA256:  source.Transport.CertificateSHA256,
				CommonName:         "other-server.iss.local",
				IssuingCASHA256:    source.Transport.IssuingCASHA256,
				OrganizationalUnit: source.Transport.OrganizationalUnit,
			},
			want: AuthorizationIdentityMismatch,
		},
		{
			name:   "wrong organizational unit rejected",
			source: source,
			use:    CertificateUseTransport,
			presented: CertificateIdentity{
				CertificateSHA256:  source.Transport.CertificateSHA256,
				CommonName:         source.Transport.CommonName,
				IssuingCASHA256:    source.Transport.IssuingCASHA256,
				OrganizationalUnit: "FI Batch Signing",
			},
			want: AuthorizationIdentityMismatch,
		},
		{
			name:      "transport certificate cannot act as batch signer",
			source:    source,
			use:       CertificateUseBatchSigning,
			presented: source.Transport,
			want:      AuthorizationIdentityMismatch,
		},
		{
			name:      "batch certificate cannot act as transport identity",
			source:    source,
			use:       CertificateUseTransport,
			presented: source.BatchSigning,
			want:      AuthorizationIdentityMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := AuthorizeSource(
				test.source,
				test.use,
				test.presented,
			)
			if err != nil {
				t.Fatalf("AuthorizeSource() error = %v", err)
			}

			if got != test.want {
				t.Fatalf(
					"AuthorizeSource() = %q, want %q",
					got,
					test.want,
				)
			}
		})
	}
}
