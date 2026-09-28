// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestLivePKIEnrollRollback(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_ENROLL_ROLLBACK",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_ENROLL_ROLLBACK=1 to run live AD CS enrollment/rollback characterization",
		)
	}

	contract := pkiEnrollmentContract{
		ExpectedDNS: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_EXPECTED_DNS",
			),
		),
		TemplateName: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_TEMPLATE",
			),
		),
		TemplateOID: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_TEMPLATE_OID",
			),
		),
	}

	if err := validatePKIEnrollmentContract(
		contract,
	); err != nil {
		t.Fatal(err)
	}

	before, err := snapshotLocalMachinePKICertificates(
		contract.TemplateOID,
	)
	if err != nil {
		t.Fatalf(
			"snapshot before enrollment: %v",
			err,
		)
	}

	t.Logf(
		"before: matching certificates=%d",
		len(before),
	)

	mutation, enrollErr :=
		enrollMachineCertificateTemplateTracked(
			contract,
		)

	cleanupNeeded := mutation.Owned

	t.Cleanup(
		func() {
			if !cleanupNeeded {
				return
			}

			if err := rollbackOwnedPKIEnrollment(
				mutation,
			); err != nil {
				t.Errorf(
					"emergency cleanup of transaction-owned certificate SHA256=%s failed: %v",
					mutation.Certificate.CertificateSHA256,
					err,
				)
			}
		},
	)

	if enrollErr != nil {
		if mutation.Owned {
			t.Fatalf(
				"live enrollment failed after creating transaction-owned SHA256=%s: %v",
				mutation.Certificate.CertificateSHA256,
				enrollErr,
			)
		}

		t.Fatalf(
			"live enrollment failed: %v",
			enrollErr,
		)
	}

	if !mutation.Owned {
		t.Fatal(
			"successful enrollment returned no transaction-owned certificate",
		)
	}

	t.Logf(
		"created: template=%s SHA256=%s CN=%s SAN=%v",
		mutation.Certificate.TemplateOID,
		mutation.Certificate.CertificateSHA256,
		mutation.Certificate.CommonName,
		mutation.Certificate.DNSNames,
	)

	if err := rollbackOwnedPKIEnrollment(
		mutation,
	); err != nil {
		t.Fatalf(
			"rollback transaction-owned certificate SHA256=%s: %v",
			mutation.Certificate.CertificateSHA256,
			err,
		)
	}

	cleanupNeeded = false

	after, err := snapshotLocalMachinePKICertificates(
		contract.TemplateOID,
	)
	if err != nil {
		t.Fatalf(
			"snapshot after rollback: %v",
			err,
		)
	}

	if !reflect.DeepEqual(
		before,
		after,
	) {
		t.Fatalf(
			"LocalMachine\\MY did not return exactly to its pre-enrollment state:\nbefore=%+v\nafter=%+v",
			before,
			after,
		)
	}

	t.Logf(
		"rollback complete: matching certificates=%d; pre-enrollment state restored exactly",
		len(after),
	)
}
