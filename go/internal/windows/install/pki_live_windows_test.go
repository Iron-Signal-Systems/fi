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

	beforeCertificates, err :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)
	if err != nil {
		t.Fatalf(
			"snapshot certificates before enrollment: %v",
			err,
		)
	}

	beforeKeys, err :=
		snapshotFIMachineCNGKeys()
	if err != nil {
		t.Fatalf(
			"snapshot machine CNG keys before enrollment: %v",
			err,
		)
	}

	t.Logf(
		"before: matching certificates=%d machine_cng_keys=%d",
		len(beforeCertificates),
		len(beforeKeys),
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
					"emergency cleanup of transaction-owned certificate SHA256=%s key=%q failed: %v",
					mutation.Certificate.CertificateSHA256,
					mutation.Key.KeyName,
					err,
				)
			}
		},
	)

	if enrollErr != nil {
		if mutation.Owned {
			t.Fatalf(
				"live enrollment failed after establishing exact transaction ownership for SHA256=%s key=%q: %v",
				mutation.Certificate.CertificateSHA256,
				mutation.Key.KeyName,
				enrollErr,
			)
		}

		t.Fatalf(
			"live enrollment failed without transaction ownership: new_machine_keys=%+v error=%v",
			mutation.NewMachineKeys,
			enrollErr,
		)
	}

	if !mutation.Owned {
		t.Fatal(
			"successful enrollment returned no exact transaction-owned certificate/key pair",
		)
	}

	if mutation.Key.KeyName == "" {
		t.Fatal(
			"successful enrollment established ownership without an exact CNG key name",
		)
	}

	if len(mutation.NewMachineKeys) != 1 {
		t.Fatalf(
			"successful enrollment observed %d new machine CNG keys; expected exactly one: %+v",
			len(mutation.NewMachineKeys),
			mutation.NewMachineKeys,
		)
	}

	t.Logf(
		"created: template=%s SHA256=%s CN=%s SAN=%v key=%q provider=%q new_machine_keys=%d",
		mutation.Certificate.TemplateOID,
		mutation.Certificate.CertificateSHA256,
		mutation.Certificate.CommonName,
		mutation.Certificate.DNSNames,
		mutation.Key.KeyName,
		mutation.Key.ProviderName,
		len(mutation.NewMachineKeys),
	)

	if err := rollbackOwnedPKIEnrollment(
		mutation,
	); err != nil {
		t.Fatalf(
			"rollback transaction-owned certificate SHA256=%s key=%q: %v",
			mutation.Certificate.CertificateSHA256,
			mutation.Key.KeyName,
			err,
		)
	}

	cleanupNeeded = false

	afterCertificates, err :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)
	if err != nil {
		t.Fatalf(
			"snapshot certificates after rollback: %v",
			err,
		)
	}

	afterKeys, err :=
		snapshotFIMachineCNGKeys()
	if err != nil {
		t.Fatalf(
			"snapshot machine CNG keys after rollback: %v",
			err,
		)
	}

	if !reflect.DeepEqual(
		beforeCertificates,
		afterCertificates,
	) {
		t.Fatalf(
			"LocalMachine\\MY did not return exactly to its pre-enrollment certificate state:\nbefore=%+v\nafter=%+v",
			beforeCertificates,
			afterCertificates,
		)
	}

	if !reflect.DeepEqual(
		beforeKeys,
		afterKeys,
	) {
		t.Fatalf(
			"Microsoft Software KSP machine-key inventory did not return exactly to its pre-enrollment state:\nbefore=%+v\nafter=%+v",
			beforeKeys,
			afterKeys,
		)
	}

	t.Logf(
		"rollback complete: matching certificates=%d machine_cng_keys=%d; certificate store and machine-key inventory restored exactly",
		len(afterCertificates),
		len(afterKeys),
	)
}
