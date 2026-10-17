// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportcrl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

func TestActivateCandidate(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			10,
			now.Add(-2*time.Hour),
			now.Add(2*time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			11,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			500,
		),
	}

	result, err := ActivateCandidate(
		active,
		candidateDER,
		issuer,
		leaf,
		now,
		"success",
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Activated {
		t.Fatalf(
			"Activated=false reason=%q",
			result.Reason,
		)
	}

	assertActivationTestDER(
		t,
		active,
		candidateDER,
	)

	assertActivationTestDER(
		t,
		result.BackupPath,
		currentDER,
	)

	if result.FailedPath != "" {
		t.Fatalf(
			"FailedPath=%q want empty",
			result.FailedPath,
		)
	}

	assertActivationTestAbsent(
		t,
		active+".fi-new-success",
	)
}

func TestActivateCandidateIdenticalIsNoChange(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			10,
			now.Add(-time.Minute),
			now.Add(time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			501,
		),
	}

	result, err := ActivateCandidate(
		active,
		currentDER,
		issuer,
		leaf,
		now,
		"nochange",
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Activated {
		t.Fatal(
			"identical CRL unexpectedly activated",
		)
	}

	assertActivationTestDER(
		t,
		active,
		currentDER,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-nochange",
	)

	assertActivationTestAbsent(
		t,
		active+".fi-backup-nochange",
	)
}

func TestActivateCandidateRejectsRollback(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			20,
			now.Add(-time.Hour),
			now.Add(2*time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			19,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			502,
		),
	}

	_, err := ActivateCandidate(
		active,
		candidateDER,
		issuer,
		leaf,
		now,
		"rollback",
	)

	if err == nil {
		t.Fatal(
			"rollback candidate unexpectedly activated",
		)
	}

	assertActivationTestDER(
		t,
		active,
		currentDER,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-rollback",
	)

	assertActivationTestAbsent(
		t,
		active+".fi-backup-rollback",
	)
}

func TestActivateCandidateDetectsActiveRace(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			30,
			now.Add(-time.Hour),
			now.Add(2*time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			31,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	newerDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			32,
			now,
			now.Add(5*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			503,
		),
	}

	_, err := activateCandidateWithDependencies(
		active,
		candidateDER,
		issuer,
		leaf,
		now,
		"race",
		activationDependencies{
			beforeFinalCheck: func() error {
				encoded, err :=
					EncodeCanonicalPEM(
						newerDER,
					)
				if err != nil {
					return err
				}

				return os.WriteFile(
					active,
					encoded,
					0600,
				)
			},
			replace: ReplaceExistingFileWithBackup,
			verify:  VerifyPersistedPEM,
		},
	)

	if err == nil {
		t.Fatal(
			"active-CRL race unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"changed after replacement assessment",
	) {
		t.Fatalf(
			"error=%q want active-state race rejection",
			err,
		)
	}

	assertActivationTestDER(
		t,
		active,
		newerDER,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-race",
	)

	assertActivationTestAbsent(
		t,
		active+".fi-backup-race",
	)
}

func TestActivateCandidateRestoresPreviousAfterPostVerifyFailure(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			40,
			now.Add(-time.Hour),
			now.Add(2*time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			41,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			504,
		),
	}

	activeVerificationCount := 0

	result, err :=
		activateCandidateWithDependencies(
			active,
			candidateDER,
			issuer,
			leaf,
			now,
			"verifyfail",
			activationDependencies{
				replace: ReplaceExistingFileWithBackup,
				verify: func(
					path string,
					expectedDER []byte,
					expectedSHA256 string,
				) error {
					if filepath.Clean(path) ==
						filepath.Clean(active) {
						activeVerificationCount++

						if activeVerificationCount == 1 {
							return errors.New(
								"injected post-activation verification failure",
							)
						}
					}

					return VerifyPersistedPEM(
						path,
						expectedDER,
						expectedSHA256,
					)
				},
			},
		)

	if err == nil {
		t.Fatal(
			"injected post-activation verification failure unexpectedly succeeded",
		)
	}

	if result.Activated {
		t.Fatal(
			"result reports activated after rollback",
		)
	}

	assertActivationTestDER(
		t,
		active,
		currentDER,
	)

	assertActivationTestDER(
		t,
		result.FailedPath,
		candidateDER,
	)

	assertActivationTestAbsent(
		t,
		result.BackupPath,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-verifyfail",
	)
}

func TestActivateCandidateRejectsInvalidTransactionID(
	t *testing.T,
) {
	_, err := ActivateCandidate(
		`C:\unused\transport.crl.pem`,
		nil,
		nil,
		nil,
		time.Now().UTC(),
		"bad/id",
	)
	if err == nil {
		t.Fatal(
			"invalid transaction ID was unexpectedly accepted",
		)
	}

	const want = "transport CRL activation transaction ID contains unsupported character '/'"

	if err.Error() != want {
		t.Fatalf(
			"error=%q want=%q",
			err,
			want,
		)
	}
}
func assertActivationTestAbsent(
	t *testing.T,
	path string,
) {
	t.Helper()

	_, err := os.Lstat(
		path,
	)

	if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"path %s unexpectedly exists; err=%v",
			path,
			err,
		)
	}
}

func assertActivationTestDER(
	t *testing.T,
	path string,
	want []byte,
) {
	t.Helper()

	value, err := receivertrust.LoadCRL(
		path,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(value.Raw) !=
		string(want) {
		t.Fatalf(
			"%s DER does not match expected CRL",
			path,
		)
	}
}

func newActivationTestCRLDER(
	t *testing.T,
	issuer *x509.Certificate,
	key *rsa.PrivateKey,
	number int64,
	thisUpdate time.Time,
	nextUpdate time.Time,
) []byte {
	t.Helper()

	value, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number: big.NewInt(
				number,
			),
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
		},
		issuer,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func writeActivationTestCRL(
	t *testing.T,
	path string,
	der []byte,
) {
	t.Helper()

	encoded, err :=
		EncodeCanonicalPEM(
			der,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		path,
		encoded,
		0600,
	); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(
		der,
	)

	if err := VerifyPersistedPEM(
		path,
		der,
		hex.EncodeToString(
			digest[:],
		),
	); err != nil {
		t.Fatal(err)
	}
}

func TestActivateCandidateReplacesExpiredAuthenticCurrent(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			50,
			now.Add(-4*time.Hour),
			now.Add(-time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			51,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			801,
		),
	}

	result, err := ActivateCandidate(
		active,
		candidateDER,
		issuer,
		leaf,
		now,
		"expired-current",
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Activated {
		t.Fatal(
			"fresh candidate did not replace expired authentic active CRL",
		)
	}

	if result.BackupPath == "" {
		t.Fatal(
			"activation did not retain previous expired CRL backup",
		)
	}

	assertActivationTestDER(
		t,
		active,
		candidateDER,
	)

	assertActivationTestDER(
		t,
		result.BackupPath,
		currentDER,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-expired-current",
	)
}
func TestActivateCandidateRejectsFutureDatedCurrent(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	currentThisUpdate :=
		now.Add(
			time.Hour,
		)

	currentDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			60,
			currentThisUpdate,
			now.Add(5*time.Hour),
		)

	candidateDER :=
		newActivationTestCRLDER(
			t,
			issuer,
			key,
			61,
			now.Add(-time.Minute),
			now.Add(4*time.Hour),
		)

	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"transport.crl.pem",
	)

	writeActivationTestCRL(
		t,
		active,
		currentDER,
	)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			802,
		),
	}

	result, err := ActivateCandidate(
		active,
		candidateDER,
		issuer,
		leaf,
		now,
		"future-current",
	)

	if err == nil {
		t.Fatal(
			"future-dated active CRL was unexpectedly accepted",
		)
	}

	want :=
		"active transport CRL is not yet valid: thisUpdate=" +
			currentThisUpdate.UTC().Format(
				time.RFC3339,
			)

	if err.Error() != want {
		t.Fatalf(
			"error=%q want=%q",
			err,
			want,
		)
	}

	if result.Activated {
		t.Fatal(
			"candidate activated despite future-dated active CRL",
		)
	}

	assertActivationTestDER(
		t,
		active,
		currentDER,
	)

	assertActivationTestAbsent(
		t,
		active+".fi-new-future-current",
	)

	assertActivationTestAbsent(
		t,
		active+".fi-backup-future-current",
	)

	assertActivationTestAbsent(
		t,
		active+".fi-failed-future-current",
	)
}
