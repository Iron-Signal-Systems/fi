// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestAssessReplacementIdenticalDERIsNoChange(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("same"),
	)

	candidate := replacementCRL(
		10,
		now,
		[]byte("same"),
	)

	decision, err := AssessReplacement(
		current,
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}

	if decision.Activate {
		t.Fatal(
			"identical CRL unexpectedly requested activation",
		)
	}
}

func TestAssessReplacementAcceptsNewerNumber(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRL(
		11,
		now.Add(time.Minute),
		[]byte("candidate"),
	)

	decision, err := AssessReplacement(
		current,
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !decision.Activate {
		t.Fatal(
			"newer CRL did not request activation",
		)
	}
}

func TestAssessReplacementAcceptsNewerNumberAtSameThisUpdate(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRL(
		11,
		now,
		[]byte("candidate"),
	)

	decision, err := AssessReplacement(
		current,
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !decision.Activate {
		t.Fatal(
			"newer CRL number at same thisUpdate did not request activation",
		)
	}
}

func TestAssessReplacementRejectsLowerNumber(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRL(
		9,
		now.Add(time.Hour),
		[]byte("candidate"),
	)

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"older CRL number was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"older than current",
	) {
		t.Fatalf(
			"error=%q want CRL-number rollback failure",
			err,
		)
	}
}

func TestAssessReplacementRejectsSameNumberDifferentDER(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRL(
		10,
		now.Add(time.Minute),
		[]byte("candidate"),
	)

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"conflicting same-number CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"reuses current CRL number",
	) {
		t.Fatalf(
			"error=%q want same-number conflict",
			err,
		)
	}
}

func TestAssessReplacementRejectsNumberRemoval(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRLWithoutNumber(
		now.Add(time.Minute),
		[]byte("candidate"),
	)

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"candidate without CRL number was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"omits CRL number",
	) {
		t.Fatalf(
			"error=%q want CRL-number removal failure",
			err,
		)
	}
}

func TestAssessReplacementRejectsOlderThisUpdate(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRLWithoutNumber(
		now,
		[]byte("current"),
	)

	candidate := replacementCRLWithoutNumber(
		now.Add(-time.Minute),
		[]byte("candidate"),
	)

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"older thisUpdate was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"precedes current",
	) {
		t.Fatalf(
			"error=%q want thisUpdate rollback failure",
			err,
		)
	}
}

func TestAssessReplacementRejectsSameTimeWithoutNumberProgression(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRLWithoutNumber(
		now,
		[]byte("current"),
	)

	candidate := replacementCRLWithoutNumber(
		now,
		[]byte("candidate"),
	)

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"ambiguous same-time CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"without a newer CRL number",
	) {
		t.Fatalf(
			"error=%q want ambiguous replacement failure",
			err,
		)
	}
}

func TestAssessReplacementAcceptsNewerThisUpdateWithoutNumbers(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRLWithoutNumber(
		now,
		[]byte("current"),
	)

	candidate := replacementCRLWithoutNumber(
		now.Add(time.Minute),
		[]byte("candidate"),
	)

	decision, err := AssessReplacement(
		current,
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !decision.Activate {
		t.Fatal(
			"newer unnumbered CRL did not request activation",
		)
	}
}

func TestAssessReplacementRejectsIssuerDrift(
	t *testing.T,
) {
	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	current := replacementCRL(
		10,
		now,
		[]byte("current"),
	)

	candidate := replacementCRL(
		11,
		now.Add(time.Minute),
		[]byte("candidate"),
	)

	candidate.RawIssuer =
		[]byte("different-issuer")

	_, err := AssessReplacement(
		current,
		candidate,
	)

	if err == nil {
		t.Fatal(
			"issuer drift was unexpectedly accepted",
		)
	}
}

func replacementCRL(
	number int64,
	thisUpdate time.Time,
	raw []byte,
) *x509.RevocationList {
	value := replacementCRLWithoutNumber(
		thisUpdate,
		raw,
	)

	value.Number = big.NewInt(
		number,
	)

	return value
}

func replacementCRLWithoutNumber(
	thisUpdate time.Time,
	raw []byte,
) *x509.RevocationList {
	return &x509.RevocationList{
		Raw: append(
			[]byte(nil),
			raw...,
		),
		RawIssuer: []byte(
			"same-issuer",
		),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(
			time.Hour,
		),
	}
}
