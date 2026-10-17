// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
)

type ReplacementDecision struct {
	Activate bool
	Reason   string
}

func AssessReplacement(
	current *x509.RevocationList,
	candidate *x509.RevocationList,
) (ReplacementDecision, error) {
	if current == nil {
		return ReplacementDecision{}, errors.New(
			"current transport CRL is required",
		)
	}

	if candidate == nil {
		return ReplacementDecision{}, errors.New(
			"candidate transport CRL is required",
		)
	}

	if current.ThisUpdate.IsZero() {
		return ReplacementDecision{}, errors.New(
			"current transport CRL thisUpdate is required",
		)
	}

	if candidate.ThisUpdate.IsZero() {
		return ReplacementDecision{}, errors.New(
			"candidate transport CRL thisUpdate is required",
		)
	}

	if !bytes.Equal(
		current.RawIssuer,
		candidate.RawIssuer,
	) {
		return ReplacementDecision{}, errors.New(
			"candidate transport CRL issuer differs from current CRL issuer",
		)
	}

	if bytes.Equal(
		current.Raw,
		candidate.Raw,
	) {
		return ReplacementDecision{
			Activate: false,
			Reason:   "candidate transport CRL matches current signed DER",
		}, nil
	}

	if current.Number != nil &&
		current.Number.Sign() < 0 {
		return ReplacementDecision{}, errors.New(
			"current transport CRL number is negative",
		)
	}

	if candidate.Number != nil &&
		candidate.Number.Sign() < 0 {
		return ReplacementDecision{}, errors.New(
			"candidate transport CRL number is negative",
		)
	}

	if current.Number != nil &&
		candidate.Number == nil {
		return ReplacementDecision{}, errors.New(
			"candidate transport CRL omits CRL number present in current CRL",
		)
	}

	numberProgressed := false

	if current.Number != nil &&
		candidate.Number != nil {
		switch candidate.Number.Cmp(
			current.Number,
		) {
		case -1:
			return ReplacementDecision{}, fmt.Errorf(
				"candidate transport CRL number=%s is older than current number=%s",
				candidate.Number.Text(10),
				current.Number.Text(10),
			)

		case 0:
			return ReplacementDecision{}, fmt.Errorf(
				"candidate transport CRL reuses current CRL number=%s with different signed DER",
				current.Number.Text(10),
			)

		case 1:
			numberProgressed = true
		}
	}

	if candidate.ThisUpdate.Before(
		current.ThisUpdate,
	) {
		return ReplacementDecision{}, fmt.Errorf(
			"candidate transport CRL thisUpdate=%s precedes current thisUpdate=%s",
			candidate.ThisUpdate.UTC().Format(
				"2006-01-02T15:04:05Z07:00",
			),
			current.ThisUpdate.UTC().Format(
				"2006-01-02T15:04:05Z07:00",
			),
		)
	}

	if candidate.ThisUpdate.Equal(
		current.ThisUpdate,
	) &&
		!numberProgressed {
		return ReplacementDecision{}, fmt.Errorf(
			"candidate transport CRL has current thisUpdate=%s but different signed DER without a newer CRL number",
			current.ThisUpdate.UTC().Format(
				"2006-01-02T15:04:05Z07:00",
			),
		)
	}

	return ReplacementDecision{
		Activate: true,
		Reason:   "candidate transport CRL is newer than current CRL",
	}, nil
}
