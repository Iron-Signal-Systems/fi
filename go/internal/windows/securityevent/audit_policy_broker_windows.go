// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
)

// brokerRequiredAuditPolicies uses named observations so the broker's fixed
// wire order cannot silently become a wrong policy-to-GUID attribution.
type brokerRequiredAuditPolicies struct {
	FileSystem         records.WindowsSecurityAuditPolicyObservation
	HandleManipulation records.WindowsSecurityAuditPolicyObservation
	DetailedFileShare  records.WindowsSecurityAuditPolicyObservation
	PolicyChange       records.WindowsSecurityAuditPolicyObservation
}

func queryBrokerRequiredAuditPolicies(ctx context.Context) (brokerRequiredAuditPolicies, error) {
	if ctx == nil {
		return brokerRequiredAuditPolicies{}, errors.New("FI Windows Security coverage context is nil")
	}

	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	flags, err := usnbroker.QueryAuditPolicies(bounded)
	if err != nil {
		return brokerRequiredAuditPolicies{}, fmt.Errorf("FIUSNReader effective audit policy: %w", err)
	}
	return brokerPolicyObservations(flags)
}

// brokerPolicyObservations validates the existing four-slot protocol. The
// schema check is deliberate: do not silently accept a changed ordering.
func brokerPolicyObservations(flags []uint32) (brokerRequiredAuditPolicies, error) {
	required := auditpolicy.Required()
	expected := [4]string{
		AuditPolicyChangeSubcategoryGUID,
		FileSystemAuditSubcategoryGUID,
		HandleManipulationSubcategoryGUID,
		DetailedFileShareSubcategoryGUID,
	}
	if len(required) != len(expected) || len(flags) != len(expected) {
		return brokerRequiredAuditPolicies{}, fmt.Errorf(
			"FIUSNReader effective audit-policy count: required=%d received=%d expected=%d",
			len(required), len(flags), len(expected),
		)
	}

	var values [4]records.WindowsSecurityAuditPolicyObservation
	for i, policy := range required {
		if policy.GUID != expected[i] {
			return brokerRequiredAuditPolicies{}, fmt.Errorf(
				"FIUSNReader effective audit-policy contract order mismatch at index %d: %s",
				i, policy.GUID,
			)
		}
		values[i] = records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     policy.GUID,
			AuditingInformation: strconv.FormatUint(uint64(flags[i]), 10),
			SuccessEnabled:      flags[i]&auditpolicy.Success != 0,
			FailureEnabled:      flags[i]&auditpolicy.Failure != 0,
		}
	}
	return brokerRequiredAuditPolicies{
		PolicyChange:       values[0],
		FileSystem:         values[1],
		HandleManipulation: values[2],
		DetailedFileShare:  values[3],
	}, nil
}

func unknownBrokerRequiredAuditPolicies(cause error) brokerRequiredAuditPolicies {
	reason := "FIUSNReader returned no effective audit policy"
	if cause != nil {
		reason = cause.Error()
	}
	unknown := func(guid string) records.WindowsSecurityAuditPolicyObservation {
		return records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     guid,
			AuditingInformation: "Unknown",
			ReasonCode:          reason,
		}
	}
	return brokerRequiredAuditPolicies{
		FileSystem:         unknown(FileSystemAuditSubcategoryGUID),
		HandleManipulation: unknown(HandleManipulationSubcategoryGUID),
		DetailedFileShare:  unknown(DetailedFileShareSubcategoryGUID),
		PolicyChange:       unknown(AuditPolicyChangeSubcategoryGUID),
	}
}
