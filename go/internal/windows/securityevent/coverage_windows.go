// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const (
	recommendedChangeAuditMask = uint64(0x000D0156)
	recommendedReadAuditMask   = uint64(0x00000001)

	recommendedChangeACEFlags = uint64(0x000000C3) // OI | CI | Success | Failure
	recommendedReadACEFlags   = uint64(0x000000C1) // OI | Success | Failure
	inheritOnlyACEFlag        = uint64(0x00000008)
)

func AssessCoverage(ctx context.Context, scopes []GovernedScope) (records.WindowsSecurityCoverageObservation, error) {
	fileSystem, fileSystemErr := queryAuditPolicy(fileSystemAuditGUID, FileSystemAuditSubcategoryGUID)
	if fileSystemErr != nil {
		fileSystem = records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID: FileSystemAuditSubcategoryGUID, AuditingInformation: "Unknown", ReasonCode: fileSystemErr.Error(),
		}
	}

	handleManipulation, handleManipulationErr := queryAuditPolicy(handleManipulationAuditGUID, HandleManipulationSubcategoryGUID)
	if handleManipulationErr != nil {
		handleManipulation = records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID: HandleManipulationSubcategoryGUID, AuditingInformation: "Unknown", ReasonCode: handleManipulationErr.Error(),
		}
	}

	detailedFileShare, detailedFileShareErr := queryAuditPolicy(detailedFileShareAuditGUID, DetailedFileShareSubcategoryGUID)
	if detailedFileShareErr != nil {
		detailedFileShare = records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID: DetailedFileShareSubcategoryGUID, AuditingInformation: "Unknown", ReasonCode: detailedFileShareErr.Error(),
		}
	}

	policyChange, policyChangeErr := queryAuditPolicy(auditPolicyChangeGUID, AuditPolicyChangeSubcategoryGUID)
	if policyChangeErr != nil {
		policyChange = records.WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID: AuditPolicyChangeSubcategoryGUID, AuditingInformation: "Unknown", ReasonCode: policyChangeErr.Error(),
		}
	}

	logReadable := true
	if _, err := QueryLogState(); err != nil {
		logReadable = false
	}

	roots := make([]records.WindowsSecurityRootAuditCoverage, 0, len(scopes))
	for _, scope := range scopes {
		rootCoverage := records.WindowsSecurityRootAuditCoverage{
			ScopeID: scope.ScopeID, GovernedRoot: scope.GovernedRoot,
		}

		observation, err := ntfs.CollectPath(ctx, scope.ScopeID, scope.GovernedRoot, scope.GovernedRoot)
		if err != nil {
			rootCoverage.SACLState = "Error"
			rootCoverage.ReasonCode = err.Error()
			roots = append(roots, rootCoverage)
			continue
		}

		rootCoverage.SACLState = string(observation.SACL.ACL.State)
		rootCoverage.RecommendedChangeAuditPresent = hasRecommendedChangeAuditACE(observation.SACL)
		rootCoverage.RecommendedReadAuditPresent = hasRecommendedReadAuditACE(observation.SACL)
		roots = append(roots, rootCoverage)
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].ScopeID < roots[j].ScopeID })

	status := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, logReadable, roots)

	return records.WindowsSecurityCoverageObservation{
		ObservedAt:               formatCanonicalTime(time.Now()),
		CollectionMethod:         CollectionMethod,
		SecurityLogReadable:      logReadable,
		FileSystemPolicy:         fileSystem,
		HandleManipulationPolicy: handleManipulation,
		DetailedFileSharePolicy:  detailedFileShare,
		AuditPolicyChangePolicy:  policyChange,
		Roots:                    roots,
		Status:                   status,
	}, nil
}

func coverageStatus(
	fileSystem records.WindowsSecurityAuditPolicyObservation,
	handleManipulation records.WindowsSecurityAuditPolicyObservation,
	detailedFileShare records.WindowsSecurityAuditPolicyObservation,
	policyChange records.WindowsSecurityAuditPolicyObservation,
	logReadable bool,
	roots []records.WindowsSecurityRootAuditCoverage,
) records.WindowsSecurityCoverageStatus {
	if !logReadable ||
		!fileSystem.SuccessEnabled ||
		!fileSystem.FailureEnabled ||
		!handleManipulation.FailureEnabled ||
		!detailedFileShare.SuccessEnabled ||
		!detailedFileShare.FailureEnabled ||
		!policyChange.SuccessEnabled {
		return records.WindowsSecurityCoveragePartial
	}

	for _, root := range roots {
		if !root.RecommendedChangeAuditPresent ||
			!root.RecommendedReadAuditPresent {
			return records.WindowsSecurityCoveragePartial
		}
	}

	return records.WindowsSecurityCoverageReady
}

func hasRecommendedChangeAuditACE(sacl records.SACLObservation) bool {
	if sacl.State != records.ObservationStatePresent || sacl.ACL.State != records.ACLStatePresent {
		return false
	}

	for _, ace := range sacl.ACL.ACEs {
		if ace.Type != "2" || ace.SID != "S-1-1-0" || ace.Mask == "" || ace.Flags == "" {
			continue
		}

		mask, err := strconv.ParseUint(ace.Mask, 10, 32)
		if err != nil || mask&recommendedChangeAuditMask != recommendedChangeAuditMask {
			continue
		}

		flags, err := strconv.ParseUint(ace.Flags, 10, 8)
		if err != nil ||
			flags&recommendedChangeACEFlags != recommendedChangeACEFlags ||
			flags&inheritOnlyACEFlag != 0 {
			continue
		}

		return true
	}

	return false
}

func hasRecommendedReadAuditACE(sacl records.SACLObservation) bool {
	if sacl.State != records.ObservationStatePresent || sacl.ACL.State != records.ACLStatePresent {
		return false
	}

	for _, ace := range sacl.ACL.ACEs {
		if ace.Type != "2" || ace.SID != "S-1-1-0" || ace.Mask == "" || ace.Flags == "" {
			continue
		}

		mask, err := strconv.ParseUint(ace.Mask, 10, 32)
		if err != nil || mask&recommendedReadAuditMask != recommendedReadAuditMask {
			continue
		}

		flags, err := strconv.ParseUint(ace.Flags, 10, 8)
		if err != nil || flags&recommendedReadACEFlags != recommendedReadACEFlags {
			continue
		}

		return true
	}

	return false
}
