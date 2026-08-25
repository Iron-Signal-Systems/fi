// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"errors"
	"sort"
)

const WindowsSecurityCollectionMethod = "WindowsSecurityEventLogV0"

type WindowsSecurityAuditResult string

const (
	WindowsSecurityAuditSuccess       WindowsSecurityAuditResult = "Success"
	WindowsSecurityAuditFailure       WindowsSecurityAuditResult = "Failure"
	WindowsSecurityAuditNotApplicable WindowsSecurityAuditResult = "NotApplicable"
	WindowsSecurityAuditUnknown       WindowsSecurityAuditResult = "Unknown"
)

type WindowsSecurityScopeBasis string

const (
	WindowsSecurityScopePathMatched                  WindowsSecurityScopeBasis = "PathMatched"
	WindowsSecurityScopeHardLinkPathMatched          WindowsSecurityScopeBasis = "HardLinkPathMatched"
	WindowsSecurityScopeUnresolvedFileDeleteIncluded WindowsSecurityScopeBasis = "UnresolvedFileDeleteIncluded"
	WindowsSecurityScopeHostMonitoringChange         WindowsSecurityScopeBasis = "HostMonitoringChange"
)

type WindowsSecurityEventField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WindowsSecurityMatchedScope struct {
	ScopeID      string `json:"scope_id"`
	GovernedRoot string `json:"governed_root"`
}

// WindowsSecurityEventObservation preserves one selected Windows Security
// channel event and common file-activity projections. RawXML remains the source
// representation; the projected fields do not infer actor intent or outcome.
type WindowsSecurityEventObservation struct {
	ObservedAt       string                        `json:"observed_at"`
	CollectionMethod string                        `json:"collection_method"`
	Channel          string                        `json:"channel"`
	Provider         string                        `json:"provider"`
	EventID          string                        `json:"event_id"`
	Version          string                        `json:"version,omitempty"`
	EventRecordID    string                        `json:"event_record_id"`
	TimeCreated      string                        `json:"time_created"`
	Computer         string                        `json:"computer"`
	Keywords         string                        `json:"keywords,omitempty"`
	AuditResult      WindowsSecurityAuditResult    `json:"audit_result"`
	ScopeBasis       WindowsSecurityScopeBasis     `json:"scope_basis"`
	MatchedScopes    []WindowsSecurityMatchedScope `json:"matched_scopes"`
	Fields           []WindowsSecurityEventField   `json:"fields"`

	SubjectUserSID        string `json:"subject_user_sid,omitempty"`
	SubjectUserName       string `json:"subject_user_name,omitempty"`
	SubjectDomainName     string `json:"subject_domain_name,omitempty"`
	SubjectLogonID        string `json:"subject_logon_id,omitempty"`
	ObjectServer          string `json:"object_server,omitempty"`
	ObjectType            string `json:"object_type,omitempty"`
	ObjectName            string `json:"object_name,omitempty"`
	HandleID              string `json:"handle_id,omitempty"`
	ProcessID             string `json:"process_id,omitempty"`
	ProcessName           string `json:"process_name,omitempty"`
	AccessMask            string `json:"access_mask,omitempty"`
	AccessList            string `json:"access_list,omitempty"`
	TransactionID         string `json:"transaction_id,omitempty"`
	FileName              string `json:"file_name,omitempty"`
	LinkName              string `json:"link_name,omitempty"`
	OldSecurityDescriptor string `json:"old_security_descriptor,omitempty"`
	NewSecurityDescriptor string `json:"new_security_descriptor,omitempty"`
	SubcategoryGUID       string `json:"subcategory_guid,omitempty"`
	AuditPolicyChanges    string `json:"audit_policy_changes,omitempty"`
	RawXML                string `json:"raw_xml"`
}

type WindowsSecurityAuditPolicyObservation struct {
	SubcategoryGUID     string `json:"subcategory_guid"`
	AuditingInformation string `json:"auditing_information"`
	SuccessEnabled      bool   `json:"success_enabled"`
	FailureEnabled      bool   `json:"failure_enabled"`
	ReasonCode          string `json:"reason_code,omitempty"`
}

type WindowsSecurityRootAuditCoverage struct {
	ScopeID                       string `json:"scope_id"`
	GovernedRoot                  string `json:"governed_root"`
	SACLState                     string `json:"sacl_state"`
	RecommendedChangeAuditPresent bool   `json:"recommended_change_audit_present"`
	ReasonCode                    string `json:"reason_code,omitempty"`
}

type WindowsSecurityCoverageStatus string

const (
	WindowsSecurityCoverageReady   WindowsSecurityCoverageStatus = "Ready"
	WindowsSecurityCoveragePartial WindowsSecurityCoverageStatus = "Partial"
)

// WindowsSecurityCoverageObservation says whether the Windows sources needed
// for actor/process-aware file activity were configured and readable when FI ran.
type WindowsSecurityCoverageObservation struct {
	ObservedAt               string                                `json:"observed_at"`
	CollectionMethod         string                                `json:"collection_method"`
	SecurityLogReadable      bool                                  `json:"security_log_readable"`
	FileSystemPolicy         WindowsSecurityAuditPolicyObservation `json:"file_system_policy"`
	HandleManipulationPolicy WindowsSecurityAuditPolicyObservation `json:"handle_manipulation_policy"`
	AuditPolicyChangePolicy  WindowsSecurityAuditPolicyObservation `json:"audit_policy_change_policy"`
	Roots                    []WindowsSecurityRootAuditCoverage    `json:"roots"`
	Status                   WindowsSecurityCoverageStatus         `json:"status"`
}

func ValidateWindowsSecurityEventObservation(value WindowsSecurityEventObservation) error {
	if err := ValidateObservedAt(value.ObservedAt); err != nil {
		return err
	}
	if value.CollectionMethod != WindowsSecurityCollectionMethod || value.Channel != "Security" ||
		value.Provider == "" || value.EventID == "" || value.EventRecordID == "" ||
		value.TimeCreated == "" || value.Computer == "" || value.RawXML == "" {
		return errors.New("invalid Windows Security event observation")
	}
	if err := ValidateObservedAt(value.TimeCreated); err != nil {
		return err
	}
	if err := validateDecimal(value.EventID, "windows_security.event_id"); err != nil {
		return err
	}
	if err := validateDecimal(value.EventRecordID, "windows_security.event_record_id"); err != nil {
		return err
	}
	switch value.AuditResult {
	case WindowsSecurityAuditSuccess, WindowsSecurityAuditFailure, WindowsSecurityAuditNotApplicable, WindowsSecurityAuditUnknown:
	default:
		return errors.New("invalid Windows Security audit result")
	}
	switch value.ScopeBasis {
	case WindowsSecurityScopePathMatched, WindowsSecurityScopeHardLinkPathMatched,
		WindowsSecurityScopeUnresolvedFileDeleteIncluded, WindowsSecurityScopeHostMonitoringChange:
	default:
		return errors.New("invalid Windows Security scope basis")
	}
	for _, scope := range value.MatchedScopes {
		if scope.ScopeID == "" || scope.GovernedRoot == "" {
			return errors.New("invalid Windows Security matched scope")
		}
	}
	return nil
}

func ValidateWindowsSecurityCoverageObservation(value WindowsSecurityCoverageObservation) error {
	if err := ValidateObservedAt(value.ObservedAt); err != nil {
		return err
	}
	if value.CollectionMethod != WindowsSecurityCollectionMethod {
		return errors.New("invalid Windows Security coverage collection method")
	}
	for _, policy := range []WindowsSecurityAuditPolicyObservation{
		value.FileSystemPolicy,
		value.HandleManipulationPolicy,
		value.AuditPolicyChangePolicy,
	} {
		if policy.SubcategoryGUID == "" || policy.AuditingInformation == "" {
			return errors.New("invalid Windows Security audit policy observation")
		}
	}
	if !sort.SliceIsSorted(value.Roots, func(i, j int) bool { return value.Roots[i].ScopeID < value.Roots[j].ScopeID }) {
		return errors.New("Windows Security coverage roots are not sorted")
	}
	switch value.Status {
	case WindowsSecurityCoverageReady, WindowsSecurityCoveragePartial:
		return nil
	default:
		return errors.New("invalid Windows Security coverage status")
	}
}
