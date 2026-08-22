// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const DirectoryPrincipalCollectionMethod = "WindowsLDAPCurrentToken"

// DirectoryPrincipalSnapshot records a bounded lookup of Active Directory
// principals by SID. It records directory facts only; it does not calculate
// effective access to files or shares.
type DirectoryPrincipalSnapshot struct {
	ObservedAt       string                          `json:"observed_at"`
	CollectionMethod string                          `json:"collection_method"`
	DomainDNSName    string                          `json:"domain_dns_name"`
	ServerDNSName    string                          `json:"server_dns_name"`
	NamingContext    string                          `json:"naming_context"`
	RequestedSIDs    []string                        `json:"requested_sids"`
	Principals       []DirectoryPrincipalObservation `json:"principals"`
	NotFoundSIDs     []string                        `json:"not_found_sids"`
}

// DirectoryPrincipalObservation records one Active Directory object returned
// for an objectSid lookup. Binary SID and objectGUID values are preserved along
// with their canonical interpretations.
type DirectoryPrincipalObservation struct {
	SID                    string   `json:"sid"`
	SIDRawBase64URL        string   `json:"sid_raw_base64url"`
	ObjectGUID             string   `json:"object_guid"`
	ObjectGUIDRawBase64URL string   `json:"object_guid_raw_base64url"`
	DistinguishedName      string   `json:"distinguished_name"`
	SAMAccountName         string   `json:"sam_account_name,omitempty"`
	UserPrincipalName      string   `json:"user_principal_name,omitempty"`
	ObjectClasses          []string `json:"object_classes"`
	UserAccountControlRaw  string   `json:"user_account_control_raw,omitempty"`
	AccountDisabled        *bool    `json:"account_disabled,omitempty"`
	PrimaryGroupIDRaw      string   `json:"primary_group_id_raw,omitempty"`
}

// ValidateDirectoryPrincipalSnapshot validates the deterministic shared record
// shape and checks that interpreted SID/GUID values match the preserved binary
// values exactly.
func ValidateDirectoryPrincipalSnapshot(snapshot DirectoryPrincipalSnapshot) error {
	if snapshot.CollectionMethod != DirectoryPrincipalCollectionMethod {
		return &ValidationError{Code: "UnsupportedValue", Field: "collection_method"}
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000000Z", snapshot.ObservedAt); err != nil {
		return &ValidationError{Code: "InvalidTimestamp", Field: "observed_at"}
	}
	if snapshot.DomainDNSName == "" {
		return &ValidationError{Code: "Required", Field: "domain_dns_name"}
	}
	if snapshot.ServerDNSName == "" {
		return &ValidationError{Code: "Required", Field: "server_dns_name"}
	}
	if snapshot.NamingContext == "" {
		return &ValidationError{Code: "Required", Field: "naming_context"}
	}
	if err := validateDirectorySortedUniqueStrings(snapshot.RequestedSIDs, "requested_sids", true); err != nil {
		return err
	}
	if err := validateDirectorySortedUniqueStrings(snapshot.NotFoundSIDs, "not_found_sids", false); err != nil {
		return err
	}

	requested := make(map[string]struct{}, len(snapshot.RequestedSIDs))
	for _, sid := range snapshot.RequestedSIDs {
		requested[sid] = struct{}{}
	}

	previousSID := ""
	found := make(map[string]struct{}, len(snapshot.Principals))
	for i, principal := range snapshot.Principals {
		field := fmt.Sprintf("principals[%d]", i)
		if principal.SID == "" {
			return &ValidationError{Code: "Required", Field: field + ".sid"}
		}
		if previousSID != "" && principal.SID <= previousSID {
			return &ValidationError{Code: "UnsortedCollection", Field: "principals"}
		}
		previousSID = principal.SID
		if _, ok := requested[principal.SID]; !ok {
			return &ValidationError{Code: "Conflict", Field: field + ".sid"}
		}
		if _, exists := found[principal.SID]; exists {
			return &ValidationError{Code: "DuplicateValue", Field: field + ".sid"}
		}
		found[principal.SID] = struct{}{}

		rawSID, err := base64.RawURLEncoding.DecodeString(principal.SIDRawBase64URL)
		if err != nil {
			return &ValidationError{Code: "InvalidBase64URL", Field: field + ".sid_raw_base64url"}
		}
		parsedSID, used, err := sidFromBytes(rawSID)
		if err != nil || used != len(rawSID) || parsedSID != principal.SID {
			return &ValidationError{Code: "Conflict", Field: field + ".sid_raw_base64url"}
		}

		rawGUID, err := base64.RawURLEncoding.DecodeString(principal.ObjectGUIDRawBase64URL)
		if err != nil || len(rawGUID) != 16 {
			return &ValidationError{Code: "InvalidGUID", Field: field + ".object_guid_raw_base64url"}
		}
		if formatWindowsGUID(rawGUID) != principal.ObjectGUID {
			return &ValidationError{Code: "Conflict", Field: field + ".object_guid"}
		}
		if principal.DistinguishedName == "" {
			return &ValidationError{Code: "Required", Field: field + ".distinguished_name"}
		}
		if len(principal.ObjectClasses) == 0 {
			return &ValidationError{Code: "Required", Field: field + ".object_classes"}
		}
		if principal.UserAccountControlRaw != "" {
			value, err := strconv.ParseUint(principal.UserAccountControlRaw, 10, 32)
			if err != nil {
				return &ValidationError{Code: "InvalidDecimal", Field: field + ".user_account_control_raw"}
			}
			if principal.AccountDisabled == nil {
				return &ValidationError{Code: "Required", Field: field + ".account_disabled"}
			}
			disabled := value&0x00000002 != 0
			if *principal.AccountDisabled != disabled {
				return &ValidationError{Code: "Conflict", Field: field + ".account_disabled"}
			}
		} else if principal.AccountDisabled != nil {
			return &ValidationError{Code: "Conflict", Field: field + ".account_disabled"}
		}
		if principal.PrimaryGroupIDRaw != "" {
			if _, err := strconv.ParseUint(principal.PrimaryGroupIDRaw, 10, 32); err != nil {
				return &ValidationError{Code: "InvalidDecimal", Field: field + ".primary_group_id_raw"}
			}
		}
	}

	for i, sid := range snapshot.NotFoundSIDs {
		if _, ok := requested[sid]; !ok {
			return &ValidationError{Code: "Conflict", Field: fmt.Sprintf("not_found_sids[%d]", i)}
		}
		if _, ok := found[sid]; ok {
			return &ValidationError{Code: "Conflict", Field: fmt.Sprintf("not_found_sids[%d]", i)}
		}
	}
	if len(found)+len(snapshot.NotFoundSIDs) != len(snapshot.RequestedSIDs) {
		return &ValidationError{Code: "Conflict", Field: "requested_sids"}
	}
	return nil
}

func validateDirectorySortedUniqueStrings(values []string, field string, requireNonEmpty bool) error {
	if requireNonEmpty && len(values) == 0 {
		return &ValidationError{Code: "Required", Field: field}
	}
	if !sort.StringsAreSorted(values) {
		return &ValidationError{Code: "UnsortedCollection", Field: field}
	}
	for i, value := range values {
		if value == "" {
			return &ValidationError{Code: "Required", Field: fmt.Sprintf("%s[%d]", field, i)}
		}
		if i > 0 && value == values[i-1] {
			return &ValidationError{Code: "DuplicateValue", Field: fmt.Sprintf("%s[%d]", field, i)}
		}
	}
	return nil
}
