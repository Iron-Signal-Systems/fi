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

// DirectoryMembershipSource identifies the source fact that established one
// direct Active Directory membership relationship. FI records only the direct
// relationship; transitive/nested membership is derived later by PostgreSQL.
type DirectoryMembershipSource string

const DirectoryMembershipSourceGroupMember DirectoryMembershipSource = "GroupMemberAttribute"

// DirectoryPrincipalSnapshot records Active Directory principals and the
// direct membership relationships discovered from the requested SID set.
//
// RequestedSIDs are the source-side seed SIDs FI asked the current domain to
// resolve. Principals may also contain groups discovered while walking direct
// membership relationships from those seeds. Memberships never represent a
// transitive conclusion: every edge records the Windows/AD source fact that
// established that direct relationship.
//
// This record contains directory facts only. It does not calculate effective
// access to files or shares.
type DirectoryPrincipalSnapshot struct {
	ObservedAt       string                           `json:"observed_at"`
	CollectionMethod string                           `json:"collection_method"`
	DomainDNSName    string                           `json:"domain_dns_name"`
	ServerDNSName    string                           `json:"server_dns_name"`
	NamingContext    string                           `json:"naming_context"`
	RequestedSIDs    []string                         `json:"requested_sids"`
	Principals       []DirectoryPrincipalObservation  `json:"principals"`
	Memberships      []DirectoryMembershipObservation `json:"memberships"`
	NotFoundSIDs     []string                         `json:"not_found_sids"`
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

// DirectoryMembershipObservation records one direct membership edge.
//
// GroupMemberAttribute means the directory group directly listed MemberSID in
// its member attribute. FI does not emit a membership edge from primaryGroupID;
// that raw directory attribute remains on the principal for later backend
// derivation. Memberships never represent transitive membership.
type DirectoryMembershipObservation struct {
	MemberSID string                    `json:"member_sid"`
	GroupSID  string                    `json:"group_sid"`
	Source    DirectoryMembershipSource `json:"source"`
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
	for _, sid := range snapshot.RequestedSIDs {
		_, wasFound := found[sid]
		_, wasNotFound := sortedStringSetContains(snapshot.NotFoundSIDs, sid)
		if wasFound == wasNotFound {
			return &ValidationError{Code: "Conflict", Field: "requested_sids"}
		}
	}

	previousMembershipKey := ""
	seenMemberships := make(map[string]struct{}, len(snapshot.Memberships))
	for i, membership := range snapshot.Memberships {
		field := fmt.Sprintf("memberships[%d]", i)
		if membership.MemberSID == "" {
			return &ValidationError{Code: "Required", Field: field + ".member_sid"}
		}
		if membership.GroupSID == "" {
			return &ValidationError{Code: "Required", Field: field + ".group_sid"}
		}
		if _, ok := found[membership.MemberSID]; !ok {
			return &ValidationError{Code: "Conflict", Field: field + ".member_sid"}
		}
		if _, ok := found[membership.GroupSID]; !ok {
			return &ValidationError{Code: "Conflict", Field: field + ".group_sid"}
		}
		switch membership.Source {
		case DirectoryMembershipSourceGroupMember:
		default:
			return &ValidationError{Code: "UnsupportedValue", Field: field + ".source"}
		}

		key := directoryMembershipKey(membership)
		if previousMembershipKey != "" && key <= previousMembershipKey {
			return &ValidationError{Code: "UnsortedCollection", Field: "memberships"}
		}
		previousMembershipKey = key
		if _, exists := seenMemberships[key]; exists {
			return &ValidationError{Code: "DuplicateValue", Field: field}
		}
		seenMemberships[key] = struct{}{}
	}

	return nil
}

// SortDirectoryPrincipalSnapshot canonicalizes collection order without
// changing source meaning.
func SortDirectoryPrincipalSnapshot(snapshot *DirectoryPrincipalSnapshot) {
	sort.Strings(snapshot.RequestedSIDs)
	sort.Slice(snapshot.Principals, func(i, j int) bool {
		return snapshot.Principals[i].SID < snapshot.Principals[j].SID
	})
	sort.Slice(snapshot.Memberships, func(i, j int) bool {
		return directoryMembershipKey(snapshot.Memberships[i]) < directoryMembershipKey(snapshot.Memberships[j])
	})
	sort.Strings(snapshot.NotFoundSIDs)
}

func directoryMembershipKey(membership DirectoryMembershipObservation) string {
	return membership.MemberSID + "\x00" + membership.GroupSID + "\x00" + string(membership.Source)
}

func sortedStringSetContains(values []string, target string) (int, bool) {
	index := sort.SearchStrings(values, target)
	return index, index < len(values) && values[index] == target
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
