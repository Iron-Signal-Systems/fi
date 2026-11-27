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

const LocalPrincipalCollectionMethod = "WindowsLocalSAMNetAPI"

const (
	LocalMembershipComplete = "Complete"
	LocalMembershipPartial  = "Partial"
	LocalMembershipError    = "Error"
)

// LocalPrincipalSnapshot records local Windows users, local groups, and direct
// local-group membership relationships. It records source state only; it does
// not calculate effective access.
type LocalPrincipalSnapshot struct {
	ObservedAt       string                            `json:"observed_at"`
	CollectionMethod string                            `json:"collection_method"`
	ComputerName     string                            `json:"computer_name"`
	Users            []LocalUserObservation            `json:"users"`
	Groups           []LocalGroupObservation           `json:"groups"`
	Memberships      []LocalGroupMembershipObservation `json:"memberships"`
}

type LocalUserObservation struct {
	SID                      string `json:"sid"`
	SIDRawBase64URL          string `json:"sid_raw_base64url"`
	NameDisplay              string `json:"name_display"`
	NameUTF16LEBase64URL     string `json:"name_utf16le_base64url"`
	FullNameDisplay          string `json:"full_name_display,omitempty"`
	FullNameUTF16LEBase64URL string `json:"full_name_utf16le_base64url,omitempty"`
	CommentDisplay           string `json:"comment_display,omitempty"`
	CommentUTF16LEBase64URL  string `json:"comment_utf16le_base64url,omitempty"`
	FlagsRaw                 string `json:"flags_raw"`
	AccountDisabled          bool   `json:"account_disabled"`
	AccountLocked            bool   `json:"account_locked"`
}

type LocalGroupObservation struct {
	SID                     string `json:"sid"`
	SIDRawBase64URL         string `json:"sid_raw_base64url"`
	AccountDomain           string `json:"account_domain,omitempty"`
	NameDisplay             string `json:"name_display"`
	NameUTF16LEBase64URL    string `json:"name_utf16le_base64url"`
	CommentDisplay          string `json:"comment_display,omitempty"`
	CommentUTF16LEBase64URL string `json:"comment_utf16le_base64url,omitempty"`
	MembershipState         string `json:"membership_state"`
	MembershipReasonCode    string `json:"membership_reason_code,omitempty"`
	MembershipDetail        string `json:"membership_detail,omitempty"`
}

type LocalGroupMembershipObservation struct {
	GroupSID                            string `json:"group_sid"`
	MemberSID                           string `json:"member_sid"`
	MemberSIDRawBase64URL               string `json:"member_sid_raw_base64url"`
	MemberDomainAndNameDisplay          string `json:"member_domain_and_name_display,omitempty"`
	MemberDomainAndNameUTF16LEBase64URL string `json:"member_domain_and_name_utf16le_base64url,omitempty"`
	SIDNameUseRaw                       string `json:"sid_name_use_raw"`
	SIDNameUseName                      string `json:"sid_name_use_name"`
}

// ValidateLocalPrincipalSnapshot validates ordering, source-state semantics,
// and exact SID interpretation against the preserved raw SID bytes.
func ValidateLocalPrincipalSnapshot(snapshot LocalPrincipalSnapshot) error {
	if snapshot.CollectionMethod != LocalPrincipalCollectionMethod {
		return &ValidationError{Code: "UnsupportedValue", Field: "collection_method"}
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000000Z", snapshot.ObservedAt); err != nil {
		return &ValidationError{Code: "InvalidTimestamp", Field: "observed_at"}
	}
	if snapshot.ComputerName == "" {
		return &ValidationError{Code: "Required", Field: "computer_name"}
	}

	userSIDs := make(map[string]struct{}, len(snapshot.Users))
	previousSID := ""
	for i, user := range snapshot.Users {
		field := fmt.Sprintf("users[%d]", i)
		if user.SID == "" || user.NameDisplay == "" {
			return &ValidationError{Code: "Required", Field: field}
		}
		if previousSID != "" && user.SID <= previousSID {
			return &ValidationError{Code: "UnsortedCollection", Field: "users"}
		}
		previousSID = user.SID
		if _, exists := userSIDs[user.SID]; exists {
			return &ValidationError{Code: "DuplicateValue", Field: field + ".sid"}
		}
		userSIDs[user.SID] = struct{}{}
		if err := validateLocalSID(user.SID, user.SIDRawBase64URL, field); err != nil {
			return err
		}
		if _, err := strconv.ParseUint(user.FlagsRaw, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: field + ".flags_raw"}
		}
	}

	groupSIDs := make(map[string]struct{}, len(snapshot.Groups))
	previousSID = ""
	for i, group := range snapshot.Groups {
		field := fmt.Sprintf("groups[%d]", i)
		if group.SID == "" || group.NameDisplay == "" {
			return &ValidationError{Code: "Required", Field: field}
		}
		if previousSID != "" && group.SID <= previousSID {
			return &ValidationError{Code: "UnsortedCollection", Field: "groups"}
		}
		previousSID = group.SID
		if _, exists := groupSIDs[group.SID]; exists {
			return &ValidationError{Code: "DuplicateValue", Field: field + ".sid"}
		}
		groupSIDs[group.SID] = struct{}{}
		if err := validateLocalSID(group.SID, group.SIDRawBase64URL, field); err != nil {
			return err
		}
		switch group.MembershipState {
		case LocalMembershipComplete:
			if group.MembershipReasonCode != "" || group.MembershipDetail != "" {
				return &ValidationError{Code: "Conflict", Field: field + ".membership_state"}
			}
		case LocalMembershipPartial, LocalMembershipError:
			if group.MembershipReasonCode == "" {
				return &ValidationError{Code: "Required", Field: field + ".membership_reason_code"}
			}
		default:
			return &ValidationError{Code: "UnsupportedValue", Field: field + ".membership_state"}
		}
	}

	previousKey := ""
	seenMemberships := make(map[string]struct{}, len(snapshot.Memberships))
	for i, membership := range snapshot.Memberships {
		field := fmt.Sprintf("memberships[%d]", i)
		if membership.GroupSID == "" || membership.MemberSID == "" {
			return &ValidationError{Code: "Required", Field: field}
		}
		if _, ok := groupSIDs[membership.GroupSID]; !ok {
			return &ValidationError{Code: "Conflict", Field: field + ".group_sid"}
		}
		if err := validateLocalSID(membership.MemberSID, membership.MemberSIDRawBase64URL, field+".member"); err != nil {
			return err
		}
		if _, err := strconv.ParseUint(membership.SIDNameUseRaw, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: field + ".sid_name_use_raw"}
		}
		if membership.SIDNameUseName == "" {
			return &ValidationError{Code: "Required", Field: field + ".sid_name_use_name"}
		}
		key := membership.GroupSID + "\x00" + membership.MemberSID + "\x00" + membership.MemberDomainAndNameDisplay
		if previousKey != "" && key < previousKey {
			return &ValidationError{Code: "UnsortedCollection", Field: "memberships"}
		}
		previousKey = key
		if _, exists := seenMemberships[key]; exists {
			return &ValidationError{Code: "DuplicateValue", Field: field}
		}
		seenMemberships[key] = struct{}{}
	}
	return nil
}

func validateLocalSID(sid, rawText, field string) error {
	raw, err := base64.RawURLEncoding.DecodeString(rawText)
	if err != nil {
		return &ValidationError{Code: "InvalidBase64URL", Field: field + ".sid_raw_base64url"}
	}
	parsed, used, err := sidFromBytes(raw)
	if err != nil || used != len(raw) || parsed != sid {
		return &ValidationError{Code: "Conflict", Field: field + ".sid_raw_base64url"}
	}
	return nil
}

// SortLocalPrincipalSnapshot canonicalizes collection order without changing
// source meaning. It is exported so the Windows collector and tests share the
// exact deterministic order contract.
func SortLocalPrincipalSnapshot(snapshot *LocalPrincipalSnapshot) {
	sort.Slice(snapshot.Users, func(i, j int) bool { return snapshot.Users[i].SID < snapshot.Users[j].SID })
	sort.Slice(snapshot.Groups, func(i, j int) bool { return snapshot.Groups[i].SID < snapshot.Groups[j].SID })
	sort.Slice(snapshot.Memberships, func(i, j int) bool {
		a, b := snapshot.Memberships[i], snapshot.Memberships[j]
		if a.GroupSID != b.GroupSID {
			return a.GroupSID < b.GroupSID
		}
		if a.MemberSID != b.MemberSID {
			return a.MemberSID < b.MemberSID
		}
		return a.MemberDomainAndNameDisplay < b.MemberDomainAndNameDisplay
	})
}
