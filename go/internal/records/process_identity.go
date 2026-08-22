// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ProcessIdentityObservation records the Windows identity and access-token facts
// for the running FI collector process. It describes the collector itself; it
// does not decide whether any user can access any file or share.
type ProcessIdentityObservation struct {
	ObservedAt       string                  `json:"observed_at"`
	CollectionMethod string                  `json:"collection_method"`
	Computer         ComputerIdentity        `json:"computer"`
	Token            ProcessTokenObservation `json:"token"`
}

// ComputerIdentity records the names Windows reports for the local computer.
type ComputerIdentity struct {
	NetBIOSName string `json:"netbios_name"`
	DNSHostName string `json:"dns_host_name,omitempty"`
	DNSDomain   string `json:"dns_domain,omitempty"`
	DNSFQDN     string `json:"dns_fqdn,omitempty"`
}

// ProcessTokenObservation records facts from the current process token.
type ProcessTokenObservation struct {
	User              TokenPrincipalObservation   `json:"user"`
	TokenTypeRaw      string                      `json:"token_type_raw"`
	TokenTypeName     string                      `json:"token_type_name"`
	ElevationTypeRaw  string                      `json:"elevation_type_raw"`
	ElevationTypeName string                      `json:"elevation_type_name"`
	Elevated          bool                        `json:"elevated"`
	Groups            []TokenGroupObservation     `json:"groups"`
	Privileges        []TokenPrivilegeObservation `json:"privileges"`
}

// TokenPrincipalObservation records a SID and, when Windows can resolve it,
// the corresponding account/domain name and SID_NAME_USE value.
type TokenPrincipalObservation struct {
	SID         string `json:"sid"`
	AccountName string `json:"account_name,omitempty"`
	DomainName  string `json:"domain_name,omitempty"`
	NameUseRaw  string `json:"name_use_raw,omitempty"`
	NameUseName string `json:"name_use_name,omitempty"`
}

// TokenGroupObservation records one group SID from TOKEN_GROUPS in source order.
// AttributesRaw is authoritative; the booleans are direct interpretations of
// documented group-attribute bits.
type TokenGroupObservation struct {
	Index            string                    `json:"index"`
	Principal        TokenPrincipalObservation `json:"principal"`
	AttributesRaw    string                    `json:"attributes_raw"`
	Mandatory        bool                      `json:"mandatory"`
	EnabledByDefault bool                      `json:"enabled_by_default"`
	Enabled          bool                      `json:"enabled"`
	Owner            bool                      `json:"owner"`
	DenyOnly         bool                      `json:"deny_only"`
	Integrity        bool                      `json:"integrity"`
	IntegrityEnabled bool                      `json:"integrity_enabled"`
	LogonID          bool                      `json:"logon_id"`
	Resource         bool                      `json:"resource"`
}

// TokenPrivilegeObservation records one privilege from TOKEN_PRIVILEGES in
// source order. The LUID is preserved as its two native 32-bit components.
type TokenPrivilegeObservation struct {
	Index            string `json:"index"`
	LUIDLow          string `json:"luid_low"`
	LUIDHigh         string `json:"luid_high"`
	Name             string `json:"name,omitempty"`
	AttributesRaw    string `json:"attributes_raw"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Enabled          bool   `json:"enabled"`
	Removed          bool   `json:"removed"`
	UsedForAccess    bool   `json:"used_for_access"`
}

const ProcessIdentityCollectionMethod = "WindowsProcessToken"

// ValidateProcessIdentityObservation validates the source-record shape without
// recomputing Windows token semantics.
func ValidateProcessIdentityObservation(observation ProcessIdentityObservation) error {
	if observation.CollectionMethod != ProcessIdentityCollectionMethod {
		return &ValidationError{Code: "UnsupportedValue", Field: "collection_method"}
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000000Z", observation.ObservedAt); err != nil {
		return &ValidationError{Code: "InvalidTimestamp", Field: "observed_at"}
	}
	if observation.Computer.NetBIOSName == "" {
		return &ValidationError{Code: "Required", Field: "computer.netbios_name"}
	}
	if err := validateTokenPrincipal(observation.Token.User, "token.user"); err != nil {
		return err
	}

	switch observation.Token.TokenTypeName {
	case "Primary", "Impersonation":
	default:
		return &ValidationError{Code: "UnsupportedValue", Field: "token.token_type_name"}
	}
	if observation.Token.TokenTypeRaw != "1" && observation.Token.TokenTypeRaw != "2" {
		return &ValidationError{Code: "UnsupportedValue", Field: "token.token_type_raw"}
	}

	switch observation.Token.ElevationTypeName {
	case "Default", "Full", "Limited":
	default:
		return &ValidationError{Code: "UnsupportedValue", Field: "token.elevation_type_name"}
	}
	if observation.Token.ElevationTypeRaw != "1" && observation.Token.ElevationTypeRaw != "2" && observation.Token.ElevationTypeRaw != "3" {
		return &ValidationError{Code: "UnsupportedValue", Field: "token.elevation_type_raw"}
	}

	for i, group := range observation.Token.Groups {
		if group.Index != strconv.Itoa(i) {
			return &ValidationError{Code: "Conflict", Field: fmt.Sprintf("token.groups[%d].index", i)}
		}
		if err := validateTokenPrincipal(group.Principal, fmt.Sprintf("token.groups[%d].principal", i)); err != nil {
			return err
		}
		if _, err := strconv.ParseUint(group.AttributesRaw, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: fmt.Sprintf("token.groups[%d].attributes_raw", i)}
		}
	}

	for i, privilege := range observation.Token.Privileges {
		if privilege.Index != strconv.Itoa(i) {
			return &ValidationError{Code: "Conflict", Field: fmt.Sprintf("token.privileges[%d].index", i)}
		}
		if _, err := strconv.ParseUint(privilege.LUIDLow, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: fmt.Sprintf("token.privileges[%d].luid_low", i)}
		}
		if _, err := strconv.ParseInt(privilege.LUIDHigh, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: fmt.Sprintf("token.privileges[%d].luid_high", i)}
		}
		if _, err := strconv.ParseUint(privilege.AttributesRaw, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: fmt.Sprintf("token.privileges[%d].attributes_raw", i)}
		}
	}
	return nil
}

func validateTokenPrincipal(principal TokenPrincipalObservation, field string) error {
	if principal.SID == "" || !strings.HasPrefix(principal.SID, "S-") {
		return &ValidationError{Code: "InvalidSID", Field: field + ".sid"}
	}
	if principal.NameUseRaw == "" && principal.NameUseName != "" {
		return &ValidationError{Code: "Conflict", Field: field + ".name_use"}
	}
	if principal.NameUseRaw != "" {
		if _, err := strconv.ParseUint(principal.NameUseRaw, 10, 32); err != nil {
			return &ValidationError{Code: "InvalidDecimal", Field: field + ".name_use_raw"}
		}
	}
	return nil
}
