// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"
)

type DesiredFIIdentities struct {
	CRLRefresher    DesiredFIIdentity
	CollectorSender DesiredFIIdentity
	ObjReader       DesiredFIIdentity
	USNReader       DesiredFIIdentity
}

type DesiredFIIdentity struct {
	Account        string
	Role           string
	SAMAccountName string
}

func DeriveDesiredFIIdentities(
	computer string,
	domainNetBIOS string,
) (DesiredFIIdentities, error) {
	computer = strings.TrimSpace(computer)
	domainNetBIOS = strings.TrimSpace(domainNetBIOS)

	if computer == "" || computer == notKnown {
		return DesiredFIIdentities{}, fmt.Errorf(
			"computer name is unavailable",
		)
	}
	if domainNetBIOS == "" || domainNetBIOS == notKnown {
		return DesiredFIIdentities{}, fmt.Errorf(
			"domain NetBIOS name is unavailable",
		)
	}

	token := desiredFIHostToken(
		computer,
		domainNetBIOS,
	)
	if token == "" {
		return DesiredFIIdentities{}, fmt.Errorf(
			"computer name %q does not produce a usable FI identity token",
			computer,
		)
	}

	collector, err := desiredFIIdentity(
		domainNetBIOS,
		"FICollector/FISender",
		"gFI-"+token+"$",
	)
	if err != nil {
		return DesiredFIIdentities{}, err
	}
	crlRefresher, err := desiredFIIdentity(
		domainNetBIOS,
		"FICRLRefresher",
		"gFI-CRL-"+token+"$",
	)
	if err != nil {
		return DesiredFIIdentities{}, err
	}
	usn, err := desiredFIIdentity(
		domainNetBIOS,
		"FIUSNReader",
		"gFI-USN-"+token+"$",
	)
	if err != nil {
		return DesiredFIIdentities{}, err
	}
	obj, err := desiredFIIdentity(
		domainNetBIOS,
		"FIObjReader",
		"gFI-OBJ-"+token+"$",
	)
	if err != nil {
		return DesiredFIIdentities{}, err
	}

	return DesiredFIIdentities{
		CRLRefresher:    crlRefresher,
		CollectorSender: collector,
		ObjReader:       obj,
		USNReader:       usn,
	}, nil
}

func desiredFIHostToken(
	computer string,
	domainNetBIOS string,
) string {
	computer = strings.ToUpper(
		strings.TrimSpace(computer),
	)
	domainNetBIOS = strings.ToUpper(
		strings.TrimSpace(domainNetBIOS),
	)

	prefix := domainNetBIOS + "-"
	if domainNetBIOS != "" &&
		strings.HasPrefix(computer, prefix) {
		computer = strings.TrimPrefix(
			computer,
			prefix,
		)
	}

	var builder strings.Builder
	for _, current := range computer {
		switch {
		case current >= 'A' && current <= 'Z':
			builder.WriteRune(current)
		case current >= '0' && current <= '9':
			builder.WriteRune(current)
		}
	}

	return builder.String()
}

func desiredFIIdentity(
	domainNetBIOS string,
	role string,
	sam string,
) (DesiredFIIdentity, error) {
	// sAMAccountName remains constrained to the legacy 20-character maximum.
	// Do not silently truncate because that can create identity collisions.
	if len(sam) > 20 {
		return DesiredFIIdentity{}, fmt.Errorf(
			"%s derived gMSA SAM name %q exceeds 20 characters; explicit operator naming is required",
			role,
			sam,
		)
	}

	return DesiredFIIdentity{
		Account:        domainNetBIOS + `\` + sam,
		Role:           role,
		SAMAccountName: sam,
	}, nil
}

func desiredFIIdentityList(
	identities DesiredFIIdentities,
) []DesiredFIIdentity {
	return []DesiredFIIdentity{
		identities.CollectorSender,
		identities.CRLRefresher,
		identities.USNReader,
		identities.ObjReader,
	}
}
