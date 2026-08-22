// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/directory"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/localidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/smb"
)

const (
	baselineKindCollectorIdentity   = "CollectorIdentity"
	baselineKindSMBShareSnapshot    = "SMBShareSnapshot"
	baselineKindLocalPrincipals     = "LocalPrincipalSnapshot"
	baselineKindDirectoryPrincipals = "DirectoryPrincipalSnapshot"
	baselineKindNTFSObservation     = "NTFSObservation"
)

// baselineEvent is the JSON Lines envelope used by the current baseline-root
// command. Each line is independently decodable so a large governed root can
// stream without retaining the full baseline in memory.
type baselineEvent struct {
	Kind                 string                              `json:"kind"`
	CollectorIdentity    *records.ProcessIdentityObservation `json:"collector_identity,omitempty"`
	SMBShareSnapshot     *records.SMBShareSnapshot           `json:"smb_share_snapshot,omitempty"`
	LocalPrincipals      *records.LocalPrincipalSnapshot     `json:"local_principal_snapshot,omitempty"`
	DirectoryPrincipals  *records.DirectoryPrincipalSnapshot `json:"directory_principal_snapshot,omitempty"`
	Observation          *ntfs.Observation                   `json:"observation,omitempty"`
	PathDisplay          string                              `json:"path_display,omitempty"`
	PathUTF16LEBase64URL string                              `json:"path_utf16le_base64url,omitempty"`
	Error                string                              `json:"error,omitempty"`
}

func runBaselineRoot(governedRoot string) {
	if err := writeBaselineRoot(context.Background(), os.Stdout, governedRoot); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// writeBaselineRoot collects the process identity once, records the local SMB
// share state once, records local principals and direct local-group membership,
// resolves related current-domain principals once, then walks the governed NTFS
// root in the same FI process.
//
// Process identity is required. SMB and directory collection are useful access
// context but are not allowed to discard a valid NTFS baseline; their failures
// are emitted explicitly and the NTFS walk continues.
func writeBaselineRoot(ctx context.Context, writer io.Writer, governedRoot string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	encoder := json.NewEncoder(writer)

	identity, err := process.CurrentIdentity()
	if err != nil {
		return fmt.Errorf("collector identity: %w", err)
	}
	if err := encoder.Encode(baselineEvent{
		Kind:              baselineKindCollectorIdentity,
		CollectorIdentity: &identity,
	}); err != nil {
		return fmt.Errorf("encode collector identity: %w", err)
	}

	shareSnapshot, shareErr := smb.CollectLocalShares(ctx)
	shareEvent := baselineEvent{Kind: baselineKindSMBShareSnapshot}
	if shareErr != nil {
		shareEvent.Error = shareErr.Error()
	} else {
		shareEvent.SMBShareSnapshot = &shareSnapshot
	}
	if err := encoder.Encode(shareEvent); err != nil {
		return fmt.Errorf("encode SMB share snapshot: %w", err)
	}

	localEvent := baselineEvent{Kind: baselineKindLocalPrincipals}
	var localSnapshot records.LocalPrincipalSnapshot
	localSnapshot, localErr := localidentity.CollectLocalPrincipals(ctx, identity.Computer.NetBIOSName)
	if localErr != nil {
		localEvent.Error = localErr.Error()
	} else {
		localEvent.LocalPrincipals = &localSnapshot
	}
	if err := encoder.Encode(localEvent); err != nil {
		return fmt.Errorf("encode local principal snapshot: %w", err)
	}

	directoryEvent := baselineEvent{Kind: baselineKindDirectoryPrincipals}
	directorySIDs := currentDomainRelatedSIDs(identity, localSnapshot, localErr == nil)
	switch {
	case identity.Computer.DNSDomain == "":
		directoryEvent.Error = "DirectoryDomainDNSNameUnavailable"
	case len(directorySIDs) == 0:
		directoryEvent.Error = "DirectoryDomainSIDsUnavailable"
	default:
		directorySnapshot, directoryErr := directory.CollectCurrentDomainPrincipals(ctx, identity.Computer.DNSDomain, directorySIDs)
		if directoryErr != nil {
			directoryEvent.Error = directoryErr.Error()
		} else {
			directoryEvent.DirectoryPrincipals = &directorySnapshot
		}
	}
	if err := encoder.Encode(directoryEvent); err != nil {
		return fmt.Errorf("encode directory principal snapshot: %w", err)
	}

	return ntfs.WalkGovernedRoot(
		ctx,
		"manual-test",
		governedRoot,
		func(path string, observation ntfs.Observation, objectErr error) error {
			exactPath, err := pathUTF16LEBase64URL(path)
			if err != nil {
				return fmt.Errorf("encode exact path: %w", err)
			}

			event := baselineEvent{
				Kind:                 baselineKindNTFSObservation,
				PathDisplay:          path,
				PathUTF16LEBase64URL: exactPath,
			}
			if observation.ObservedAt != "" {
				event.Observation = &observation
			}
			if objectErr != nil {
				event.Error = objectErr.Error()
			}
			if err := encoder.Encode(event); err != nil {
				return fmt.Errorf("encode NTFS observation: %w", err)
			}
			return nil
		},
	)
}

// currentDomainTokenSIDs selects only principals in the collector user's AD
// domain SID namespace. Well-known, local-machine, logon-session, integrity,
// and other non-domain SIDs remain in the token record but are not sent to the
// current-domain LDAP lookup.
// currentDomainTokenSIDs keeps the token-only selector used by the
// Directory Principal 1A tests and callers. Local Principal 1A expands the
// baseline lookup through currentDomainRelatedSIDs below.
func currentDomainTokenSIDs(identity records.ProcessIdentityObservation) []string {
	return currentDomainRelatedSIDs(identity, records.LocalPrincipalSnapshot{}, false)
}

func currentDomainRelatedSIDs(identity records.ProcessIdentityObservation, local records.LocalPrincipalSnapshot, includeLocal bool) []string {
	if identity.Token.User.DomainName == "" || strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) {
		return []string{}
	}
	prefix, ok := accountDomainSIDPrefix(identity.Token.User.SID)
	if !ok {
		return []string{}
	}

	set := map[string]struct{}{}
	add := func(sid string) {
		if sid == prefix || strings.HasPrefix(sid, prefix+"-") {
			set[sid] = struct{}{}
		}
	}
	add(identity.Token.User.SID)
	for _, group := range identity.Token.Groups {
		add(group.Principal.SID)
	}
	if includeLocal {
		for _, membership := range local.Memberships {
			add(membership.MemberSID)
		}
	}

	result := make([]string, 0, len(set))
	for sid := range set {
		result = append(result, sid)
	}
	sort.Strings(result)
	return result
}

func accountDomainSIDPrefix(sid string) (string, bool) {
	parts := strings.Split(sid, "-")
	if len(parts) != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return "", false
	}
	return strings.Join(parts[:7], "-"), true
}
