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

	maxBaselineObservedSIDs = 262144
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

type observedSIDSet struct {
	values   map[string]struct{}
	overflow bool
}

func newObservedSIDSet() *observedSIDSet {
	return &observedSIDSet{values: make(map[string]struct{})}
}

func (set *observedSIDSet) add(sid string) {
	if set == nil || sid == "" {
		return
	}
	if _, exists := set.values[sid]; exists {
		return
	}
	if len(set.values) >= maxBaselineObservedSIDs {
		set.overflow = true
		return
	}
	set.values[sid] = struct{}{}
}

func runBaselineRoot(governedRoot string) {
	if err := writeBaselineRoot(context.Background(), os.Stdout, governedRoot); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// writeBaselineRoot records collector identity, local SMB share state, local
// principals/direct local-group membership, and the governed NTFS baseline.
// While those source facts stream, FI gathers the unique SIDs it actually saw.
// After the NTFS walk completes, those observed current-domain SIDs seed one AD
// snapshot containing principals plus direct AD membership edges.
//
// The NTFS observations continue to stream and are never retained as one giant
// in-memory baseline. Only the bounded unique SID set is retained for the later
// directory lookup.
//
// Process identity is required. SMB, local-identity, and directory collection
// failures are emitted explicitly and do not discard an otherwise valid NTFS
// baseline.
func writeBaselineRoot(ctx context.Context, writer io.Writer, governedRoot string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	encoder := json.NewEncoder(writer)
	observedSIDs := newObservedSIDSet()

	identity, err := process.CurrentIdentity()
	if err != nil {
		return fmt.Errorf("collector identity: %w", err)
	}
	addProcessIdentitySIDs(observedSIDs, identity)
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
		addSMBShareSnapshotSIDs(observedSIDs, shareSnapshot)
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
		addLocalPrincipalSIDs(observedSIDs, localSnapshot)
	}
	if err := encoder.Encode(localEvent); err != nil {
		return fmt.Errorf("encode local principal snapshot: %w", err)
	}

	walkErr := ntfs.WalkGovernedRoot(
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
				addNTFSObservationSIDs(observedSIDs, observation)
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
	if walkErr != nil {
		return walkErr
	}

	directoryEvent := baselineEvent{Kind: baselineKindDirectoryPrincipals}
	directorySIDs := currentDomainObservedSIDs(identity, observedSIDs.values)
	switch {
	case observedSIDs.overflow:
		directoryEvent.Error = fmt.Sprintf("DirectorySIDCandidateLimitExceeded:%d", maxBaselineObservedSIDs)
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

	return nil
}

func addProcessIdentitySIDs(set *observedSIDSet, identity records.ProcessIdentityObservation) {
	set.add(identity.Token.User.SID)
	for _, group := range identity.Token.Groups {
		set.add(group.Principal.SID)
	}
}

func addLocalPrincipalSIDs(set *observedSIDSet, snapshot records.LocalPrincipalSnapshot) {
	for _, user := range snapshot.Users {
		set.add(user.SID)
	}
	for _, group := range snapshot.Groups {
		set.add(group.SID)
	}
	for _, membership := range snapshot.Memberships {
		set.add(membership.GroupSID)
		set.add(membership.MemberSID)
	}
}

func addSMBShareSnapshotSIDs(set *observedSIDSet, snapshot records.SMBShareSnapshot) {
	for _, share := range snapshot.Shares {
		addSecurityObservationSIDs(set, share.Security)
	}
}

func addNTFSObservationSIDs(set *observedSIDSet, observation ntfs.Observation) {
	addSecurityObservationSIDs(set, observation.Security)
	addSACLObservationSIDs(set, observation.SACL)
}

func addSecurityObservationSIDs(set *observedSIDSet, security records.SecurityObservation) {
	set.add(security.OwnerSID)
	set.add(security.PrimaryGroupSID)
	for _, ace := range security.DACL.ACEs {
		set.add(ace.SID)
	}
}

func addSACLObservationSIDs(set *observedSIDSet, sacl records.SACLObservation) {
	for _, ace := range sacl.ACL.ACEs {
		set.add(ace.SID)
	}
}

// currentDomainTokenSIDs keeps the token-only selector used by existing tests
// and callers.
func currentDomainTokenSIDs(identity records.ProcessIdentityObservation) []string {
	set := newObservedSIDSet()
	addProcessIdentitySIDs(set, identity)
	return currentDomainObservedSIDs(identity, set.values)
}

// currentDomainRelatedSIDs keeps the earlier token/local selector while the
// baseline itself now expands the candidate set from share and NTFS security.
func currentDomainRelatedSIDs(identity records.ProcessIdentityObservation, local records.LocalPrincipalSnapshot, includeLocal bool) []string {
	set := newObservedSIDSet()
	addProcessIdentitySIDs(set, identity)
	if includeLocal {
		addLocalPrincipalSIDs(set, local)
	}
	return currentDomainObservedSIDs(identity, set.values)
}

// currentDomainObservedSIDs filters an observed SID set to the collector
// account's AD domain SID namespace. Well-known, local-machine, logon-session,
// integrity, service, and foreign-domain SIDs remain preserved in their source
// records but are not falsely sent to the current-domain LDAP collector.
func currentDomainObservedSIDs(identity records.ProcessIdentityObservation, observed map[string]struct{}) []string {
	if identity.Token.User.DomainName == "" || strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) {
		return []string{}
	}
	prefix, ok := accountDomainSIDPrefix(identity.Token.User.SID)
	if !ok {
		return []string{}
	}

	result := make([]string, 0)
	for sid := range observed {
		if sid == prefix || strings.HasPrefix(sid, prefix+"-") {
			result = append(result, sid)
		}
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
