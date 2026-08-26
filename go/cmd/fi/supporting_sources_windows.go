// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/directory"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/localidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/smb"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/supportingstate"
)

const maxBaselineObservedSIDs = 262144

// supportingSourceContext contains the slower-changing source facts collected
// alongside a governed-root baseline. It is deliberately separate from NTFS
// traversal so the same source collectors can later be reused by a bounded
// supporting-source refresh operation without duplicating their collection
// logic.
type supportingSourceContext struct {
	CollectorIdentity   records.ProcessIdentityObservation
	SMBShareSnapshot    *records.SMBShareSnapshot
	SMBShareError       string
	LocalPrincipals     *records.LocalPrincipalSnapshot
	LocalPrincipalError string
	ObservedSIDs        *observedSIDSet
}

// directorySourceResult keeps directory-source success separate from an explicit
// source error. Directory failure is not allowed to erase otherwise usable
// baseline source facts.
type directorySourceResult struct {
	Snapshot *records.DirectoryPrincipalSnapshot
	Error    string
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

// collectSupportingSourceContext collects the existing baseline supporting
// sources using their established collectors. Collector/process identity is
// required because it identifies the source host/token and supplies the current
// domain context used by directory collection.
//
// SMB and local-identity source failures remain explicit source errors rather
// than causing the entire NTFS baseline to be discarded.
func collectSupportingSourceContext(ctx context.Context) (supportingSourceContext, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	result := supportingSourceContext{
		ObservedSIDs: newObservedSIDSet(),
	}

	identity, err := process.CurrentIdentity()
	if err != nil {
		return result, fmt.Errorf("collector identity: %w", err)
	}
	result.CollectorIdentity = identity
	addProcessIdentitySIDs(result.ObservedSIDs, identity)

	shareSnapshot, shareErr := smb.CollectLocalShares(ctx)
	if shareErr != nil {
		result.SMBShareError = shareErr.Error()
	} else {
		result.SMBShareSnapshot = &shareSnapshot
		addSMBShareSnapshotSIDs(result.ObservedSIDs, shareSnapshot)
	}

	localSnapshot, localErr := localidentity.CollectLocalPrincipals(
		ctx,
		identity.Computer.NetBIOSName,
	)
	if localErr != nil {
		result.LocalPrincipalError = localErr.Error()
	} else {
		result.LocalPrincipals = &localSnapshot
		addLocalPrincipalSIDs(result.ObservedSIDs, localSnapshot)
	}

	return result, nil
}

// collectDirectorySource resolves only current-domain SIDs that FI has already
// observed from collector identity, SMB security, local identity, and NTFS
// security. It does not turn the collector into a general AD inventory.
//
// The caller may add additional observed SIDs before calling this function. The
// baseline does that while NTFS observations stream.
func collectDirectorySource(
	ctx context.Context,
	identity records.ProcessIdentityObservation,
	observedSIDs *observedSIDSet,
) directorySourceResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if observedSIDs == nil {
		return directorySourceResult{Error: "DirectoryObservedSIDsUnavailable"}
	}

	directorySIDs := currentDomainObservedSIDs(identity, observedSIDs.values)

	switch {
	case observedSIDs.overflow:
		return directorySourceResult{
			Error: fmt.Sprintf(
				"DirectorySIDCandidateLimitExceeded:%d",
				maxBaselineObservedSIDs,
			),
		}
	case identity.Computer.DNSDomain == "":
		return directorySourceResult{Error: "DirectoryDomainDNSNameUnavailable"}
	case len(directorySIDs) == 0:
		return directorySourceResult{Error: "DirectoryDomainSIDsUnavailable"}
	}

	snapshot, err := directory.CollectCurrentDomainPrincipals(
		ctx,
		identity.Computer.DNSDomain,
		directorySIDs,
	)
	if err != nil {
		return directorySourceResult{Error: err.Error()}
	}

	return directorySourceResult{Snapshot: &snapshot}
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
// baseline itself expands the candidate set from share and NTFS security.
func currentDomainRelatedSIDs(
	identity records.ProcessIdentityObservation,
	local records.LocalPrincipalSnapshot,
	includeLocal bool,
) []string {
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
func currentDomainObservedSIDs(
	identity records.ProcessIdentityObservation,
	observed map[string]struct{},
) []string {
	if identity.Token.User.DomainName == "" ||
		strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) {
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
	if len(parts) != 8 ||
		parts[0] != "S" ||
		parts[1] != "1" ||
		parts[2] != "5" ||
		parts[3] != "21" {
		return "", false
	}
	return strings.Join(parts[:7], "-"), true
}

// addDirectoryPrincipalSIDs retains every domain SID returned by the bounded
// directory lookup. These are still source principals/direct-membership facts;
// FI does not calculate transitive membership here.
func addDirectoryPrincipalSIDs(
	set *observedSIDSet,
	snapshot records.DirectoryPrincipalSnapshot,
) {
	for _, sid := range snapshot.RequestedSIDs {
		set.add(sid)
	}
	for _, principal := range snapshot.Principals {
		set.add(principal.SID)
	}
	for _, membership := range snapshot.Memberships {
		set.add(membership.MemberSID)
		set.add(membership.GroupSID)
	}
	for _, sid := range snapshot.NotFoundSIDs {
		set.add(sid)
	}
}

// saveSupportingSIDState persists the monotonic set of current-domain SIDs that
// have become relevant to governed history on this host.
//
// The source observations themselves remain in FI spool/history. This file is
// only operational state used to bound later AD refreshes.
func saveSupportingSIDState(
	identity records.ProcessIdentityObservation,
	observedSIDs *observedSIDSet,
) (string, int, error) {
	if observedSIDs == nil {
		return "", 0, errors.New("supporting SID state requires observed SID set")
	}
	if observedSIDs.overflow {
		return "", 0, fmt.Errorf(
			"supporting SID state candidate limit exceeded: %d",
			maxBaselineObservedSIDs,
		)
	}

	domainPrefix, ok := accountDomainSIDPrefix(identity.Token.User.SID)
	if !ok ||
		identity.Token.User.DomainName == "" ||
		strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) ||
		identity.Computer.DNSDomain == "" {
		return "", 0, nil
	}

	domainSIDs := currentDomainObservedSIDs(identity, observedSIDs.values)

	statePath, err := supportingstate.DefaultPath()
	if err != nil {
		return "", 0, err
	}

	current, err := supportingstate.Load(statePath)
	switch {
	case err == nil:
		if !strings.EqualFold(
			current.ComputerNetBIOSName,
			identity.Computer.NetBIOSName,
		) {
			return statePath, 0, errors.New(
				"supporting SID state computer identity does not match current collector",
			)
		}
		if !strings.EqualFold(
			current.DomainDNSName,
			identity.Computer.DNSDomain,
		) || current.DomainSIDPrefix != domainPrefix {
			return statePath, 0, errors.New(
				"supporting SID state domain identity does not match current collector",
			)
		}

	case errors.Is(err, os.ErrNotExist):
		current, err = supportingstate.New(
			identity.Computer.NetBIOSName,
			identity.Computer.DNSFQDN,
			identity.Computer.DNSDomain,
			domainPrefix,
			nil,
		)
		if err != nil {
			return statePath, 0, err
		}

	default:
		return statePath, 0, err
	}

	merged, err := supportingstate.Merge(statePath, current, domainSIDs)
	if err != nil {
		return statePath, 0, err
	}
	return statePath, len(merged.RelevantSIDs), nil
}
