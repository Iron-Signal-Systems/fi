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

const (
	maxBaselineObservedSIDs = 262144
	directorySIDBatchSize   = 16384
)

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

// directorySourceResult keeps each bounded directory read as its own source
// snapshot. FI does not fabricate one synthetic LDAP observation by merging
// snapshots that may have different source times or directory-server facts.
//
// Error can coexist with completed Snapshots. That preserves successfully
// collected source facts when a later bounded directory read fails.
type directorySourceResult struct {
	Snapshots []records.DirectoryPrincipalSnapshot
	Error     string
}

type directoryPrincipalCollector func(
	context.Context,
	string,
	[]string,
) (records.DirectoryPrincipalSnapshot, error)

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
// One LDAP source call remains bounded to directorySIDBatchSize seed SIDs. A
// larger FI relevant-SID set is processed as multiple independent snapshots so
// the collector never silently truncates relevant SIDs and never invents one
// combined source observation from several LDAP reads.
func collectDirectorySource(
	ctx context.Context,
	identity records.ProcessIdentityObservation,
	observedSIDs *observedSIDSet,
) directorySourceResult {
	return collectDirectorySourceWithCollector(
		ctx,
		identity,
		observedSIDs,
		directory.CollectCurrentDomainPrincipals,
	)
}

func collectDirectorySourceWithCollector(
	ctx context.Context,
	identity records.ProcessIdentityObservation,
	observedSIDs *observedSIDSet,
	collector directoryPrincipalCollector,
) directorySourceResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := directorySourceResult{
		Snapshots: []records.DirectoryPrincipalSnapshot{},
	}
	if observedSIDs == nil {
		result.Error = "DirectoryObservedSIDsUnavailable"
		return result
	}
	if collector == nil {
		result.Error = "DirectoryCollectorUnavailable"
		return result
	}

	directorySIDs := currentDomainObservedSIDs(identity, observedSIDs.values)

	switch {
	case observedSIDs.overflow:
		result.Error = fmt.Sprintf(
			"DirectorySIDCandidateLimitExceeded:%d",
			maxBaselineObservedSIDs,
		)
		return result
	case identity.Computer.DNSDomain == "":
		result.Error = "DirectoryDomainDNSNameUnavailable"
		return result
	case len(directorySIDs) == 0:
		result.Error = "DirectoryDomainSIDsUnavailable"
		return result
	}

	for start := 0; start < len(directorySIDs); start += directorySIDBatchSize {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			return result
		}

		end := start + directorySIDBatchSize
		if end > len(directorySIDs) {
			end = len(directorySIDs)
		}

		snapshot, err := collector(
			ctx,
			identity.Computer.DNSDomain,
			directorySIDs[start:end],
		)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Snapshots = append(result.Snapshots, snapshot)
	}

	return result
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

// addDirectoryPrincipalSIDs retains every domain SID returned by one bounded
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

// loadSupportingSIDState adds every previously relevant current-domain SID to
// the supplied bounded set. A supporting-source refresh requires this state:
// refreshing only the SIDs visible in the current token/share/local snapshot
// could silently forget identities that remain historically relevant.
func loadSupportingSIDState(
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

	statePath, err := supportingstate.DefaultPath()
	if err != nil {
		return "", 0, err
	}
	current, err := supportingstate.Load(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return statePath, 0, fmt.Errorf(
			"supporting SID state is unavailable at %s; complete a durable baseline before supporting-source refresh",
			statePath,
		)
	}
	if err != nil {
		return statePath, 0, err
	}
	if err := validateSupportingSIDStateIdentity(identity, current); err != nil {
		return statePath, 0, err
	}

	for _, sid := range current.RelevantSIDs {
		observedSIDs.add(sid)
	}
	if observedSIDs.overflow {
		return statePath, 0, fmt.Errorf(
			"supporting SID state candidate limit exceeded: %d",
			maxBaselineObservedSIDs,
		)
	}
	return statePath, len(current.RelevantSIDs), nil
}

func validateSupportingSIDStateIdentity(
	identity records.ProcessIdentityObservation,
	current supportingstate.State,
) error {
	domainPrefix, ok := accountDomainSIDPrefix(identity.Token.User.SID)
	if !ok ||
		identity.Token.User.DomainName == "" ||
		strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) ||
		identity.Computer.DNSDomain == "" {
		return errors.New("current collector token does not identify an AD domain")
	}
	if !strings.EqualFold(
		current.ComputerNetBIOSName,
		identity.Computer.NetBIOSName,
	) {
		return errors.New(
			"supporting SID state computer identity does not match current collector",
		)
	}
	if !strings.EqualFold(
		current.DomainDNSName,
		identity.Computer.DNSDomain,
	) || current.DomainSIDPrefix != domainPrefix {
		return errors.New(
			"supporting SID state domain identity does not match current collector",
		)
	}
	return nil
}

type supportingSIDStateMergeResult struct {
	Path        string
	CountBefore int
	CountAfter  int
	Updated     bool
}

// mergeSupportingSIDState persists only newly observed current-domain SIDs.
// Existing state is not rewritten when the incoming SIDs are already known.
// This matters for continuous USN collection because FI should not generate a
// supporting-state write on every otherwise unrelated journal catch-up.
func mergeSupportingSIDState(
	identity records.ProcessIdentityObservation,
	observedSIDs *observedSIDSet,
) (supportingSIDStateMergeResult, error) {
	if observedSIDs == nil {
		return supportingSIDStateMergeResult{},
			errors.New("supporting SID state requires observed SID set")
	}
	if observedSIDs.overflow {
		return supportingSIDStateMergeResult{}, fmt.Errorf(
			"supporting SID state candidate limit exceeded: %d",
			maxBaselineObservedSIDs,
		)
	}

	domainPrefix, ok := accountDomainSIDPrefix(identity.Token.User.SID)
	if !ok ||
		identity.Token.User.DomainName == "" ||
		strings.EqualFold(identity.Token.User.DomainName, identity.Computer.NetBIOSName) ||
		identity.Computer.DNSDomain == "" {
		return supportingSIDStateMergeResult{}, nil
	}

	domainSIDs := currentDomainObservedSIDs(identity, observedSIDs.values)
	if len(domainSIDs) == 0 {
		return supportingSIDStateMergeResult{}, nil
	}

	statePath, err := supportingstate.DefaultPath()
	if err != nil {
		return supportingSIDStateMergeResult{}, err
	}

	current, err := supportingstate.Load(statePath)
	stateExists := err == nil
	switch {
	case err == nil:
		if err := validateSupportingSIDStateIdentity(identity, current); err != nil {
			return supportingSIDStateMergeResult{Path: statePath}, err
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
			return supportingSIDStateMergeResult{Path: statePath}, err
		}

	default:
		return supportingSIDStateMergeResult{Path: statePath}, err
	}

	result := supportingSIDStateMergeResult{
		Path:        statePath,
		CountBefore: len(current.RelevantSIDs),
		CountAfter:  len(current.RelevantSIDs),
	}

	known := make(map[string]struct{}, len(current.RelevantSIDs))
	for _, sid := range current.RelevantSIDs {
		known[sid] = struct{}{}
	}

	hasNewSID := !stateExists
	if stateExists {
		for _, sid := range domainSIDs {
			if _, exists := known[sid]; !exists {
				hasNewSID = true
				break
			}
		}
	}
	if !hasNewSID {
		return result, nil
	}

	merged, err := supportingstate.Merge(statePath, current, domainSIDs)
	if err != nil {
		return result, err
	}
	result.CountAfter = len(merged.RelevantSIDs)
	result.Updated = true
	return result, nil
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
		if err := validateSupportingSIDStateIdentity(identity, current); err != nil {
			return statePath, 0, err
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
