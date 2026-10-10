// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"io"
	"strings"
)

type Approval1ADCreatedGMSA struct {
	Account           string
	DistinguishedName string
	Role              string
	SAMAccountName    string
}

type Approval1ADTransactionResult struct {
	Created           []Approval1ADCreatedGMSA
	RollbackAttempted bool
	RollbackErrors    []string
}

type approval1ADGMSABackend interface {
	Create(
		report Report,
		identity DesiredFIIdentity,
	) (
		state ActiveDirectoryGMSAState,
		createdByTransaction bool,
		err error,
	)
	RollbackCreated(
		report Report,
		identity DesiredFIIdentity,
	) error
}

type ldapApproval1ADGMSABackend struct {
	session *ldapSession
}

func (backend *ldapApproval1ADGMSABackend) Create(
	report Report,
	identity DesiredFIIdentity,
) (
	ActiveDirectoryGMSAState,
	bool,
	error,
) {
	if backend == nil || backend.session == nil {
		return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
			"Approval 1 LDAP backend is unavailable",
		)
	}
	return createFIGroupManagedServiceAccountTracked(
		backend.session,
		report,
		identity,
	)
}

func (backend *ldapApproval1ADGMSABackend) RollbackCreated(
	report Report,
	identity DesiredFIIdentity,
) error {
	if backend == nil || backend.session == nil {
		return fmt.Errorf(
			"Approval 1 LDAP backend is unavailable",
		)
	}
	return deleteFIGroupManagedServiceAccountIfExact(
		backend.session,
		report,
		identity,
	)
}

// executeServer2016Approval1ADGMSATransaction is deliberately not wired to
// fi-install -apply in this milestone. It is the native AD transaction engine
// that a later two-boundary apply controller will invoke only after validating
// the exact Approval 1 digest and before rebuilding the Approval 2 plan.
func executeServer2016Approval1ADGMSATransaction(
	writer io.Writer,
	before Report,
	plan InstallPlan,
) (Approval1ADTransactionResult, error) {
	if writer == nil {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"Approval 1 output writer is required",
		)
	}

	identities, err := approval1ADCreateIdentities(
		before,
		plan,
	)
	if err != nil {
		return Approval1ADTransactionResult{}, err
	}
	if len(identities) == 0 {
		fmt.Fprintln(
			writer,
			"APPROVAL 1 AD: NO-OP - no FI gMSA CREATE actions are present",
		)
		return Approval1ADTransactionResult{}, nil
	}

	if strings.TrimSpace(before.AD.DomainController) == "" ||
		strings.EqualFold(
			strings.TrimSpace(before.AD.DomainController),
			notKnown,
		) {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"writable Active Directory domain controller is unavailable",
		)
	}

	session, err := openLDAPSession(
		before.AD.DomainController,
	)
	if err != nil {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"open signed/sealed Approval 1 LDAP session: %w",
			err,
		)
	}
	defer session.close()

	if err := revalidateApproval1ADPreconditions(
		session,
		before,
	); err != nil {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"Approval 1 AD pre-mutation revalidation failed: %w",
			err,
		)
	}

	return executeApproval1ADGMSATransactionWithBackend(
		writer,
		before,
		identities,
		&ldapApproval1ADGMSABackend{
			session: session,
		},
	)
}

func executeApproval1ADGMSATransactionWithBackend(
	writer io.Writer,
	before Report,
	identities []DesiredFIIdentity,
	backend approval1ADGMSABackend,
) (Approval1ADTransactionResult, error) {
	if writer == nil {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"Approval 1 output writer is required",
		)
	}
	if backend == nil {
		return Approval1ADTransactionResult{}, fmt.Errorf(
			"Approval 1 AD backend is required",
		)
	}

	result := Approval1ADTransactionResult{
		Created:        make([]Approval1ADCreatedGMSA, 0, len(identities)),
		RollbackErrors: make([]string, 0),
	}
	owned := make([]DesiredFIIdentity, 0, len(identities))

	rollback := func(cause error) (Approval1ADTransactionResult, error) {
		result.RollbackAttempted = len(owned) != 0
		for index := len(owned) - 1; index >= 0; index-- {
			identity := owned[index]
			fmt.Fprintf(
				writer,
				"ROLLBACK AD: delete transaction-created %s (%s)\n",
				identity.SAMAccountName,
				identity.Role,
			)
			if err := backend.RollbackCreated(
				before,
				identity,
			); err != nil {
				result.RollbackErrors = append(
					result.RollbackErrors,
					identity.SAMAccountName+": "+err.Error(),
				)
			}
		}
		if len(result.RollbackErrors) == 0 {
			return result, cause
		}
		return result, fmt.Errorf(
			"%w; Approval 1 AD rollback errors: %s",
			cause,
			strings.Join(
				result.RollbackErrors,
				"; ",
			),
		)
	}

	for _, identity := range identities {
		fmt.Fprintf(
			writer,
			"APPLY AD: create %s (%s) with one-host password-retrieval authorization\n",
			identity.SAMAccountName,
			identity.Role,
		)

		state, createdByTransaction, err := backend.Create(
			before,
			identity,
		)
		if createdByTransaction {
			owned = append(
				owned,
				identity,
			)
			result.Created = append(
				result.Created,
				Approval1ADCreatedGMSA{
					Account:           identity.Account,
					DistinguishedName: state.DistinguishedName,
					Role:              identity.Role,
					SAMAccountName:    identity.SAMAccountName,
				},
			)
		}
		if err != nil {
			return rollback(
				fmt.Errorf(
					"create and verify %s: %w",
					identity.SAMAccountName,
					err,
				),
			)
		}
		if !createdByTransaction {
			return rollback(
				fmt.Errorf(
					"create and verify %s returned success without transaction ownership",
					identity.SAMAccountName,
				),
			)
		}
	}

	fmt.Fprintf(
		writer,
		"APPROVAL 1 AD: PASS - created and verified %d FI gMSA object(s); retain rollback ownership until the outer Approval 1 controller completes authoritative rediscovery\n",
		len(result.Created),
	)
	return result, nil
}

func approval1ADCreateIdentities(
	before Report,
	plan InstallPlan,
) ([]DesiredFIIdentity, error) {
	if !installerMutationSupportedBuild(before.Host.BuildNumber) {
		return nil, fmt.Errorf(
			"Approval 1 AD mutation does not support Windows build %d",
			before.Host.BuildNumber,
		)
	}
	if plan.HasBlockers() {
		return nil, fmt.Errorf(
			"plan contains blockers",
		)
	}
	if plan.HasQuestions() {
		return nil, fmt.Errorf(
			"plan still contains unanswered questions",
		)
	}
	if !before.AD.ComputerObjectKnown ||
		strings.TrimSpace(before.AD.ComputerSID) == "" {
		return nil, fmt.Errorf(
			"Active Directory computer object/SID is not authoritative",
		)
	}
	if !before.AD.GMSADiscoveryKnown {
		return nil, fmt.Errorf(
			"gMSA discovery is not authoritative",
		)
	}
	if !before.AD.KDSRootKeyKnown {
		return nil, fmt.Errorf(
			"KDS root-key state is not authoritative",
		)
	}
	if before.AD.KDSRootKeyCount == 0 {
		return nil, fmt.Errorf(
			"KDS root-key creation is not enabled in this M20 slice",
		)
	}

	identityByTarget := make(map[string]DesiredFIIdentity)
	ordered := desiredFIIdentityList(
		plan.Identities,
	)
	for _, identity := range ordered {
		identityByTarget[strings.ToLower(identity.Account)] = identity
	}

	plannedCreate := make(map[string]bool)
	for _, action := range plan.Actions {
		if action.Authority != "AD" ||
			!planActionMutates(action.Action) {
			continue
		}
		if action.Action != planActionCreate {
			return nil, fmt.Errorf(
				"Approval 1 AD action is not a characterized gMSA CREATE: action=%s target=%s",
				action.Action,
				action.Target,
			)
		}

		identity, found := identityByTarget[strings.ToLower(
			strings.TrimSpace(action.Target),
		)]
		if !found {
			return nil, fmt.Errorf(
				"Approval 1 AD CREATE target %q is not a characterized FI gMSA identity",
				action.Target,
			)
		}
		if _, exists := findADGMSA(
			before.AD.GMSAs,
			identity.SAMAccountName,
		); exists {
			return nil, fmt.Errorf(
				"plan requests CREATE for %s but authoritative discovery already contains the gMSA",
				identity.SAMAccountName,
			)
		}
		plannedCreate[strings.ToLower(identity.Account)] = true
	}

	result := make(
		[]DesiredFIIdentity,
		0,
		len(plannedCreate),
	)
	for _, identity := range ordered {
		if plannedCreate[strings.ToLower(identity.Account)] {
			result = append(result, identity)
		}
	}
	return result, nil
}

func revalidateApproval1ADPreconditions(
	session *ldapSession,
	before Report,
) error {
	if session == nil || session.handle == 0 {
		return fmt.Errorf(
			"LDAP session is unavailable",
		)
	}

	rootDSE, err := session.rootDSE()
	if err != nil {
		return err
	}
	if !strings.EqualFold(
		strings.TrimSpace(rootDSE["defaultNamingContext"]),
		strings.TrimSpace(before.AD.DefaultNamingContext),
	) {
		return fmt.Errorf(
			"default naming context changed: approved=%q current=%q",
			before.AD.DefaultNamingContext,
			rootDSE["defaultNamingContext"],
		)
	}
	if !strings.EqualFold(
		strings.TrimSpace(rootDSE["configurationNamingContext"]),
		strings.TrimSpace(before.AD.ConfigurationNamingContext),
	) {
		return fmt.Errorf(
			"configuration naming context changed: approved=%q current=%q",
			before.AD.ConfigurationNamingContext,
			rootDSE["configurationNamingContext"],
		)
	}

	computerSAM := strings.TrimSpace(before.Host.Computer)
	if computerSAM == "" || strings.EqualFold(computerSAM, notKnown) {
		return fmt.Errorf(
			"computer name is unavailable",
		)
	}
	if !strings.HasSuffix(computerSAM, "$") {
		computerSAM += "$"
	}
	computerDN, computerSID, err := session.findComputerObject(
		before.AD.DefaultNamingContext,
		computerSAM,
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(
		strings.TrimSpace(computerDN),
		strings.TrimSpace(before.AD.ComputerDN),
	) ||
		!strings.EqualFold(
			strings.TrimSpace(computerSID),
			strings.TrimSpace(before.AD.ComputerSID),
		) {
		return fmt.Errorf(
			"computer object changed after planning: approved_dn=%q current_dn=%q approved_sid=%s current_sid=%s",
			before.AD.ComputerDN,
			computerDN,
			before.AD.ComputerSID,
			computerSID,
		)
	}

	kdsBase := fmt.Sprintf(
		"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,%s",
		before.AD.ConfigurationNamingContext,
	)
	kdsCount, err := session.countSearch(
		kdsBase,
		uint32(ldapScopeOneLevel),
		"(objectClass=msKds-ProvRootKey)",
	)
	if err != nil {
		return err
	}
	if kdsCount == 0 {
		return fmt.Errorf(
			"KDS root key is no longer available",
		)
	}
	return nil
}
