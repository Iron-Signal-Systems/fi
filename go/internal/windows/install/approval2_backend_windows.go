// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

type server2016Approval2Backend struct{}

var _ approval2ControllerBackend = (*server2016Approval2Backend)(nil)
var _ approval2ExtendedControllerBackend = (*server2016Approval2Backend)(nil)

func (backend *server2016Approval2Backend) ApplyLocalIdentities(
	report Report,
	plan InstallPlan,
) (func() error, error) {
	if backend == nil {
		return nil, errors.New(
			"Server 2016 Approval 2 backend is unavailable",
		)
	}

	if !planHasMutationAuthority(
		plan,
		"LOCAL ID",
	) {
		return nil, errors.New(
			"Approval 2 plan does not authorize a LOCAL ID mutation",
		)
	}

	return reconcileApproval2LocalIdentities(
		report,
		plan,
	)
}

func (backend *server2016Approval2Backend) ApplyOperationalConfig(
	report Report,
	plan InstallPlan,
	inputs PlanInputs,
	handoff approval1PKIHandoff,
	transactionID string,
) (func() error, error) {
	if backend == nil {
		return nil, errors.New(
			"Server 2016 Approval 2 backend is unavailable",
		)
	}

	if !approval2OperationalConfigRequired(
		report,
		plan,
	) {
		return nil, errors.New(
			"Approval 2 plan does not authorize an operational CONFIG mutation",
		)
	}

	return createApproval2OperationalConfig(
		report,
		plan,
		inputs,
		handoff,
		transactionID,
	)
}

func (backend *server2016Approval2Backend) ApplyTransportTrust(
	report Report,
	plan InstallPlan,
	handoff approval1PKIHandoff,
	transactionID string,
) (func() error, error) {
	if backend == nil {
		return nil, errors.New(
			"Server 2016 Approval 2 backend is unavailable",
		)
	}

	if !planHasMutationAuthority(
		plan,
		"CONFIG",
	) {
		return nil, errors.New(
			"Approval 2 plan does not authorize a CONFIG mutation",
		)
	}

	if !approval2TransportConfigRequired(
		report,
		plan,
		handoff,
	) {
		return nil, errors.New(
			"Approval 2 plan does not authorize the exact transport-trust CONFIG pair",
		)
	}

	if retainedTransportCRLMigrationRequired(
		report,
	) {
		return migrateRetainedTransportTrust(
			report,
			transactionID,
			time.Now().UTC(),
		)
	}

	if err := handoff.validate(); err != nil {
		return nil, fmt.Errorf(
			"Approval 2 native backend received an invalid typed PKI handoff: %w",
			err,
		)
	}

	session, err :=
		openApproval2TransportTrustLDAPSession(
			report,
			handoff,
		)
	if err != nil {
		return nil, err
	}

	if session != nil {
		defer session.close()
	}

	return createApproval2TransportTrust(
		session,
		report,
		handoff,
		transactionID,
	)
}

func (backend *server2016Approval2Backend) ApplyRemainingLocal(
	report Report,
	plan InstallPlan,
	transactionID string,
) ([]approval2ControllerStep, []AppliedMutation, error) {
	if backend == nil {
		return nil, nil, errors.New(
			"Server 2016 Approval 2 backend is unavailable",
		)
	}

	return applyServer2016Approval2RemainingLocal(
		report,
		plan,
		transactionID,
	)
}

func (backend *server2016Approval2Backend) BuildPlan(
	report Report,
	inputs PlanInputs,
	handoff approval1PKIHandoff,
) InstallPlan {
	// New-install deployment inputs are authoritative only while the
	// operational configuration is absent. Once fi.conf exists, reusing those
	// command-line values would intentionally trigger the planner's
	// existing-config protection. Post-mutation convergence therefore rebuilds
	// from the installed configuration itself.
	if report.Config.Presence == presencePresent {
		inputs = PlanInputs{}
	}

	plan := BuildPlanWithInputs(
		report,
		inputs,
	)

	if !handoff.complete() {
		return plan
	}

	if report.Trust.Presence != presenceAbsent {
		return plan
	}

	return applyApproval1PKIHandoffToPlan(
		report,
		plan,
		handoff,
	)
}

func (backend *server2016Approval2Backend) Rediscover() Report {
	return Discover()
}

func executeServer2016Approval2Controller(
	writer io.Writer,
	approval1 Approval1ControllerResult,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
) (Approval2ControllerResult, error) {
	if writer == nil {
		return Approval2ControllerResult{}, errors.New(
			"Approval 2 controller output writer is required",
		)
	}

	backend := &server2016Approval2Backend{}

	return executeRecordedApproval2Controller(
		writer,
		approval1,
		inputs,
		approval,
		backend,
	)
}

func openApproval2TransportTrustLDAPSession(
	report Report,
	handoff approval1PKIHandoff,
) (*ldapSession, error) {
	source := strings.TrimSpace(
		handoff.CRLDistributionPoint,
	)
	if source == "" {
		return nil, errors.New(
			"Approval 2 transport CRL distribution point is empty",
		)
	}

	parsed, err := url.Parse(
		source,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse Approval 2 transport CRL distribution point %q: %w",
			source,
			err,
		)
	}

	switch strings.ToLower(
		strings.TrimSpace(
			parsed.Scheme,
		),
	) {
	case "http", "https":
		// HTTP(S) CRL acquisition does not require the AD LDAP session.
		return nil, nil

	case "ldap":
		domainController := strings.TrimSpace(
			report.AD.DomainController,
		)

		if domainController == "" ||
			strings.EqualFold(
				domainController,
				notKnown,
			) {
			return nil, errors.New(
				"current authoritative domain controller is unavailable for Approval 2 LDAP CRL retrieval",
			)
		}

		session, err := openLDAPSession(
			domainController,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"open signed/sealed Approval 2 LDAP session to %s: %w",
				domainController,
				err,
			)
		}

		if err := revalidateApproval2LDAPSession(
			session,
			report,
		); err != nil {
			session.close()

			return nil, fmt.Errorf(
				"revalidate Approval 2 LDAP session: %w",
				err,
			)
		}

		return session, nil

	default:
		return nil, fmt.Errorf(
			"unsupported Approval 2 transport CRL distribution point scheme %q",
			parsed.Scheme,
		)
	}
}

func revalidateApproval2LDAPSession(
	session *ldapSession,
	report Report,
) error {
	if session == nil ||
		session.handle == 0 {
		return errors.New(
			"Approval 2 LDAP session is unavailable",
		)
	}

	expectedDefault :=
		strings.TrimSpace(
			report.AD.DefaultNamingContext,
		)

	if expectedDefault == "" ||
		strings.EqualFold(
			expectedDefault,
			notKnown,
		) {
		return errors.New(
			"authoritative default naming context is unavailable for Approval 2",
		)
	}

	expectedConfiguration :=
		strings.TrimSpace(
			report.AD.ConfigurationNamingContext,
		)

	if expectedConfiguration == "" ||
		strings.EqualFold(
			expectedConfiguration,
			notKnown,
		) {
		return errors.New(
			"authoritative configuration naming context is unavailable for Approval 2",
		)
	}

	rootDSE, err := session.rootDSE()
	if err != nil {
		return fmt.Errorf(
			"read Approval 2 LDAP RootDSE: %w",
			err,
		)
	}

	observedDefault :=
		strings.TrimSpace(
			rootDSE["defaultNamingContext"],
		)

	if !strings.EqualFold(
		observedDefault,
		expectedDefault,
	) {
		return fmt.Errorf(
			"default naming context changed before Approval 2 CONFIG mutation: approved=%q current=%q",
			expectedDefault,
			observedDefault,
		)
	}

	observedConfiguration :=
		strings.TrimSpace(
			rootDSE["configurationNamingContext"],
		)

	if !strings.EqualFold(
		observedConfiguration,
		expectedConfiguration,
	) {
		return fmt.Errorf(
			"configuration naming context changed before Approval 2 CONFIG mutation: approved=%q current=%q",
			expectedConfiguration,
			observedConfiguration,
		)
	}

	return nil
}
