// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	planActionBlocked   = "BLOCKED"
	planActionCreate    = "CREATE"
	planActionNoChange  = "NO CHANGE"
	planActionQuestion  = "QUESTION"
	planActionReconcile = "RECONCILE"
)

type InstallPlan struct {
	Actions    []PlanAction
	Approvals  []string
	Identities DesiredFIIdentities
	Mode       string
	PKIChoices []string
	Questions  []string
}

type PlanInputs struct {
	GovernedRoots   []string
	ReceiverPending bool
	PKIChoice       string
	ReceiverAddress string
	ReceiverName    string
	SpoolDir        string
	StageDir        string
	StateDir        string
}

func (inputs PlanInputs) ConfigEmpty() bool {
	return len(inputs.GovernedRoots) == 0 &&
		strings.TrimSpace(inputs.ReceiverAddress) == "" &&
		strings.TrimSpace(inputs.ReceiverName) == "" &&
		strings.TrimSpace(inputs.SpoolDir) == "" &&
		strings.TrimSpace(inputs.StageDir) == "" &&
		strings.TrimSpace(inputs.StateDir) == ""
}

func (inputs PlanInputs) Empty() bool {
	return inputs.ConfigEmpty() &&
		strings.TrimSpace(inputs.PKIChoice) == ""
}

type PlanAction struct {
	Action    string
	Authority string
	Detail    string
	Target    string
}

func BuildPlan(report Report) InstallPlan {
	return BuildPlanWithInputs(
		report,
		PlanInputs{},
	)
}

func BuildPlanWithInputs(
	report Report,
	inputs PlanInputs,
) InstallPlan {
	plan := InstallPlan{
		Mode: installPlanMode(report),
		PKIChoices: []string{
			"Use/reuse the discovered FI PKI",
			"Enroll or provision this source from an existing FI PKI",
			"Create a new FI PKI with explicit CA-key custody/export handling",
		},
		Approvals: []string{
			"Approval 1: AD / KDS / gMSA / PKI changes",
			"Approval 2: local FI configuration / binaries / privileges / ACLs / services",
		},
	}

	identities, identityErr := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if identityErr == nil {
		identities, identityErr = bindDesiredFIIdentitySIDs(
			report,
			identities,
		)
	}
	if identityErr != nil {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "IDENTITY",
				Detail:    identityErr.Error(),
				Target:    "FI gMSA naming",
			},
		)
	} else {
		plan.Identities = identities
		for _, identity := range desiredFIIdentityList(
			identities,
		) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "IDENTITY",
					Detail: fmt.Sprintf(
						"derived from computer=%s domain=%s",
						report.Host.Computer,
						report.Join.Name,
					),
					Target: identity.Role + " -> " + identity.Account,
				},
			)
		}
	}

	planHostAndOS(&plan, report)
	planConfiguration(&plan, &report, inputs)
	supplementACLDiscoveryForPlan(&report)
	planActiveDirectory(&plan, report, identities, identityErr)
	planLocalGMSAs(&plan, report, identities, identityErr)
	planPKI(&plan, report, inputs)
	planPrivileges(&plan, report, identities, identityErr)
	planLocalGroups(&plan, report, identities, identityErr)
	planACLs(&plan, report)
	planCNGKeyACLs(&plan, report)
	planServices(&plan, report, identities, identityErr, inputs.ReceiverPending)
	planReleaseTrust(&plan, report)
	planReleaseTrustACL(&plan, report)
	planPackage(&plan, report)

	return plan
}

func (plan InstallPlan) HasBlockers() bool {
	for _, action := range plan.Actions {
		if action.Action == planActionBlocked {
			return true
		}
	}
	return false
}

func (plan InstallPlan) HasQuestions() bool {
	return len(plan.Questions) != 0
}

func (plan InstallPlan) WriteText(writer io.Writer) error {
	if writer == nil {
		return fmt.Errorf(
			"output writer is required",
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - DESIRED-STATE PLAN")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Mode: %s\n", plan.Mode)

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== PKI CHOICES =====")
	for index, choice := range plan.PKIChoices {
		fmt.Fprintf(
			writer,
			"[%d] %s\n",
			index+1,
			choice,
		)
	}

	if len(plan.Questions) != 0 {
		fmt.Fprintln(writer, "")
		fmt.Fprintln(writer, "===== MISSING INFORMATION =====")
		for _, question := range plan.Questions {
			fmt.Fprintf(writer, "- %s\n", question)
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== PLANNED ACTIONS =====")
	for _, action := range plan.Actions {
		fmt.Fprintf(
			writer,
			"%-10s %-12s %-40s %s\n",
			action.Action,
			action.Authority,
			action.Target,
			action.Detail,
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== APPROVAL BOUNDARIES =====")
	for _, approval := range plan.Approvals {
		fmt.Fprintf(writer, "- %s\n", approval)
	}

	fmt.Fprintln(writer, "")
	if plan.HasBlockers() {
		fmt.Fprintln(
			writer,
			"FI INSTALLER PLAN RESULT: BLOCKED FOR MUTATION",
		)
	} else if plan.HasQuestions() {
		fmt.Fprintln(
			writer,
			"FI INSTALLER PLAN RESULT: NEEDS OPERATOR INPUT",
		)
	} else {
		fmt.Fprintln(
			writer,
			"FI INSTALLER PLAN RESULT: READY FOR OPERATOR APPROVAL",
		)
	}
	fmt.Fprintln(
		writer,
		"No changes were made. This milestone is planning-only.",
	)

	return nil
}

func installPlanMode(report Report) string {
	if report.Config.Presence == presencePresent ||
		strings.TrimSpace(report.Config.VersionID) != "" {
		return "UPDATE / RECONCILE"
	}
	if report.Config.Presence == presenceUnknown {
		return "DISCOVERY INCOMPLETE"
	}

	unknownObserved := false

	for _, service := range report.Services {
		if service.Presence == presencePresent ||
			serviceObserved(service) {
			return "UPDATE / RECONCILE"
		}
		if service.Presence == presenceUnknown {
			unknownObserved = true
		}
	}
	for _, binary := range report.Binaries {
		if binary.Presence == presencePresent ||
			(strings.TrimSpace(binary.SHA256) != "" &&
				binary.SHA256 != notKnown) {
			return "UPDATE / RECONCILE"
		}
		if binary.Presence == presenceUnknown {
			unknownObserved = true
		}
	}

	if unknownObserved {
		return "DISCOVERY INCOMPLETE"
	}

	return "NEW INSTALL"
}

func planHostAndOS(
	plan *InstallPlan,
	report Report,
) {
	if report.Host.Profile.Name == notKnown ||
		report.Host.Profile.BuildNumber == 0 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "HOST",
				Detail: fmt.Sprintf(
					"build %d has no accepted FI installer profile",
					report.Host.BuildNumber,
				),
				Target: "Windows release profile",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "HOST",
				Detail: fmt.Sprintf(
					"%s build %d",
					report.Host.Profile.Name,
					report.Host.BuildNumber,
				),
				Target: "Windows release profile",
			},
		)
	}

	if report.Join.Status != "domain" {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "HOST",
				Detail:    "FI gMSA deployment requires an Active Directory domain-joined source",
				Target:    "domain membership",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "HOST",
				Detail:    "domain=" + report.Join.Name,
				Target:    "domain membership",
			},
		)
	}
}

func planConfiguration(
	plan *InstallPlan,
	report *Report,
	inputs PlanInputs,
) {
	if report.Config.Presence == presenceUnknown {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "CONFIG",
				Detail:    "operational configuration presence/content is unknown; FI will not infer absence or construct a new configuration from an unreadable existing state",
				Target:    "FI operational configuration",
			},
		)
		return
	}

	if report.Config.Presence == presencePresent ||
		strings.TrimSpace(report.Config.VersionID) != "" {
		if !inputs.ConfigEmpty() {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "CONFIG",
					Detail:    "new-install planning inputs were supplied while a validated FI configuration already exists; use the future explicit configuration-change workflow rather than silently overriding installed authority",
					Target:    "FI operational configuration",
				},
			)
			return
		}

		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "CONFIG",
				Detail: fmt.Sprintf(
					"reuse validated config %s version=%s unless operator selects a change",
					report.Config.Path,
					report.Config.VersionID,
				),
				Target: "FI operational configuration",
			},
		)
		return
	}

	configPath := strings.TrimSpace(report.Config.Path)
	if configPath == "" {
		configPath = `C:\ProgramData\FI\config\fi.conf`
	}

	proposal := ConfigState{
		GovernedRoots: append([]string(nil), inputs.GovernedRoots...),
		Path:          configPath,
		Presence:      presenceAbsent,
		SpoolDir:      strings.TrimSpace(inputs.SpoolDir),
		StageDir:      strings.TrimSpace(inputs.StageDir),
		StateDir:      strings.TrimSpace(inputs.StateDir),
	}

	if proposal.StageDir == "" {
		proposal.StageDir = `C:\ProgramData\FI\transport-v2-drain\stage`
	}
	if proposal.StateDir == "" {
		proposal.StateDir = `C:\ProgramData\FI\state`
	}

	proposal.ReceiverAddress = strings.TrimSpace(
		inputs.ReceiverAddress,
	)
	proposal.ReceiverName = strings.TrimSpace(
		inputs.ReceiverName,
	)

	if report.Host.Computer != notKnown &&
		report.Host.DomainDNS != notKnown &&
		strings.TrimSpace(report.Host.Computer) != "" &&
		strings.TrimSpace(report.Host.DomainDNS) != "" {
		proposal.SourceID = strings.ToLower(
			report.Host.Computer +
				"." +
				report.Host.DomainDNS,
		)
	}

	missing := make([]string, 0)
	if proposal.SourceID == "" {
		missing = append(
			missing,
			"source identity cannot be derived because the computer name or DNS domain is unavailable",
		)
	}
	if proposal.ReceiverAddress == "" {
		missing = append(
			missing,
			"receiver address (-receiver-address)",
		)
	}
	if proposal.ReceiverName == "" {
		missing = append(
			missing,
			"receiver DNS/name (-receiver-name)",
		)
	}
	if proposal.SpoolDir == "" {
		missing = append(
			missing,
			"spool location (-spool-dir)",
		)
	}
	if len(proposal.GovernedRoots) == 0 {
		missing = append(
			missing,
			"at least one governed root (-governed-root, repeatable)",
		)
	}

	if err := validateProposedConfigPaths(proposal); err != nil {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "CONFIG",
				Detail:    err.Error(),
				Target:    "FI operational configuration",
			},
		)
		return
	}

	*report = reportWithProposedConfig(
		*report,
		proposal,
	)

	if len(missing) != 0 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionQuestion,
				Authority: "CONFIG",
				Detail:    "new source configuration is absent; supply only deployment values that cannot be discovered or safely derived",
				Target:    configPath,
			},
		)
		for _, item := range missing {
			plan.Questions = append(
				plan.Questions,
				item,
			)
		}
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "CONFIG",
				Detail: fmt.Sprintf(
					"after Approval 2 create FI 1.1 config source=%s receiver=%s receiver_name=%s spool=%s stage=%s state=%s governed_roots=%s",
					proposal.SourceID,
					proposal.ReceiverAddress,
					proposal.ReceiverName,
					proposal.SpoolDir,
					proposal.StageDir,
					proposal.StateDir,
					strings.Join(
						proposal.GovernedRoots,
						",",
					),
				),
				Target: configPath,
			},
		)
	}

	if proposal.SourceID != "" {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "CONFIG",
				Detail:    "derived automatically from local computer + DNS domain",
				Target:    "source.id=" + proposal.SourceID,
			},
		)
	}
}

func reportWithProposedConfig(
	report Report,
	proposal ConfigState,
) Report {
	report.Config = proposal
	return report
}

func validateProposedConfigPaths(
	proposal ConfigState,
) error {
	systemDrive := strings.TrimSpace(
		os.Getenv(
			"SystemDrive",
		),
	)

	if systemDrive != "" &&
		strings.TrimSpace(
			proposal.SpoolDir,
		) != "" &&
		strings.EqualFold(
			filepath.Clean(
				proposal.SpoolDir,
			),
			filepath.Clean(
				systemDrive+`\`,
			),
		) {
		return fmt.Errorf(
			"FI spool directory must not be the Windows system-volume root %q; choose a dedicated directory or a non-system volume",
			proposal.SpoolDir,
		)
	}

	values := []struct {
		name  string
		path  string
		allow bool
	}{
		{
			name:  "configuration path",
			path:  proposal.Path,
			allow: strings.TrimSpace(proposal.Path) != "",
		},
		{
			name:  "spool directory",
			path:  proposal.SpoolDir,
			allow: strings.TrimSpace(proposal.SpoolDir) != "",
		},
		{
			name:  "stage directory",
			path:  proposal.StageDir,
			allow: true,
		},
		{
			name:  "state directory",
			path:  proposal.StateDir,
			allow: true,
		},
	}

	for _, value := range values {
		if !value.allow {
			continue
		}
		if !filepath.IsAbs(
			value.path,
		) {
			return fmt.Errorf(
				"%s must be an absolute Windows path: %q",
				value.name,
				value.path,
			)
		}
	}

	for _, root := range proposal.GovernedRoots {
		if !filepath.IsAbs(
			strings.TrimSpace(
				root,
			),
		) {
			return fmt.Errorf(
				"governed root must be an absolute Windows path: %q",
				root,
			)
		}
	}

	return nil
}

func planActiveDirectory(
	plan *InstallPlan,
	report Report,
	identities DesiredFIIdentities,
	identityErr error,
) {
	if report.AD.DomainController == "" ||
		report.AD.DefaultNamingContext == "" {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "AD",
				Detail:    "writable Active Directory discovery is incomplete",
				Target:    "Active Directory",
			},
		)
		return
	}

	if !report.AD.KDSRootKeyKnown {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "AD",
				Detail:    "KDS root-key state is unknown",
				Target:    "KDS root key",
			},
		)
	} else if report.AD.KDSRootKeyCount == 0 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "AD",
				Detail:    "requires Approval 1; production forests use normal KDS propagation timing; lab backdating is never automatic",
				Target:    "KDS root key",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "AD",
				Detail: fmt.Sprintf(
					"root_key_objects=%d",
					report.AD.KDSRootKeyCount,
				),
				Target: "KDS root key",
			},
		)
	}

	if identityErr != nil {
		return
	}

	computerObjectKnown := report.AD.ComputerObjectKnown &&
		strings.TrimSpace(report.AD.ComputerDN) != "" &&
		strings.TrimSpace(report.AD.ComputerSID) != ""

	if !computerObjectKnown || !report.AD.GMSADiscoveryKnown {
		detailParts := make([]string, 0, 2)
		if !computerObjectKnown {
			detailParts = append(
				detailParts,
				"local computer AD object/SID was not authoritatively discovered",
			)
		}
		if !report.AD.GMSADiscoveryKnown {
			detailParts = append(
				detailParts,
				"one or more gMSA LDAP searches did not complete authoritatively",
			)
		}

		for _, identity := range desiredFIIdentityList(
			identities,
		) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "AD",
					Detail: strings.Join(
						detailParts,
						"; ",
					) + "; FI will not infer absence or plan CREATE from unknown AD state",
					Target: identity.Account,
				},
			)
		}
		return
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		state, found := findADGMSA(
			report.AD.GMSAs,
			identity.SAMAccountName,
		)
		if !found {
			if !report.AD.KDSRootKeyKnown {
				plan.Actions = append(
					plan.Actions,
					PlanAction{
						Action:    planActionBlocked,
						Authority: "AD",
						Detail:    "gMSA absence is known, but KDS root-key state is unknown; FI will not plan gMSA creation until KDS state is authoritative",
						Target:    identity.Account,
					},
				)
				continue
			}

			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionCreate,
					Authority: "AD",
					Detail:    "authoritative AD discovery confirmed the gMSA is absent; create it and authorize only the local computer object to retrieve the managed password after Approval 1",
					Target:    identity.Account,
				},
			)
			continue
		}

		expectedDNS := strings.TrimSuffix(
			identity.SAMAccountName,
			"$",
		)
		if report.Host.DomainDNS != notKnown {
			expectedDNS += "." + report.Host.DomainDNS
		}

		exactTrustee := exactSingleGMSATrustee(
			state.PasswordRetrievalTrustees,
			report.AD.ComputerSID,
		)

		if strings.EqualFold(
			state.DNSHostName,
			expectedDNS,
		) && exactTrustee {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "AD",
					Detail:    "gMSA exists with expected DNS name and exact one-host password-retrieval authorization",
					Target:    identity.Account,
				},
			)
			continue
		}

		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "AD",
				Detail:    "gMSA exists but DNS/password-retrieval authorization differs from desired one-host contract; requires Approval 1",
				Target:    identity.Account,
			},
		)
	}
}

func planLocalGMSAs(
	plan *InstallPlan,
	report Report,
	identities DesiredFIIdentities,
	identityErr error,
) {
	if identityErr != nil {
		return
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		state, found := findLocalGMSA(
			report.GMSAs,
			identity.SAMAccountName,
		)
		if !found {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "LOCAL ID",
					Detail:    "authoritative gMSA local-state discovery is unavailable; FI will not infer local absence",
					Target:    identity.Account,
				},
			)
			continue
		}

		switch state.State {
		case "installed":
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "LOCAL ID",
					Detail:    "AD gMSA exists and the native Netlogon local service-account store contains the identity",
					Target:    identity.Account,
				},
			)

		case "not_installed":
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "LOCAL ID",
					Detail:    "AD gMSA exists but the native Netlogon local service-account store does not contain the identity; install it locally after Approval 2 before configuring rights, groups, ACL dependencies, or services",
					Target:    identity.Account,
				},
			)

		case "pending_ad_creation":
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "LOCAL ID",
					Detail:    "AD authoritatively confirms the gMSA is absent; Approval 1 must create it, then FI must rediscover authoritative AD and native Netlogon local state before Approval 2 can install it locally",
					Target:    identity.Account,
				},
			)

		case notKnown:
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "LOCAL ID",
					Detail:    "gMSA AD/native Netlogon local state is unknown; FI will not infer local absence or installation authority",
					Target:    identity.Account,
				},
			)

		default:
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "LOCAL ID",
					Detail:    "gMSA local state=" + state.State + " does not authorize automatic local installation planning",
					Target:    identity.Account,
				},
			)
		}
	}
}

func planPKI(
	plan *InstallPlan,
	report Report,
	inputs PlanInputs,
) {
	if report.Trust.Presence == presenceUnknown &&
		strings.TrimSpace(report.Trust.VersionID) == "" {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PKI",
				Detail:    "transport-trust configuration presence/content is unknown; FI will not infer absence from an unreadable trust state",
				Target:    "FI transport PKI",
			},
		)
		return
	}

	if transportPKIComplete(report) {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "PKI",
				Detail:    "current trust configuration, root, issuer, source identity, batch identity, and CRL are all available; default choice is reuse",
				Target:    "FI transport PKI",
			},
		)

		if retainedTransportCRLMigrationRequired(
			report,
		) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "CONFIG",
					Detail:    "after Approval 2 migrate the validated retained transport CRL into the dedicated CRL activation namespace without changing PKI identity",
					Target:    approval1TransportCRLDestination,
				},
				PlanAction{
					Action:    planActionReconcile,
					Authority: "CONFIG",
					Detail:    "after Approval 2 rewrite only trust.transport_crl to the dedicated CRL activation namespace while preserving all pinned certificate hashes",
					Target:    report.Trust.Path,
				},
			)
		}

		return
	}

	choice := strings.ToLower(
		strings.TrimSpace(
			inputs.PKIChoice,
		),
	)

	switch choice {
	case "":
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionQuestion,
				Authority: "PKI",
				Detail:    "transport PKI is absent/incomplete; select one explicit bootstrap path before Approval 1",
				Target:    "FI transport PKI",
			},
		)
		plan.Questions = append(
			plan.Questions,
			"PKI path (-pki-choice reuse|enroll|create).",
		)
	case "reuse":
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "PKI",
				Detail:    "after Approval 1 import/reuse an existing FI transport trust set and source/batch identities; exact certificate/CRL inputs remain a later mutation contract",
				Target:    "FI transport PKI",
			},
		)
	case "enroll":
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "PKI",
				Detail:    "after Approval 1 ensure the source computer is authorized through existing group ISS-FI-Certificate-Enrollment, purge SYSTEM Kerberos LUID 0x3e7, then enroll and verify the machine transport and batch identities from the existing FI PKI",
				Target:    "FI transport PKI",
			},
		)
	case "create":
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "PKI",
				Detail:    "after Approval 1 bootstrap a new FI transport PKI with explicit CA-key custody/export handling; release-signing trust remains separate",
				Target:    "FI transport PKI",
			},
		)
	default:
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PKI",
				Detail: fmt.Sprintf(
					"unsupported -pki-choice %q; expected reuse, enroll, or create",
					inputs.PKIChoice,
				),
				Target: "FI transport PKI",
			},
		)
	}
}

func planPrivileges(
	plan *InstallPlan,
	report Report,
	identities DesiredFIIdentities,
	identityErr error,
) {
	if identityErr != nil {
		return
	}

	collectorRights := directRights(
		report,
		identities.CollectorSender.Account,
	)
	if containsFold(
		collectorRights,
		"SeServiceLogonRight",
	) && len(collectorRights) == 1 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RIGHTS",
				Detail:    "exact direct-right set is SeServiceLogonRight",
				Target:    identities.CollectorSender.Account,
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "RIGHTS",
				Detail:    "desired direct-right set is SeServiceLogonRight only; remove historical/unnecessary direct rights such as SeManageVolumePrivilege after Approval 2",
				Target:    identities.CollectorSender.Account,
			},
		)
	}

	crlRights := directRights(
		report,
		identities.CRLRefresher.Account,
	)
	if containsFold(
		crlRights,
		"SeServiceLogonRight",
	) && len(crlRights) == 1 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RIGHTS",
				Detail:    "exact CRL refresher direct-right set is SeServiceLogonRight",
				Target:    identities.CRLRefresher.Account,
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "RIGHTS",
				Detail:    "CRL refresher desired direct-right set is SeServiceLogonRight only",
				Target:    identities.CRLRefresher.Account,
			},
		)
	}

	usnRights := directRights(
		report,
		identities.USNReader.Account,
	)
	if containsFold(
		usnRights,
		"SeServiceLogonRight",
	) && len(usnRights) == 1 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RIGHTS",
				Detail:    "direct-right set matches currently validated USN helper contract; local Administrators membership remains separately required",
				Target:    identities.USNReader.Account,
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "RIGHTS",
				Detail:    "desired direct-right set is SeServiceLogonRight; raw-volume access is supplied through the narrowly scoped local-Administrator helper boundary",
				Target:    identities.USNReader.Account,
			},
		)
	}

	if !objReaderRightsMutationEnabledBuild(report.Host.BuildNumber) {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "RIGHTS",
				Detail: fmt.Sprintf(
					"FIObjReader exact least-privilege contract has not yet been characterized for %s build %d",
					report.Host.Profile.Name,
					report.Host.BuildNumber,
				),
				Target: identities.ObjReader.Account,
			},
		)
		return
	}

	objRights := directRights(
		report,
		identities.ObjReader.Account,
	)
	required := []string{
		"SeBackupPrivilege",
		"SeSecurityPrivilege",
		"SeServiceLogonRight",
	}
	if exactRights(objRights, required) {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RIGHTS",
				Detail:    "release-specific direct-right set matches accepted FIObjReader contract",
				Target:    identities.ObjReader.Account,
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "RIGHTS",
				Detail:    "desired FIObjReader direct rights: SeServiceLogonRight, SeBackupPrivilege, SeSecurityPrivilege; SeRestorePrivilege and SeManageVolumePrivilege forbidden",
				Target:    identities.ObjReader.Account,
			},
		)
	}
}

func planLocalGroups(
	plan *InstallPlan,
	report Report,
	identities DesiredFIIdentities,
	identityErr error,
) {
	if identityErr != nil {
		return
	}

	type groupContract struct {
		account string
		check   string
		detail  string
		group   string
		want    bool
	}

	contracts := []groupContract{
		{
			account: identities.CollectorSender.Account,
			check:   "FICollector direct local Administrator membership",
			detail:  "collector/sender must not be a direct member of local Administrators",
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.CollectorSender.Account,
			check:   "FICollector/FISender direct Event Log Readers membership",
			detail:  "collector/sender requires direct Event Log Readers membership for Windows Security channel read access without local-Administrator membership",
			group:   "Event Log Readers",
			want:    true,
		},
		{
			account: identities.CRLRefresher.Account,
			check:   "FICRLRefresher direct local Administrator membership",
			detail:  "CRL refresher must not be a direct member of local Administrators",
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.CRLRefresher.Account,
			check:   "FICRLRefresher direct Event Log Readers membership",
			detail:  "CRL refresher does not require Windows Event Log Readers membership",
			group:   "Event Log Readers",
			want:    false,
		},
		{
			account: identities.CRLRefresher.Account,
			check:   "FICRLRefresher direct Backup Operators membership",
			detail:  "CRL refresher must not receive Backup Operators membership",
			group:   "Backup Operators",
			want:    false,
		},
		{
			account: identities.USNReader.Account,
			check:   "FIUSNReader direct local Administrator membership",
			detail:  "USN helper requires the characterized narrow local-Administrator boundary",
			group:   "Administrators",
			want:    true,
		},
		{
			account: identities.ObjReader.Account,
			check:   "FIObjReader direct local Administrator membership",
			detail:  "object reader must not be a direct member of local Administrators",
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.ObjReader.Account,
			check:   "FIObjReader direct Backup Operators membership",
			detail:  "object reader receives direct SeBackupPrivilege/SeSecurityPrivilege and must not use Backup Operators membership",
			group:   "Backup Operators",
			want:    false,
		},
	}

	for _, contract := range contracts {
		check, found := findCheck(
			report,
			contract.check,
		)
		target := fmt.Sprintf(
			"%s -> %s",
			contract.account,
			contract.group,
		)

		if found && check.Status == checkPass {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "GROUPS",
					Detail:    contract.detail + "; " + check.Detail,
					Target:    target,
				},
			)
			continue
		}

		detail := contract.detail
		if found && strings.TrimSpace(check.Detail) != "" {
			detail += "; observed: " + check.Detail
		}
		if contract.want {
			detail += "; add direct membership after Approval 2"
		} else {
			detail += "; remove direct membership after Approval 2"
		}

		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "GROUPS",
				Detail:    detail,
				Target:    target,
			},
		)
	}
}

func planACLs(
	plan *InstallPlan,
	report Report,
) {
	contracts := []struct {
		check  string
		target string
	}{
		{
			check:  "FI config directory desired ACL contract",
			target: `C:\ProgramData\FI\config`,
		},
		{
			check:  "FI program directory desired ACL contract",
			target: `C:\Program Files\FI`,
		},
		{
			check:  "FI state directory desired ACL contract",
			target: valueOrNotKnown(report.Config.StateDir),
		},
		{
			check:  "FI spool directory desired ACL contract",
			target: valueOrNotKnown(report.Config.SpoolDir),
		},
		{
			check: collectorWorkDirectoryACLLabel +
				" desired ACL contract",
			target: valueOrNotKnown(
				collectorWorkDirectoryTarget(
					report.Config.SpoolDir,
				),
			),
		},
		{
			check:  "FI PKI trust directory desired ACL contract",
			target: "FI PKI trust root",
		},
		{
			check:  "FI CRL activation directory desired ACL contract",
			target: crlRefresherActivationDirectory,
		},
		{
			check:  "FI CRL active file desired ACL contract",
			target: approval1TransportCRLDestination,
		},
		{
			check:  "FI CRL refresher journal directory desired ACL contract",
			target: crlRefresherJournalDirectory,
		},
		{
			check:  "FI CRL refresher journal file desired ACL contract",
			target: crlRefresherJournalPath,
		},
		{
			check:  "FI CRL refresher trust config file desired ACL contract",
			target: crlRefresherTrustConfigPath,
		},
		{
			check:  "FI CRL refresher executable file desired ACL contract",
			target: crlRefresherExecutablePath,
		},
	}

	for _, contract := range contracts {
		if contract.check ==
			"FI PKI trust directory desired ACL contract" &&
			!legacyTransportTrustDirectoryRequired(
				report,
			) {
			continue
		}

		if strings.EqualFold(
			strings.TrimSpace(contract.target),
			notKnown,
		) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionQuestion,
					Authority: "ACL",
					Detail:    "ACL target depends on a required deployment value that has not been supplied; no filesystem mutation is planned against an unknown path",
					Target:    contract.check,
				},
			)
			continue
		}

		state, found := findCheck(
			report,
			contract.check,
		)
		if found && state.Status == checkPass {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "ACL",
					Detail:    state.Detail,
					Target:    contract.target,
				},
			)
			continue
		}

		detail := "desired ACL state is not currently proven"
		if found {
			detail = state.Detail
		}
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "ACL",
				Detail:    detail,
				Target:    contract.target,
			},
		)
	}

	stageShape, stageShapeFound := findCheck(
		report,
		"FI stage directory desired ACL shape",
	)
	stageInheritance, stageInheritanceFound := findCheck(
		report,
		"FI stage directory inheritance",
	)

	if stageShapeFound &&
		stageShape.Status == checkPass &&
		(!stageInheritanceFound ||
			stageInheritance.Status != checkWarn) {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "ACL",
				Detail:    stageShape.Detail,
				Target:    valueOrNotKnown(report.Config.StageDir),
			},
		)
	} else {
		detail := "protect FI-owned stage root and preserve Administrators/SYSTEM FullControl plus collector/sender Modify"
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "ACL",
				Detail:    detail,
				Target:    valueOrNotKnown(report.Config.StageDir),
			},
		)
	}
}

func planServices(
	plan *InstallPlan,
	report Report,
	identities DesiredFIIdentities,
	identityErr error,
	receiverPendingOption ...bool,
) {
	receiverPending := false
	if len(receiverPendingOption) != 0 {
		receiverPending = receiverPendingOption[0]
	}

	if identityErr != nil {
		return
	}

	expected := []struct {
		account      string
		name         string
		path         string
		runtimeState string
		sidType      string
		startType    string
	}{
		{
			account:      identities.CollectorSender.Account,
			name:         "FICollector",
			path:         `"C:\Program Files\FI\fi-collector.exe" -service`,
			runtimeState: "Running",
			sidType:      "UNRESTRICTED",
			startType:    "Automatic",
		},
		{
			account:      identities.USNReader.Account,
			name:         "FIUSNReader",
			path:         `"C:\Program Files\FI\fi-usn-reader.exe"`,
			runtimeState: "Running",
			sidType:      "UNRESTRICTED",
			startType:    "Automatic",
		},
		{
			account:      identities.ObjReader.Account,
			name:         "FIObjReader",
			path:         `"C:\Program Files\FI\fi-obj-reader.exe"`,
			runtimeState: "Running",
			sidType:      "UNRESTRICTED",
			startType:    "Automatic",
		},
		{
			account:      identities.CRLRefresher.Account,
			name:         "FICRLRefresher",
			path:         `"C:\Program Files\FI\fi-crl-refresher.exe"`,
			runtimeState: "Running",
			sidType:      "NONE",
			startType:    "Automatic",
		},
		{
			account:      identities.CollectorSender.Account,
			name:         "FISender",
			path:         `"C:\Program Files\FI\fi-sender.exe"`,
			runtimeState: "Running",
			sidType:      "NONE",
			startType:    "Automatic",
		},
	}

	if receiverPending {
		for index := range expected {
			if expected[index].name == "FISender" {
				expected[index].startType = "Manual"
				expected[index].runtimeState = "Stopped"
			}
		}
	}

	for _, desired := range expected {
		marker := ""
		if receiverPending && desired.name == "FISender" {
			marker = receiverPendingPlanMarker + "; "
		}

		observed, found := findService(
			report.Services,
			desired.name,
		)
		if !found {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "SCM",
					Detail:    "service discovery state is unavailable; FI will not infer absence from a missing discovery result",
					Target:    desired.name,
				},
			)
			continue
		}
		if observed.Presence == presenceUnknown {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "SCM",
					Detail:    "service presence/configuration is unknown; FI will not infer absence or plan CREATE",
					Target:    desired.name,
				},
			)
			continue
		}
		if observed.Presence == presenceAbsent ||
			(observed.Presence == "" && !serviceObserved(observed)) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionCreate,
					Authority: "SCM",
					Detail: fmt.Sprintf(
						"%sauthoritative SCM discovery confirmed the service is absent; create managed-account service start=%s runtime=%s with exact binary path, identity, and service-SID type after Approval 2",
						marker,
						desired.startType,
						desired.runtimeState,
					),
					Target: desired.name,
				},
			)
			continue
		}

		configMatches := strings.EqualFold(
			strings.TrimSpace(observed.Account),
			desired.account,
		) &&
			strings.EqualFold(
				strings.TrimSpace(observed.BinaryPath),
				desired.path,
			) &&
			observed.ManagedAccount == "true" &&
			observed.SIDType == desired.sidType &&
			observed.StartType == desired.startType

		if configMatches {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "SCM",
					Detail:    marker + "service matches desired identity/path/start/SID configuration",
					Target:    desired.name,
				},
			)
		} else {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "SCM",
					Detail: fmt.Sprintf(
						"%sdesired account=%s path=%s managed=true start=%s sid=%s",
						marker,
						desired.account,
						desired.path,
						desired.startType,
						desired.sidType,
					),
					Target: desired.name,
				},
			)
		}

		runtimeMatches :=
			observed.State ==
				desired.runtimeState

		runtimeDetail :=
			marker +
				"service runtime state is " +
				desired.runtimeState

		if runtimeMatches &&
			desired.runtimeState == "Running" &&
			observed.ProcessID != 0 {

			expectedProcessPath, known :=
				expectedFIServiceExecutablePath(
					desired.name,
				)

			if !known {
				plan.Actions =
					append(
						plan.Actions,
						PlanAction{
							Action:    planActionBlocked,
							Authority: "RUNTIME",
							Detail:    marker + "desired FI service executable path is not characterized",
							Target:    desired.name,
						},
					)

				continue
			}

			if !sameWindowsExecutablePath(
				observed.ProcessPath,
				expectedProcessPath,
			) {
				runtimeMatches =
					false

				runtimeDetail =
					fmt.Sprintf(
						"%sservice is Running but SCM PID=%d executes image=%s; expected image=%s; controlled restart after Approval 2",
						marker,
						observed.ProcessID,
						valueOrNotKnown(
							observed.ProcessPath,
						),
						expectedProcessPath,
					)
			} else {
				runtimeDetail =
					fmt.Sprintf(
						"%sservice runtime state is Running and SCM PID=%d executes image=%s",
						marker,
						observed.ProcessID,
						expectedProcessPath,
					)
			}
		}

		if runtimeMatches {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "RUNTIME",
					Detail:    runtimeDetail,
					Target:    desired.name,
				},
			)
		} else {
			if observed.State != desired.runtimeState {
				runtimeDetail =
					fmt.Sprintf(
						"%sdesired runtime state=%s; observed state=%s; reconcile after Approval 2",
						marker,
						desired.runtimeState,
						valueOrNotKnown(
							observed.State,
						),
					)
			}

			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "RUNTIME",
					Detail:    runtimeDetail,
					Target:    desired.name,
				},
			)
		}
	}
}

func planReleaseTrust(
	plan *InstallPlan,
	report Report,
) {
	state := report.ReleaseTrust

	if !state.BootstrapAuthorityConfigured {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "RELEASE TRUST",
				Detail:    "this fi-install.exe build does not contain the pinned SPKI SHA-256 of the offline Iron Signal Systems release-policy authority",
				Target:    "ISS release-policy authority",
			},
		)
		return
	}

	if state.Installed.Present && !state.Installed.Valid {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "RELEASE TRUST",
				Detail:    "installed release-trust state exists but is not valid; fail closed rather than replacing an untrusted authority state",
				Target:    installedReleaseTrustRoot,
			},
		)
		return
	}

	if !state.Installed.Present {
		if !state.Package.Valid {
			detail := state.Package.Error
			if detail == "" {
				detail = "first installation requires package release-trust.json + release-trust.p7s generation=1 signed by the pinned ISS release-policy authority"
			}
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "RELEASE TRUST",
					Detail:    detail,
					Target:    "bootstrap FI release trust",
				},
			)
			return
		}

		if !state.TransitionAllowed {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "RELEASE TRUST",
					Detail:    state.Error,
					Target:    "bootstrap FI release trust",
				},
			)
			return
		}

		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "RELEASE TRUST",
				Detail: fmt.Sprintf(
					"after Approval 2 install protected generation=%d policy_sha256=%s authorized by the pinned ISS release-policy authority",
					state.Package.Policy.Generation,
					state.Package.PolicySHA256,
				),
				Target: installedReleaseTrustRoot,
			},
		)
	} else if state.Package.Present {
		if !state.Package.Valid ||
			!state.TransitionAllowed {
			detail := state.Error
			if detail == "" {
				detail = state.Package.Error
			}
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "RELEASE TRUST",
					Detail:    detail,
					Target:    "release-trust transition",
				},
			)
			return
		}

		if state.Package.Policy.Generation ==
			state.Installed.Policy.Generation {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "RELEASE TRUST",
					Detail: fmt.Sprintf(
						"package policy is byte-identical to installed generation=%d policy_sha256=%s",
						state.Installed.Policy.Generation,
						state.Installed.PolicySHA256,
					),
					Target: installedReleaseTrustRoot,
				},
			)
		} else {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "RELEASE TRUST",
					Detail: fmt.Sprintf(
						"authorized one-generation transition %d -> %d; package previous_policy_sha256 matches installed policy SHA-256",
						state.Installed.Policy.Generation,
						state.Package.Policy.Generation,
					),
					Target: installedReleaseTrustRoot,
				},
			)
		}
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RELEASE TRUST",
				Detail: fmt.Sprintf(
					"reuse installed generation=%d policy_sha256=%s",
					state.Installed.Policy.Generation,
					state.Installed.PolicySHA256,
				),
				Target: installedReleaseTrustRoot,
			},
		)
	}

	if !state.ManifestSignerAuthorized {
		detail := state.Error
		if detail == "" {
			detail = "manifest signer is not authorized by the effective FI release-trust policy"
		}
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "RELEASE TRUST",
				Detail:    detail,
				Target:    "release manifest signer",
			},
		)
		return
	}

	plan.Actions = append(
		plan.Actions,
		PlanAction{
			Action:    planActionNoChange,
			Authority: "RELEASE TRUST",
			Detail: fmt.Sprintf(
				"manifest signer id=%s is active in effective policy source=%s",
				state.ManifestSignerID,
				state.EffectivePolicySource,
			),
			Target: "release manifest signer",
		},
	)
}

func planReleaseTrustACL(
	plan *InstallPlan,
	report Report,
) {
	if !report.ReleaseTrust.Installed.Present {
		return
	}
	check, found := findCheck(
		report,
		"FI release trust directory desired ACL contract",
	)
	if found && check.Status == checkPass {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "RELEASE TRUST",
				Detail:    check.Detail,
				Target:    "release-trust ACL",
			},
		)
		return
	}
	detail := "protected administrative-only release-trust ACL is not proven"
	if found && strings.TrimSpace(check.Detail) != "" {
		detail = check.Detail
	}
	plan.Actions = append(
		plan.Actions,
		PlanAction{
			Action:    planActionReconcile,
			Authority: "RELEASE TRUST",
			Detail:    detail,
			Target:    "release-trust ACL",
		},
	)
}

func planPackage(
	plan *InstallPlan,
	report Report,
) {
	if !report.Package.ManifestValid {
		detail := "release manifest is missing or invalid"
		if report.Package.Error != "" {
			detail = report.Package.Error
		}
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    detail,
				Target:    "manifest.json",
			},
		)
		return
	}

	if !report.Package.PayloadHashesMatch {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"one or more files under %s are missing, indirect, non-regular, or do not match reviewed manifest release_id=%s",
					report.Package.PayloadRoot,
					report.Package.ReleaseID,
				),
				Target: "release payload",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"all five bin payload files exactly match reviewed manifest release_id=%s",
					report.Package.ReleaseID,
				),
				Target: "release payload",
			},
		)
	}

	installedPresenceUnknown := false
	installedAllAbsent := len(report.Binaries) != 0
	installedAnyPresent := false

	for _, binary := range report.Binaries {
		switch binary.Presence {
		case presenceAbsent:
			// Keep installedAllAbsent true.
		case presencePresent:
			installedAllAbsent = false
			installedAnyPresent = true
		case presenceUnknown:
			installedAllAbsent = false
			installedPresenceUnknown = true
		default:
			// Backward-compatible handling for synthetic/older report fixtures.
			if strings.TrimSpace(binary.SHA256) != "" &&
				binary.SHA256 != notKnown {
				installedAllAbsent = false
				installedAnyPresent = true
			} else {
				installedAllAbsent = false
				installedPresenceUnknown = true
			}
		}
	}

	switch {
	case installedPresenceUnknown:
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    "one or more installed FI executable presence/hash states are unknown; FI will not infer absence or overwrite an unreadable runtime",
				Target:    "installed FI executables",
			},
		)
	case report.Package.InstalledHashesMatch:
		legacyRuntimePaths :=
			approval2LegacyRuntimePaths(
				report,
			)

		if len(legacyRuntimePaths) != 0 {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionReconcile,
					Authority: "PACKAGE",
					Detail: fmt.Sprintf(
						"installed FI runtime hashes match reviewed release_id=%s, but authoritative interrupted executable-name migration state requires controlled runtime convergence and retirement of hash-sealed legacy runtime(s): %s",
						report.Package.ReleaseID,
						strings.Join(
							legacyRuntimePaths,
							", ",
						),
					),
					Target: "installed FI executables",
				},
			)
		} else {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "PACKAGE",
					Detail: fmt.Sprintf(
						"installed FI runtime hashes exactly match reviewed manifest release_id=%s",
						report.Package.ReleaseID,
					),
					Target: "installed FI executables",
				},
			)
		}
	case installedAllAbsent && report.Package.PayloadHashesMatch:
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionCreate,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"authoritative local discovery confirmed all five FI runtime executables are absent; install reviewed release_id=%s after Approval 2",
					report.Package.ReleaseID,
				),
				Target: "installed FI executables",
			},
		)
	case installedAnyPresent && report.Package.PayloadHashesMatch:
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"installed runtime differs from reviewed release_id=%s; verified bin payload is available for an approved reconciliation",
					report.Package.ReleaseID,
				),
				Target: "installed FI executables",
			},
		)
	default:
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    "installed runtime state is incomplete and no safe manifest-verified installation/reconciliation path is proven",
				Target:    "installed FI executables",
			},
		)
	}

	if !report.Package.AuthenticodeFilesTrusted {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    "fi-install.exe and every executable under bin\\ must pass native WinVerifyTrust Authenticode verification against Windows trust before mutation is permitted",
				Target:    "installer/payload Authenticode",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "PACKAGE",
				Detail:    "fi-install.exe and every manifest-listed payload executable pass native WinVerifyTrust Authenticode verification",
				Target:    "installer/payload Authenticode",
			},
		)
	}

	if !report.Package.AuthenticodeSignerIdentitiesComplete {
		detail := "FI could not establish the primary Authenticode signer certificate/SPKI identity for every executable"
		if !report.Package.AuthenticodeFilesTrusted {
			detail = "primary Authenticode signer identities are not authoritative because native WinVerifyTrust did not establish Windows trust for every executable"
		}
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    detail,
				Target:    "Authenticode signer identity",
			},
		)
	} else if !report.Package.AuthenticodeSignersAuthorized {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    "Windows trust alone is insufficient: fi-install.exe and every manifest-listed payload must be signed by a certificate/SPKI listed in active_signers of the effective FI release-trust policy",
				Target:    "ISS Authenticode signer identity",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"fi-install.exe and every manifest-listed payload are Authenticode-signed by active FI release signer(s); installer signer_id=%s",
					report.Package.InstallerAuthenticodeSignerID,
				),
				Target: "ISS Authenticode signer identity",
			},
		)
	}

	if !report.Package.ManifestSignature.SignatureValid ||
		!report.Package.ManifestSignature.SignerChainTrusted {
		detail := report.Package.ManifestSignature.Error
		if detail == "" {
			detail = "manifest.p7s did not establish a valid detached signature and Windows-trusted code-signing certificate chain"
		}
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PACKAGE",
				Detail:    detail,
				Target:    "manifest detached signature",
			},
		)
	} else {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionNoChange,
				Authority: "PACKAGE",
				Detail: fmt.Sprintf(
					"manifest.json is covered by manifest.p7s; signer=%s cert_sha256=%s and the signer builds a Windows-trusted code-signing chain",
					report.Package.ManifestSignature.SignerSubject,
					report.Package.ManifestSignature.SignerCertSHA256,
				),
				Target: "manifest detached signature",
			},
		)

		if report.ReleaseTrust.ManifestSignerAuthorized {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "PACKAGE",
					Detail: fmt.Sprintf(
						"manifest signer is authorized by FI release-trust signer id=%s",
						report.ReleaseTrust.ManifestSignerID,
					),
					Target: "ISS release signer identity",
				},
			)
		} else {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "PACKAGE",
					Detail:    "manifest signer has valid Windows code-signing trust but is not authorized by the effective Iron Signal Systems release-trust policy",
					Target:    "ISS release signer identity",
				},
			)
		}
	}
}

func transportPKIComplete(report Report) bool {
	if strings.TrimSpace(report.Trust.VersionID) == "" {
		return false
	}

	required := map[string]bool{
		"transport root certificate":        false,
		"transport issuer certificate":      false,
		"source transport signing identity": false,
		"batch signing identity":            false,
		"transport CRL":                     false,
	}

	for _, state := range report.PKI {
		if _, ok := required[state.Name]; !ok {
			continue
		}
		if state.State != checkPass {
			return false
		}
		required[state.Name] = true
	}

	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func findADGMSA(
	states []ActiveDirectoryGMSAState,
	sam string,
) (ActiveDirectoryGMSAState, bool) {
	for _, state := range states {
		if strings.EqualFold(
			state.SAMAccountName,
			sam,
		) {
			return state, true
		}
	}
	return ActiveDirectoryGMSAState{}, false
}

func findLocalGMSA(
	states []GMSAState,
	sam string,
) (GMSAState, bool) {
	for _, state := range states {
		if strings.EqualFold(
			state.SAMAccountName,
			sam,
		) {
			return state, true
		}
	}
	return GMSAState{}, false
}

func findService(
	states []ServiceState,
	name string,
) (ServiceState, bool) {
	for _, state := range states {
		if state.Name == name {
			return state, true
		}
	}
	return ServiceState{}, false
}

func serviceObserved(state ServiceState) bool {
	if state.Presence != "" {
		return state.Presence == presencePresent
	}
	return strings.TrimSpace(state.Account) != "" ||
		strings.TrimSpace(state.BinaryPath) != "" ||
		(state.ManagedAccount != "" &&
			state.ManagedAccount != notKnown) ||
		(state.State != "" &&
			state.State != notKnown)
}

func findCheck(
	report Report,
	name string,
) (Check, bool) {
	for _, check := range report.Checks {
		if check.Name == name {
			return check, true
		}
	}
	return Check{}, false
}

func directRights(
	report Report,
	account string,
) []string {
	for _, state := range report.AccountRights {
		if strings.EqualFold(
			state.Account,
			account,
		) {
			return append(
				[]string(nil),
				state.Rights...,
			)
		}
	}
	return nil
}

func containsFold(
	values []string,
	expected string,
) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func exactRights(
	observed []string,
	required []string,
) bool {
	if len(observed) != len(required) {
		return false
	}
	for _, value := range required {
		if !containsFold(observed, value) {
			return false
		}
	}
	return true
}
