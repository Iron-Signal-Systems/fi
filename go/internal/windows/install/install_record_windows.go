// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	installRecordProduct = "FI Windows Source"
	installRecordRoot    = `C:\ProgramData\FI\install`
	installRecordVersion = "fi-install-record/1.0"

	installRecordMoveFileWriteThrough = 0x00000008
	installRecordFileSDDL             = "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)"
	installRecordMaximumBytes         = 4 << 20
)

var installRecordMoveFileExW = kernel32DLL.NewProc(
	"MoveFileExW",
)

type InstallRecord struct {
	Version         string                    `json:"version"`
	Product         string                    `json:"product"`
	TransactionID   string                    `json:"transaction_id"`
	TransactionKind string                    `json:"transaction_kind"`
	StartedAtUTC    string                    `json:"started_at_utc"`
	CompletedAtUTC  string                    `json:"completed_at_utc"`
	Result          string                    `json:"result"`
	Error           string                    `json:"error"`
	Host            InstallRecordHost         `json:"host"`
	Approval        InstallRecordApproval     `json:"approval"`
	Release         InstallRecordRelease      `json:"release"`
	Payloads        []InstallRecordPayload    `json:"payloads"`
	Applied         []InstallRecordApplied    `json:"applied"`
	Rollback        InstallRecordRollback     `json:"rollback"`
	Verification    InstallRecordVerification `json:"verification"`
}

type InstallRecordApproval struct {
	PlanMode          string                `json:"plan_mode"`
	PlanSHA256        string                `json:"plan_sha256"`
	Approval1Required bool                  `json:"approval_1_required"`
	Approval1Given    bool                  `json:"approval_1_given"`
	Approval2Required bool                  `json:"approval_2_required"`
	Approval2Given    bool                  `json:"approval_2_given"`
	Mutations         []InstallRecordAction `json:"mutations"`
}

type InstallRecordAction struct {
	Action    string `json:"action"`
	Authority string `json:"authority"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
}

type InstallRecordApplied struct {
	Authority string `json:"authority"`
	Target    string `json:"target"`
}

type InstallRecordCheck struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

type InstallRecordHost struct {
	BuildNumber uint32 `json:"build_number"`
	Computer    string `json:"computer"`
	DomainDNS   string `json:"domain_dns"`
	OSProfile   string `json:"os_profile"`
	ProductName string `json:"product_name"`
}

type InstallRecordPayload struct {
	Role                    string `json:"role"`
	Name                    string `json:"name"`
	ExpectedSHA256          string `json:"expected_sha256"`
	PackageSHA256           string `json:"package_sha256"`
	InstalledBeforeSHA256   string `json:"installed_before_sha256"`
	InstalledFinalSHA256    string `json:"installed_final_sha256"`
	SignerID                string `json:"signer_id"`
	SignerSubject           string `json:"signer_subject"`
	SignerCertificateSHA256 string `json:"signer_certificate_sha256"`
	SignerSPKISHA256        string `json:"signer_spki_sha256"`
	AuthenticodeTrusted     bool   `json:"authenticode_trusted"`
	SignerAuthorized        bool   `json:"signer_authorized"`
}

type InstallRecordRelease struct {
	ReleaseID                           string `json:"release_id"`
	PackageRoot                         string `json:"package_root"`
	ManifestPath                        string `json:"manifest_path"`
	ManifestSHA256                      string `json:"manifest_sha256"`
	ManifestValid                       bool   `json:"manifest_valid"`
	ManifestSignaturePath               string `json:"manifest_signature_path"`
	ManifestSignatureValid              bool   `json:"manifest_signature_valid"`
	ManifestSignerChainTrusted          bool   `json:"manifest_signer_chain_trusted"`
	ManifestSignerAuthorized            bool   `json:"manifest_signer_authorized"`
	ManifestSignerID                    string `json:"manifest_signer_id"`
	ManifestSignerSubject               string `json:"manifest_signer_subject"`
	ManifestSignerCertificateSHA256     string `json:"manifest_signer_certificate_sha256"`
	ManifestSignerSPKISHA256            string `json:"manifest_signer_spki_sha256"`
	InstallerPath                       string `json:"installer_path"`
	InstallerSHA256                     string `json:"installer_sha256"`
	InstallerAuthenticodeTrusted        bool   `json:"installer_authenticode_trusted"`
	InstallerSignerAuthorized           bool   `json:"installer_signer_authorized"`
	InstallerSignerID                   string `json:"installer_signer_id"`
	InstallerSignerSubject              string `json:"installer_signer_subject"`
	InstallerSignerCertificateSHA256    string `json:"installer_signer_certificate_sha256"`
	InstallerSignerSPKISHA256           string `json:"installer_signer_spki_sha256"`
	PackagePolicyPresent                bool   `json:"package_policy_present"`
	PackagePolicyGeneration             uint64 `json:"package_policy_generation"`
	PackagePolicySHA256                 string `json:"package_policy_sha256"`
	InstalledPolicyPresentBefore        bool   `json:"installed_policy_present_before"`
	InstalledPolicyGenerationBefore     uint64 `json:"installed_policy_generation_before"`
	InstalledPolicySHA256Before         string `json:"installed_policy_sha256_before"`
	InstalledPolicyPresentFinal         bool   `json:"installed_policy_present_final"`
	InstalledPolicyGenerationFinal      uint64 `json:"installed_policy_generation_final"`
	InstalledPolicySHA256Final          string `json:"installed_policy_sha256_final"`
	PolicyAuthorityConfigured           bool   `json:"policy_authority_configured"`
	PolicyAuthoritySPKISHA256           string `json:"policy_authority_spki_sha256"`
	PackagePolicyAuthorityPinned        bool   `json:"package_policy_authority_pinned"`
	InstalledPolicyAuthorityPinnedFinal bool   `json:"installed_policy_authority_pinned_final"`
}
type InstallRecordRollback struct {
	Attempted bool     `json:"attempted"`
	Errors    []string `json:"errors"`
}

type InstallRecordVerification struct {
	PostMutation InstallRecordVerificationState `json:"post_mutation"`
	Final        InstallRecordVerificationState `json:"final"`
}

type InstallRecordVerificationState struct {
	Available           bool                  `json:"available"`
	DiscoveryFailures   []InstallRecordCheck  `json:"discovery_failures"`
	PlanBlockers        []InstallRecordAction `json:"plan_blockers"`
	RemainingMutations  []InstallRecordAction `json:"remaining_mutations"`
	ConvergedToNoChange bool                  `json:"converged_to_no_change"`
}

type installRecordContext struct {
	Approval      ApprovalState
	Before        Report
	Plan          InstallPlan
	StartedAtUTC  time.Time
	TransactionID string
}

func newInstallRecordContext(
	before Report,
	plan InstallPlan,
	approval ApprovalState,
	transactionID string,
	started time.Time,
) installRecordContext {
	return installRecordContext{
		Approval:      approval,
		Before:        before,
		Plan:          plan,
		StartedAtUTC:  started,
		TransactionID: transactionID,
	}
}

func buildInstallRecord(
	context installRecordContext,
	applied []AppliedMutation,
	result string,
	resultError error,
	rollbackAttempted bool,
	rollbackErrors []string,
	postMutation *Report,
	postMutationPlan *InstallPlan,
	final Report,
	finalPlan InstallPlan,
) InstallRecord {
	record := InstallRecord{
		Version:         installRecordVersion,
		Product:         installRecordProduct,
		TransactionID:   auditValue(context.TransactionID),
		TransactionKind: installRecordTransactionKind(context.Plan),
		StartedAtUTC:    context.StartedAtUTC.UTC().Format(time.RFC3339Nano),
		CompletedAtUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		Result:          auditValue(result),
		Error:           "no_record",
		Host: InstallRecordHost{
			BuildNumber: context.Before.Host.BuildNumber,
			Computer:    auditValue(context.Before.Host.Computer),
			DomainDNS:   auditValue(context.Before.Host.DomainDNS),
			OSProfile:   auditValue(context.Before.Host.Profile.Name),
			ProductName: auditValue(context.Before.Host.ProductName),
		},
		Approval: InstallRecordApproval{
			PlanMode:          auditValue(context.Plan.Mode),
			PlanSHA256:        auditValue(context.Approval.PlanSHA256),
			Approval1Required: context.Approval.Approval1Required,
			Approval1Given:    context.Approval.Approval1Given,
			Approval2Required: context.Approval.Approval2Required,
			Approval2Given:    context.Approval.Approval2Given,
			Mutations:         approvedInstallRecordMutations(context.Plan),
		},
		Release:  buildInstallRecordRelease(context.Before, final),
		Payloads: buildInstallRecordPayloads(context.Before, final),
		Applied:  appliedInstallRecordMutations(applied),
		Rollback: InstallRecordRollback{
			Attempted: rollbackAttempted,
			Errors:    append([]string{}, rollbackErrors...),
		},
		Verification: InstallRecordVerification{
			PostMutation: unavailableInstallRecordVerification(),
			Final:        buildInstallRecordVerification(final, finalPlan),
		},
	}

	if resultError != nil {
		record.Error = resultError.Error()
	}
	if record.Applied == nil {
		record.Applied = make([]InstallRecordApplied, 0)
	}
	if record.Rollback.Errors == nil {
		record.Rollback.Errors = make([]string, 0)
	}

	if postMutation != nil &&
		postMutationPlan != nil {
		record.Verification.PostMutation =
			buildInstallRecordVerification(
				*postMutation,
				*postMutationPlan,
			)
	}

	return record
}

func installRecordTransactionKind(
	plan InstallPlan,
) string {
	for _, action := range plan.Actions {
		if planActionMutates(
			action.Action,
		) {
			return "mutation"
		}
	}
	return "verified_no_op"
}

func approvedInstallRecordMutations(
	plan InstallPlan,
) []InstallRecordAction {
	mutations := make(
		[]InstallRecordAction,
		0,
	)
	for _, action := range plan.Actions {
		if !planActionMutates(
			action.Action,
		) {
			continue
		}
		mutations = append(
			mutations,
			installRecordAction(
				action,
			),
		)
	}
	return mutations
}

func appliedInstallRecordMutations(
	applied []AppliedMutation,
) []InstallRecordApplied {
	result := make(
		[]InstallRecordApplied,
		0,
		len(applied),
	)
	for _, mutation := range applied {
		result = append(
			result,
			InstallRecordApplied{
				Authority: auditValue(
					mutation.Authority,
				),
				Target: auditValue(
					mutation.Target,
				),
			},
		)
	}
	return result
}

func installRecordAction(
	action PlanAction,
) InstallRecordAction {
	return InstallRecordAction{
		Action: auditValue(
			action.Action,
		),
		Authority: auditValue(
			action.Authority,
		),
		Target: auditValue(
			action.Target,
		),
		Detail: auditValue(
			action.Detail,
		),
	}
}

func buildInstallRecordPayloads(
	before Report,
	final Report,
) []InstallRecordPayload {
	beforeInstalled := make(map[string]string)
	for _, file := range before.Package.Files {
		beforeInstalled[file.Role] = file.ActualSHA256
	}

	finalInstalled := make(map[string]string)
	for _, file := range final.Package.Files {
		finalInstalled[file.Role] = file.ActualSHA256
	}

	payloads := make(
		[]InstallRecordPayload,
		0,
		len(before.Package.Files),
	)
	for _, file := range before.Package.Files {
		payloads = append(
			payloads,
			InstallRecordPayload{
				Role:                    auditValue(file.Role),
				Name:                    auditValue(file.Name),
				ExpectedSHA256:          auditValue(file.ExpectedSHA256),
				PackageSHA256:           auditValue(file.PayloadSHA256),
				InstalledBeforeSHA256:   auditValue(beforeInstalled[file.Role]),
				InstalledFinalSHA256:    auditValue(finalInstalled[file.Role]),
				SignerID:                auditValue(file.PayloadAuthenticodeSignerID),
				SignerSubject:           auditValue(file.PayloadAuthenticodeSignerSubject),
				SignerCertificateSHA256: auditValue(file.PayloadAuthenticodeSignerCertSHA256),
				SignerSPKISHA256:        auditValue(file.PayloadAuthenticodeSignerSPKISHA256),
				AuthenticodeTrusted:     file.PayloadAuthenticodeTrusted,
				SignerAuthorized:        file.PayloadAuthenticodeSignerAuthorized,
			},
		)
	}

	sort.Slice(
		payloads,
		func(i int, j int) bool {
			if payloads[i].Role == payloads[j].Role {
				return payloads[i].Name < payloads[j].Name
			}
			return payloads[i].Role < payloads[j].Role
		},
	)

	return payloads
}

func buildInstallRecordRelease(
	before Report,
	final Report,
) InstallRecordRelease {
	return InstallRecordRelease{
		ReleaseID:                       auditValue(before.Package.ReleaseID),
		PackageRoot:                     auditValue(before.Package.Root),
		ManifestPath:                    auditValue(before.Package.ManifestPath),
		ManifestSHA256:                  auditFileSHA256(before.Package.ManifestPath),
		ManifestValid:                   before.Package.ManifestValid,
		ManifestSignaturePath:           auditValue(before.Package.ManifestSignaturePath),
		ManifestSignatureValid:          before.Package.ManifestSignature.SignatureValid,
		ManifestSignerChainTrusted:      before.Package.ManifestSignature.SignerChainTrusted,
		ManifestSignerAuthorized:        before.ReleaseTrust.ManifestSignerAuthorized,
		ManifestSignerID:                auditValue(before.ReleaseTrust.ManifestSignerID),
		ManifestSignerSubject:           auditValue(before.Package.ManifestSignature.SignerSubject),
		ManifestSignerCertificateSHA256: auditValue(before.Package.ManifestSignature.SignerCertSHA256),
		ManifestSignerSPKISHA256:        auditValue(before.Package.ManifestSignature.SignerSPKISHA256),
		InstallerPath:                   auditValue(before.Package.InstallerPath),
		InstallerSHA256:                 auditFileSHA256(before.Package.InstallerPath),
		InstallerAuthenticodeTrusted:    before.Package.InstallerAuthenticodeTrusted,
		InstallerSignerAuthorized:       before.Package.InstallerAuthenticodeSignerAuthorized,
		InstallerSignerID:               auditValue(before.Package.InstallerAuthenticodeSignerID),
		InstallerSignerSubject:          auditValue(before.Package.InstallerAuthenticodeSignerSubject),
		InstallerSignerCertificateSHA256: auditValue(
			before.Package.InstallerAuthenticodeSignerCertSHA256,
		),
		InstallerSignerSPKISHA256:           auditValue(before.Package.InstallerAuthenticodeSignerSPKISHA256),
		PackagePolicyPresent:                before.ReleaseTrust.Package.Present,
		PackagePolicyGeneration:             before.ReleaseTrust.Package.Policy.Generation,
		PackagePolicySHA256:                 auditValue(before.ReleaseTrust.Package.PolicySHA256),
		InstalledPolicyPresentBefore:        before.ReleaseTrust.Installed.Present,
		InstalledPolicyGenerationBefore:     before.ReleaseTrust.Installed.Policy.Generation,
		InstalledPolicySHA256Before:         auditValue(before.ReleaseTrust.Installed.PolicySHA256),
		InstalledPolicyPresentFinal:         final.ReleaseTrust.Installed.Present,
		InstalledPolicyGenerationFinal:      final.ReleaseTrust.Installed.Policy.Generation,
		InstalledPolicySHA256Final:          auditValue(final.ReleaseTrust.Installed.PolicySHA256),
		PolicyAuthorityConfigured:           before.ReleaseTrust.BootstrapAuthorityConfigured,
		PolicyAuthoritySPKISHA256:           auditValue(before.ReleaseTrust.BootstrapAuthoritySPKISHA256),
		PackagePolicyAuthorityPinned:        before.ReleaseTrust.Package.AuthorityPinned,
		InstalledPolicyAuthorityPinnedFinal: final.ReleaseTrust.Installed.AuthorityPinned,
	}
}

func buildInstallRecordVerification(
	report Report,
	plan InstallPlan,
) InstallRecordVerificationState {
	state := InstallRecordVerificationState{
		Available:          true,
		DiscoveryFailures:  make([]InstallRecordCheck, 0),
		PlanBlockers:       make([]InstallRecordAction, 0),
		RemainingMutations: make([]InstallRecordAction, 0),
	}

	for _, check := range report.Checks {
		if check.Status == checkFail {
			state.DiscoveryFailures = append(
				state.DiscoveryFailures,
				InstallRecordCheck{
					Status: auditValue(
						check.Status,
					),
					Name: auditValue(
						check.Name,
					),
					Detail: auditValue(
						check.Detail,
					),
				},
			)
		}
	}

	for _, action := range plan.Actions {
		if action.Action == planActionBlocked {
			state.PlanBlockers = append(
				state.PlanBlockers,
				installRecordAction(
					action,
				),
			)
		}
		if planActionMutates(action.Action) {
			state.RemainingMutations = append(
				state.RemainingMutations,
				installRecordAction(
					action,
				),
			)
		}
	}

	state.ConvergedToNoChange =
		len(state.DiscoveryFailures) == 0 &&
			len(state.PlanBlockers) == 0 &&
			len(state.RemainingMutations) == 0

	return state
}

func unavailableInstallRecordVerification() InstallRecordVerificationState {
	return InstallRecordVerificationState{
		Available:           false,
		DiscoveryFailures:   make([]InstallRecordCheck, 0),
		PlanBlockers:        make([]InstallRecordAction, 0),
		RemainingMutations:  make([]InstallRecordAction, 0),
		ConvergedToNoChange: false,
	}
}

func prepareInstallRecordRoot() error {
	if err := os.MkdirAll(
		installRecordRoot,
		0o700,
	); err != nil {
		return fmt.Errorf(
			"create FI install-record root: %w",
			err,
		)
	}

	info, err := os.Lstat(
		installRecordRoot,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect FI install-record root: %w",
			err,
		)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return fmt.Errorf(
			"FI install-record root must name a real directory",
		)
	}

	sddl := desiredProtectedDirectorySDDL(
		nil,
	)
	if err := withEnabledProcessPrivilege(
		"SeRestorePrivilege",
		func() error {
			return setNamedSecurityDescriptorFromSDDL(
				installRecordRoot,
				sddl,
			)
		},
	); err != nil {
		return fmt.Errorf(
			"secure FI install-record root: %w",
			err,
		)
	}

	return nil
}

func writeInstallRecord(
	record InstallRecord,
) (
	string,
	string,
	error,
) {
	if err := prepareInstallRecordRoot(); err != nil {
		return "", "", err
	}

	encoded, err := json.MarshalIndent(
		record,
		"",
		"  ",
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"encode FI install record: %w",
			err,
		)
	}
	encoded = append(
		encoded,
		'\n',
	)

	name := "install-" +
		installRecordFileToken(
			record.TransactionID,
		) +
		".json"
	finalPath := filepath.Join(
		installRecordRoot,
		name,
	)
	tempPath := filepath.Join(
		installRecordRoot,
		"."+name+".open",
	)

	if _, err := os.Lstat(finalPath); err == nil {
		return "", "", fmt.Errorf(
			"FI install record already exists: %s",
			finalPath,
		)
	} else if !os.IsNotExist(err) {
		return "", "", fmt.Errorf(
			"inspect FI install record destination: %w",
			err,
		)
	}

	file, err := os.OpenFile(
		tempPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"create FI install record temporary file: %w",
			err,
		)
	}

	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.Remove(
				tempPath,
			)
		}
	}()

	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return "", "", fmt.Errorf(
			"write FI install record: %w",
			err,
		)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", "", fmt.Errorf(
			"flush FI install record: %w",
			err,
		)
	}
	if err := file.Close(); err != nil {
		return "", "", fmt.Errorf(
			"close FI install record: %w",
			err,
		)
	}

	if err := withEnabledProcessPrivilege(
		"SeRestorePrivilege",
		func() error {
			return setNamedSecurityDescriptorFromSDDL(
				tempPath,
				installRecordFileSDDL,
			)
		},
	); err != nil {
		return "", "", fmt.Errorf(
			"secure FI install record temporary file: %w",
			err,
		)
	}

	if err := moveInstallRecordWriteThrough(
		tempPath,
		finalPath,
	); err != nil {
		return "", "", err
	}
	cleanupTemp = false

	if err := verifyWrittenInstallRecord(
		finalPath,
		record,
	); err != nil {
		return finalPath, "", err
	}

	hash, err := fileSHA256(
		finalPath,
	)
	if err != nil {
		return finalPath, "", fmt.Errorf(
			"hash final FI install record: %w",
			err,
		)
	}

	return finalPath, hash, nil
}

func verifyWrittenInstallRecord(
	path string,
	expected InstallRecord,
) error {
	raw, err := readBoundedFile(
		path,
		installRecordMaximumBytes,
	)
	if err != nil {
		return fmt.Errorf(
			"read back FI install record: %w",
			err,
		)
	}

	var observed InstallRecord
	if err := json.Unmarshal(
		raw,
		&observed,
	); err != nil {
		return fmt.Errorf(
			"parse written FI install record: %w",
			err,
		)
	}

	if observed.Version != installRecordVersion {
		return fmt.Errorf(
			"written FI install record version=%q expected=%q",
			observed.Version,
			installRecordVersion,
		)
	}
	if observed.TransactionID != expected.TransactionID {
		return fmt.Errorf(
			"written FI install record transaction_id=%q expected=%q",
			observed.TransactionID,
			expected.TransactionID,
		)
	}
	if observed.Result != expected.Result {
		return fmt.Errorf(
			"written FI install record result=%q expected=%q",
			observed.Result,
			expected.Result,
		)
	}
	if observed.Approval.PlanSHA256 !=
		expected.Approval.PlanSHA256 {
		return fmt.Errorf(
			"written FI install record plan_sha256=%q expected=%q",
			observed.Approval.PlanSHA256,
			expected.Approval.PlanSHA256,
		)
	}

	return nil
}

func moveInstallRecordWriteThrough(
	source string,
	destination string,
) error {
	sourcePointer, err := syscall.UTF16PtrFromString(
		source,
	)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.UTF16PtrFromString(
		destination,
	)
	if err != nil {
		return err
	}

	result, _, callErr := installRecordMoveFileExW.Call(
		uintptr(
			unsafe.Pointer(
				sourcePointer,
			),
		),
		uintptr(
			unsafe.Pointer(
				destinationPointer,
			),
		),
		uintptr(
			installRecordMoveFileWriteThrough,
		),
	)
	if result == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(
				0,
			) {
			return fmt.Errorf(
				"publish FI install record: %w",
				callErr,
			)
		}
		return fmt.Errorf(
			"MoveFileExW failed publishing FI install record",
		)
	}

	return nil
}

func installRecordFileToken(
	transactionID string,
) string {
	token := strings.TrimSpace(
		transactionID,
	)
	if token == "" {
		return "not_known"
	}

	var builder strings.Builder
	for _, character := range token {
		switch {
		case character >= '0' &&
			character <= '9':
			builder.WriteRune(
				character,
			)
		case character >= 'A' &&
			character <= 'Z':
			builder.WriteRune(
				character,
			)
		case character >= 'a' &&
			character <= 'z':
			builder.WriteRune(
				character,
			)
		case character == '-' ||
			character == '_' ||
			character == '.':
			builder.WriteRune(
				character,
			)
		default:
			builder.WriteRune(
				'_',
			)
		}
	}

	value := builder.String()
	if value == "" {
		return "not_known"
	}
	return value
}

func auditFileSHA256(
	path string,
) string {
	if strings.TrimSpace(
		path,
	) == "" {
		return "not_known"
	}
	hash, err := fileSHA256(
		path,
	)
	if err != nil {
		return "not_known"
	}
	return auditValue(
		hash,
	)
}

func auditValue(
	value string,
) string {
	value = strings.TrimSpace(
		value,
	)
	if value == "" {
		return "no_record"
	}
	return value
}
