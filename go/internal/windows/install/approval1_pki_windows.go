// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"strings"
)

type approval1PKIIdentityResult struct {
	CertificateSHA256 string
	Disposition       string
	TemplateName      string
	TemplateOID       string
}

type approval1PKIBackend interface {
	Enroll(
		contract pkiEnrollmentContract,
	) (pkiEnrollmentMutation, error)

	FindReusable(
		contract pkiEnrollmentContract,
	) (localMachinePKICertificate, bool, error)

	ResolveTemplateOID(
		templateName string,
	) (string, error)

	RollbackOwned(
		mutation pkiEnrollmentMutation,
	) error
}

type nativeApproval1PKIBackend struct {
	session *ldapSession
}

func (backend *nativeApproval1PKIBackend) Enroll(
	contract pkiEnrollmentContract,
) (pkiEnrollmentMutation, error) {
	return enrollMachineCertificateTemplateTracked(
		contract,
	)
}

func (backend *nativeApproval1PKIBackend) FindReusable(
	contract pkiEnrollmentContract,
) (localMachinePKICertificate, bool, error) {
	certificates, err := snapshotLocalMachinePKICertificates(
		contract.TemplateOID,
	)
	if err != nil {
		return localMachinePKICertificate{}, false, err
	}

	valid := make(
		[]localMachinePKICertificate,
		0,
		len(certificates),
	)

	for _, certificate := range certificates {
		if err := verifyTrackedPKIEnrollment(
			certificate,
			contract,
		); err != nil {
			continue
		}

		valid = append(
			valid,
			certificate,
		)
	}

	switch len(valid) {
	case 0:
		return localMachinePKICertificate{}, false, nil
	case 1:
		return valid[0], true, nil
	default:
		return localMachinePKICertificate{}, false, fmt.Errorf(
			"found %d valid LocalMachine\\MY certificates for template=%s OID=%s DNS=%s; FI refuses ambiguous automatic identity selection",
			len(valid),
			contract.TemplateName,
			contract.TemplateOID,
			contract.ExpectedDNS,
		)
	}
}

func (backend *nativeApproval1PKIBackend) ResolveTemplateOID(
	templateName string,
) (string, error) {
	if backend == nil ||
		backend.session == nil ||
		backend.session.handle == 0 {
		return "", errors.New(
			"Approval 1 PKI LDAP session is unavailable",
		)
	}

	rootDSE, err := backend.session.rootDSE()
	if err != nil {
		return "", fmt.Errorf(
			"discover configuration naming context for PKI template %s: %w",
			templateName,
			err,
		)
	}

	configurationNamingContext := strings.TrimSpace(
		rootDSE["configurationNamingContext"],
	)

	if configurationNamingContext == "" {
		return "", errors.New(
			"configuration naming context is unavailable",
		)
	}

	return resolveCertificateTemplateOID(
		backend.session,
		configurationNamingContext,
		templateName,
	)
}

func (backend *nativeApproval1PKIBackend) RollbackOwned(
	mutation pkiEnrollmentMutation,
) error {
	return rollbackOwnedPKIEnrollment(
		mutation,
	)
}

func approval1PKIExpectedDNS(
	before Report,
) (string, error) {
	computer := strings.TrimSpace(
		before.Host.Computer,
	)

	domain := strings.TrimSpace(
		before.Host.DomainDNS,
	)

	if computer == "" ||
		strings.EqualFold(
			computer,
			notKnown,
		) {
		return "", errors.New(
			"computer name is unavailable for FI certificate enrollment",
		)
	}

	if domain == "" ||
		strings.EqualFold(
			domain,
			notKnown,
		) {
		return "", errors.New(
			"DNS domain name is unavailable for FI certificate enrollment",
		)
	}

	computer = strings.TrimSuffix(
		computer,
		".",
	)

	domain = strings.Trim(
		domain,
		".",
	)

	if strings.Contains(
		computer,
		".",
	) {
		expectedSuffix := "." + strings.ToLower(
			domain,
		)

		lowerComputer := strings.ToLower(
			computer,
		)

		if lowerComputer != strings.ToLower(domain) &&
			!strings.HasSuffix(
				lowerComputer,
				expectedSuffix,
			) {
			return "", fmt.Errorf(
				"computer DNS name %q is not within discovered domain %q",
				computer,
				domain,
			)
		}

		return computer, nil
	}

	return computer + "." + domain, nil
}

func ensureApproval1PKIIdentity(
	backend approval1PKIBackend,
	contract pkiEnrollmentContract,
) (approval1PKIIdentityResult, error) {
	existing, found, err := backend.FindReusable(
		contract,
	)
	if err != nil {
		return approval1PKIIdentityResult{}, fmt.Errorf(
			"discover reusable %s identity: %w",
			contract.TemplateName,
			err,
		)
	}

	if found {
		return approval1PKIIdentityResult{
			CertificateSHA256: existing.CertificateSHA256,
			Disposition:       "reused",
			TemplateName:      contract.TemplateName,
			TemplateOID:       contract.TemplateOID,
		}, nil
	}

	mutation, enrollErr := backend.Enroll(
		contract,
	)

	if enrollErr != nil {
		if mutation.Owned {
			rollbackErr := backend.RollbackOwned(
				mutation,
			)

			if rollbackErr != nil {
				return approval1PKIIdentityResult{}, errors.Join(
					fmt.Errorf(
						"%s enrollment failed before durable acceptance: %w",
						contract.TemplateName,
						enrollErr,
					),
					fmt.Errorf(
						"rollback exact transaction-owned %s certificate/key: %w",
						contract.TemplateName,
						rollbackErr,
					),
				)
			}
		}

		return approval1PKIIdentityResult{}, fmt.Errorf(
			"%s enrollment failed before durable acceptance: %w",
			contract.TemplateName,
			enrollErr,
		)
	}

	if !mutation.Owned {
		return approval1PKIIdentityResult{}, fmt.Errorf(
			"%s enrollment returned success without exact certificate/key transaction ownership",
			contract.TemplateName,
		)
	}

	if strings.TrimSpace(
		mutation.Certificate.CertificateSHA256,
	) == "" {
		rollbackErr := backend.RollbackOwned(
			mutation,
		)

		cause := fmt.Errorf(
			"%s enrollment returned an owned certificate without a DER SHA-256 identity",
			contract.TemplateName,
		)

		if rollbackErr != nil {
			return approval1PKIIdentityResult{}, errors.Join(
				cause,
				fmt.Errorf(
					"rollback exact transaction-owned %s certificate/key: %w",
					contract.TemplateName,
					rollbackErr,
				),
			)
		}

		return approval1PKIIdentityResult{}, cause
	}

	// enrollMachineCertificateTemplateTracked has already completed the
	// certificate contract, private-key policy, chain, and revocation checks.
	// Crossing this point accepts the identity as durable. Do not return a
	// rollback handle for unrelated later installer failures.
	return approval1PKIIdentityResult{
		CertificateSHA256: mutation.Certificate.CertificateSHA256,
		Disposition:       "enrolled",
		TemplateName:      contract.TemplateName,
		TemplateOID:       contract.TemplateOID,
	}, nil
}

func executeApproval1PKIEnrollmentTransactionWithBackend(
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	backend approval1PKIBackend,
) (Approval1PKITransactionResult, error) {
	if backend == nil {
		return Approval1PKITransactionResult{}, errors.New(
			"Approval 1 PKI backend is required",
		)
	}

	if before.Host.BuildNumber != 14393 {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"Approval 1 PKI enrollment is characterized only for Windows Server 2016 build 14393; observed build=%d",
			before.Host.BuildNumber,
		)
	}

	if !before.Host.Elevated {
		return Approval1PKITransactionResult{}, errors.New(
			"Approval 1 PKI enrollment requires an elevated administrator session",
		)
	}

	if before.Join.Status != "domain" {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"Approval 1 PKI enrollment requires a domain-joined source; observed status=%s",
			valueOrNotKnown(
				before.Join.Status,
			),
		)
	}

	if plan.HasBlockers() {
		return Approval1PKITransactionResult{}, errors.New(
			"plan contains blockers",
		)
	}

	if plan.HasQuestions() {
		return Approval1PKITransactionResult{}, errors.New(
			"plan still contains unanswered questions",
		)
	}

	if !planHasMutationAuthority(
		plan,
		"PKI",
	) {
		return Approval1PKITransactionResult{}, errors.New(
			"plan does not authorize an Approval 1 PKI mutation",
		)
	}

	choice := strings.ToLower(
		strings.TrimSpace(
			inputs.PKIChoice,
		),
	)

	if choice != "enroll" {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"Approval 1 native PKI mutation currently supports only -pki-choice enroll; observed choice=%q",
			inputs.PKIChoice,
		)
	}

	expectedDNS, err := approval1PKIExpectedDNS(
		before,
	)
	if err != nil {
		return Approval1PKITransactionResult{}, err
	}

	// Resolve both deployment-specific template OIDs before any certificate
	// mutation. FI never substitutes hard-coded lab OIDs for AD authority.
	transportOID, err := backend.ResolveTemplateOID(
		fiTransportClientTemplateName,
	)
	if err != nil {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"resolve %s template OID: %w",
			fiTransportClientTemplateName,
			err,
		)
	}

	batchOID, err := backend.ResolveTemplateOID(
		fiBatchSigningTemplateName,
	)
	if err != nil {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"resolve %s template OID: %w",
			fiBatchSigningTemplateName,
			err,
		)
	}

	transportContract := pkiEnrollmentContract{
		ExpectedDNS:  expectedDNS,
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  transportOID,
	}

	batchContract := pkiEnrollmentContract{
		ExpectedDNS:  expectedDNS,
		TemplateName: fiBatchSigningTemplateName,
		TemplateOID:  batchOID,
	}

	if err := validatePKIEnrollmentContract(
		transportContract,
	); err != nil {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"validate transport enrollment contract: %w",
			err,
		)
	}

	if err := validatePKIEnrollmentContract(
		batchContract,
	); err != nil {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"validate batch-signing enrollment contract: %w",
			err,
		)
	}

	transport, err := ensureApproval1PKIIdentity(
		backend,
		transportContract,
	)
	if err != nil {
		return Approval1PKITransactionResult{}, fmt.Errorf(
			"establish durable transport identity: %w",
			err,
		)
	}

	// The transport identity has crossed its PKI-local acceptance boundary.
	// From here onward it is durable even if batch enrollment fails.
	result := Approval1PKITransactionResult{
		Applied: true,
		Detail: fmt.Sprintf(
			"transport=%s:%s",
			transport.Disposition,
			transport.CertificateSHA256,
		),
		Durable: true,
	}

	batch, err := ensureApproval1PKIIdentity(
		backend,
		batchContract,
	)
	if err != nil {
		result.Detail += "; batch=failed-before-durable-acceptance"

		return result, fmt.Errorf(
			"establish durable batch-signing identity after transport identity became durable: %w",
			err,
		)
	}

	result.Detail = fmt.Sprintf(
		"transport=%s:%s; batch=%s:%s",
		transport.Disposition,
		transport.CertificateSHA256,
		batch.Disposition,
		batch.CertificateSHA256,
	)

	return result, nil
}

func resolveCertificateTemplateOID(
	session *ldapSession,
	configurationNamingContext string,
	templateName string,
) (string, error) {
	if session == nil ||
		session.handle == 0 {
		return "", errors.New(
			"LDAP session is unavailable",
		)
	}

	configurationNamingContext = strings.TrimSpace(
		configurationNamingContext,
	)

	templateName = strings.TrimSpace(
		templateName,
	)

	if configurationNamingContext == "" {
		return "", errors.New(
			"configuration naming context is required",
		)
	}

	if templateName == "" {
		return "", errors.New(
			"certificate template name is required",
		)
	}

	base := fmt.Sprintf(
		"CN=Certificate Templates,CN=Public Key Services,CN=Services,%s",
		configurationNamingContext,
	)

	filter := fmt.Sprintf(
		"(&(objectClass=pKICertificateTemplate)(cn=%s))",
		escapeLDAPFilterValue(
			templateName,
		),
	)

	entry, result, err := session.searchSingleEntry(
		base,
		uint32(
			ldapScopeOneLevel,
		),
		filter,
		[]string{
			"cn",
			"msPKI-Cert-Template-OID",
		},
	)

	if result != 0 {
		defer ldapMsgFreeProc.Call(
			result,
		)
	}

	if err != nil {
		return "", err
	}

	observedName, err := session.getStringValue(
		entry,
		"cn",
	)
	if err != nil {
		return "", err
	}

	if !strings.EqualFold(
		strings.TrimSpace(
			observedName,
		),
		templateName,
	) {
		return "", fmt.Errorf(
			"certificate template CN expected=%q observed=%q",
			templateName,
			observedName,
		)
	}

	oid, err := session.getStringValue(
		entry,
		"msPKI-Cert-Template-OID",
	)
	if err != nil {
		return "", err
	}

	oid = strings.TrimSpace(
		oid,
	)

	if oid == "" {
		return "", fmt.Errorf(
			"certificate template %s has an empty msPKI-Cert-Template-OID",
			templateName,
		)
	}

	return oid, nil
}
