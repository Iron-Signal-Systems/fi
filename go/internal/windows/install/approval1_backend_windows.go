// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

type approval1PKIHandoff struct {
	BatchCertificateSHA256     string
	BatchTemplateOID           string
	CRLDestinationPath         string
	CRLDistributionPoint       string
	CRLNextUpdate              string
	CRLSHA256                  string
	CRLThisUpdate              string
	RootCertificateSHA256      string
	TransportCertificateSHA256 string
	TransportIssuerSHA256      string
	TransportTemplateOID       string
}

type server2016Approval1Backend struct {
	handoff approval1PKIHandoff
	inputs  PlanInputs
	pki     nativeApproval1PKIBackend
	session *ldapSession
}

var _ approval1ControllerBackend = (*server2016Approval1Backend)(nil)

func (backend *server2016Approval1Backend) ApplyPKI(
	before Report,
	plan InstallPlan,
) (Approval1PKITransactionResult, error) {
	if backend == nil || backend.session == nil {
		return Approval1PKITransactionResult{}, errors.New(
			"Server 2016 Approval 1 backend is unavailable",
		)
	}

	result, err := executeApproval1PKIEnrollmentTransactionWithBackend(
		before,
		plan,
		backend.inputs,
		&backend.pki,
	)
	if err != nil {
		return result, err
	}

	identityHandoff, err := discoverApproval1PKIIdentityHandoff(
		before,
		&backend.pki,
	)
	if err != nil {
		return result, fmt.Errorf(
			"rediscover durable Approval 1 PKI identities: %w",
			err,
		)
	}

	trustMaterial, err := deriveApproval1TransportTrustMaterial(
		identityHandoff.TransportCertificateSHA256,
	)
	if err != nil {
		return result, fmt.Errorf(
			"derive durable Approval 1 transport trust material: %w",
			err,
		)
	}

	crlMaterial, err := acquireApproval1TransportCRL(
		backend.session,
		trustMaterial,
		time.Now(),
	)
	if err != nil {
		return result, fmt.Errorf(
			"acquire durable Approval 1 transport CRL material: %w",
			err,
		)
	}

	handoff, err := finalizeApproval1PKIHandoff(
		identityHandoff,
		trustMaterial,
		crlMaterial,
	)
	if err != nil {
		return result, fmt.Errorf(
			"finalize post-Approval-1 durable PKI handoff: %w",
			err,
		)
	}

	backend.handoff = handoff
	return result, nil
}

func (backend *server2016Approval1Backend) BuildPlan(
	report Report,
	inputs PlanInputs,
) InstallPlan {
	plan := BuildPlanWithInputs(
		report,
		inputs,
	)

	if !backend.handoff.complete() {
		return plan
	}

	if report.Trust.Presence != presenceAbsent {
		return plan
	}

	return applyApproval1PKIHandoffToPlan(
		report,
		plan,
		backend.handoff,
	)
}

func (backend *server2016Approval1Backend) Close() {
	if backend == nil || backend.session == nil {
		return
	}

	backend.session.close()
	backend.session = nil
	backend.pki.session = nil
}

func (backend *server2016Approval1Backend) Create(
	report Report,
	identity DesiredFIIdentity,
) (ActiveDirectoryGMSAState, bool, error) {
	if backend == nil || backend.session == nil {
		return ActiveDirectoryGMSAState{}, false, errors.New(
			"Server 2016 Approval 1 LDAP backend is unavailable",
		)
	}

	return createFIGroupManagedServiceAccountTracked(
		backend.session,
		report,
		identity,
	)
}

func (backend *server2016Approval1Backend) Rediscover() Report {
	return Discover()
}

func (backend *server2016Approval1Backend) RollbackCreated(
	report Report,
	identity DesiredFIIdentity,
) error {
	if backend == nil || backend.session == nil {
		return errors.New(
			"Server 2016 Approval 1 LDAP backend is unavailable",
		)
	}

	return deleteFIGroupManagedServiceAccountIfExact(
		backend.session,
		report,
		identity,
	)
}

func (handoff approval1PKIHandoff) complete() bool {
	return handoff.validate() == nil
}

func (handoff approval1PKIHandoff) validate() error {
	if err := validateApproval1PKIIdentityHandoff(
		handoff,
	); err != nil {
		return err
	}

	if !validSHA256Hex(
		handoff.TransportIssuerSHA256,
	) {
		return errors.New(
			"transport issuer certificate SHA-256 is invalid",
		)
	}

	if !validSHA256Hex(
		handoff.RootCertificateSHA256,
	) {
		return errors.New(
			"transport root certificate SHA-256 is invalid",
		)
	}

	if !validSHA256Hex(
		handoff.CRLSHA256,
	) {
		return errors.New(
			"transport CRL SHA-256 is invalid",
		)
	}

	if !approval1SupportedCRLDistributionPoint(
		handoff.CRLDistributionPoint,
	) {
		return errors.New(
			"transport CRL distribution point is missing or unsupported",
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(
			handoff.CRLDestinationPath,
		),
		approval1TransportCRLDestination,
	) {
		return fmt.Errorf(
			"transport CRL destination=%q does not match FI destination=%q",
			handoff.CRLDestinationPath,
			approval1TransportCRLDestination,
		)
	}

	thisUpdate, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(
			handoff.CRLThisUpdate,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"transport CRL thisUpdate is invalid: %w",
			err,
		)
	}

	nextUpdate, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(
			handoff.CRLNextUpdate,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"transport CRL nextUpdate is invalid: %w",
			err,
		)
	}

	if !nextUpdate.After(
		thisUpdate,
	) {
		return errors.New(
			"transport CRL nextUpdate must be later than thisUpdate",
		)
	}

	return nil
}

func applyApproval1PKIHandoffToPlan(
	report Report,
	plan InstallPlan,
	handoff approval1PKIHandoff,
) InstallPlan {
	if err := handoff.validate(); err != nil {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PKI",
				Detail: fmt.Sprintf(
					"Approval 1 durable PKI handoff is incomplete or invalid: %v",
					err,
				),
				Target: "FI transport PKI",
			},
		)
		return plan
	}

	if report.Trust.Presence != presenceAbsent {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PKI",
				Detail:    "Approval 1 durable PKI handoff may be consumed only while the local transport-trust configuration is authoritatively absent",
				Target:    "FI transport PKI",
			},
		)
		return plan
	}

	replaced := 0
	for index := range plan.Actions {
		action := plan.Actions[index]
		if action.Authority != "PKI" ||
			!planActionMutates(
				action.Action,
			) {
			continue
		}

		if action.Target != "FI transport PKI" {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "PKI",
					Detail: fmt.Sprintf(
						"Approval 1 durable PKI handoff cannot replace unexpected PKI mutation target %q",
						action.Target,
					),
					Target: action.Target,
				},
			)
			return plan
		}

		plan.Actions[index] = PlanAction{
			Action:    planActionNoChange,
			Authority: "PKI",
			Detail: fmt.Sprintf(
				"Approval 1 durable PKI accepted transport_cert_sha256=%s transport_template_oid=%s batch_cert_sha256=%s batch_template_oid=%s transport_issuer_sha256=%s root_cert_sha256=%s crl_sha256=%s; Approval 2 has no PKI mutation authority",
				handoff.TransportCertificateSHA256,
				handoff.TransportTemplateOID,
				handoff.BatchCertificateSHA256,
				handoff.BatchTemplateOID,
				handoff.TransportIssuerSHA256,
				handoff.RootCertificateSHA256,
				handoff.CRLSHA256,
			),
			Target: "FI transport PKI",
		}
		replaced++
	}

	if replaced != 1 {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "PKI",
				Detail: fmt.Sprintf(
					"Approval 1 durable PKI handoff expected exactly one pending PKI mutation in the post-rediscovery plan; observed=%d",
					replaced,
				),
				Target: "FI transport PKI",
			},
		)
		return plan
	}

	trustPath := strings.TrimSpace(
		report.Trust.Path,
	)
	if trustPath == "" {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionBlocked,
				Authority: "CONFIG",
				Detail:    "transport-trust configuration path is unavailable after Approval 1",
				Target:    "FI transport trust configuration",
			},
		)
		return plan
	}

	plan.Actions = append(
		plan.Actions,
		PlanAction{
			Action:    planActionCreate,
			Authority: "CONFIG",
			Detail: fmt.Sprintf(
				"after Approval 2 reacquire CRL source=%s through the approved native retrieval path, require DER SHA256=%s this_update=%s next_update=%s, validate issuer/signature/freshness/non-revocation again, and persist canonical PEM",
				handoff.CRLDistributionPoint,
				handoff.CRLSHA256,
				handoff.CRLThisUpdate,
				handoff.CRLNextUpdate,
			),
			Target: handoff.CRLDestinationPath,
		},
		PlanAction{
			Action:    planActionCreate,
			Authority: "CONFIG",
			Detail: fmt.Sprintf(
				"after Approval 2 write version_id=%s trust.root_cert_sha256=%s trust.transport_cert_sha256=%s trust.transport_issuer_sha256=%s trust.batch_signing_cert_sha256=%s trust.transport_crl=%s; all values are committed by the Approval 2 digest",
				config.TransportTrustVersion1,
				handoff.RootCertificateSHA256,
				handoff.TransportCertificateSHA256,
				handoff.TransportIssuerSHA256,
				handoff.BatchCertificateSHA256,
				handoff.CRLDestinationPath,
			),
			Target: trustPath,
		},
	)

	return plan
}

func discoverApproval1PKIIdentityHandoff(
	before Report,
	backend approval1PKIBackend,
) (approval1PKIHandoff, error) {
	if backend == nil {
		return approval1PKIHandoff{}, errors.New(
			"Approval 1 PKI backend is required",
		)
	}

	expectedDNS, err := approval1PKIExpectedDNS(
		before,
	)
	if err != nil {
		return approval1PKIHandoff{}, err
	}

	transportOID, err := backend.ResolveTemplateOID(
		fiTransportClientTemplateName,
	)
	if err != nil {
		return approval1PKIHandoff{}, fmt.Errorf(
			"resolve %s template OID for durable handoff: %w",
			fiTransportClientTemplateName,
			err,
		)
	}

	batchOID, err := backend.ResolveTemplateOID(
		fiBatchSigningTemplateName,
	)
	if err != nil {
		return approval1PKIHandoff{}, fmt.Errorf(
			"resolve %s template OID for durable handoff: %w",
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

	transport, found, err := backend.FindReusable(
		transportContract,
	)
	if err != nil {
		return approval1PKIHandoff{}, fmt.Errorf(
			"rediscover durable transport identity: %w",
			err,
		)
	}
	if !found {
		return approval1PKIHandoff{}, errors.New(
			"durable transport identity disappeared before post-Approval-1 handoff",
		)
	}

	batch, found, err := backend.FindReusable(
		batchContract,
	)
	if err != nil {
		return approval1PKIHandoff{}, fmt.Errorf(
			"rediscover durable batch-signing identity: %w",
			err,
		)
	}
	if !found {
		return approval1PKIHandoff{}, errors.New(
			"durable batch-signing identity disappeared before post-Approval-1 handoff",
		)
	}

	handoff := approval1PKIHandoff{
		BatchCertificateSHA256:     batch.CertificateSHA256,
		BatchTemplateOID:           batchOID,
		TransportCertificateSHA256: transport.CertificateSHA256,
		TransportTemplateOID:       transportOID,
	}

	if err := validateApproval1PKIIdentityHandoff(
		handoff,
	); err != nil {
		return approval1PKIHandoff{}, fmt.Errorf(
			"rediscovered durable PKI identity handoff is invalid: %w",
			err,
		)
	}

	return handoff, nil
}

func finalizeApproval1PKIHandoff(
	identity approval1PKIHandoff,
	trust approval1TransportTrustMaterial,
	crl approval1CRLMaterial,
) (approval1PKIHandoff, error) {
	if err := validateApproval1PKIIdentityHandoff(
		identity,
	); err != nil {
		return approval1PKIHandoff{}, err
	}

	if !strings.EqualFold(
		identity.TransportCertificateSHA256,
		trust.TransportCertificateSHA256,
	) {
		return approval1PKIHandoff{}, errors.New(
			"derived transport trust material does not match the durable transport identity",
		)
	}

	if !validSHA256Hex(
		trust.IssuerCertificateSHA256,
	) ||
		!validSHA256Hex(
			trust.RootCertificateSHA256,
		) {
		return approval1PKIHandoff{}, errors.New(
			"derived transport issuer/root certificate identity is invalid",
		)
	}

	if !approval1SupportedCRLDistributionPoint(
		trust.CRLDistributionPoint,
	) {
		return approval1PKIHandoff{}, errors.New(
			"derived transport CRL distribution point is unsupported",
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(
			trust.CRLDestinationPath,
		),
		strings.TrimSpace(
			crl.DestinationPath,
		),
	) {
		return approval1PKIHandoff{}, errors.New(
			"validated CRL destination does not match derived transport trust material",
		)
	}

	if strings.TrimSpace(
		trust.CRLDistributionPoint,
	) != strings.TrimSpace(
		crl.Source,
	) {
		return approval1PKIHandoff{}, errors.New(
			"validated CRL source does not match derived transport trust material",
		)
	}

	if len(crl.DER) == 0 {
		return approval1PKIHandoff{}, errors.New(
			"validated transport CRL DER is empty",
		)
	}

	digest := sha256.Sum256(
		crl.DER,
	)
	observedCRLSHA256 := hex.EncodeToString(
		digest[:],
	)

	if !strings.EqualFold(
		observedCRLSHA256,
		crl.SHA256,
	) {
		return approval1PKIHandoff{}, fmt.Errorf(
			"validated transport CRL SHA256=%s does not match DER SHA256=%s",
			crl.SHA256,
			observedCRLSHA256,
		)
	}

	handoff := identity
	handoff.CRLDestinationPath = trust.CRLDestinationPath
	handoff.CRLDistributionPoint = trust.CRLDistributionPoint
	handoff.CRLNextUpdate = crl.NextUpdate
	handoff.CRLSHA256 = crl.SHA256
	handoff.CRLThisUpdate = crl.ThisUpdate
	handoff.RootCertificateSHA256 = trust.RootCertificateSHA256
	handoff.TransportIssuerSHA256 = trust.IssuerCertificateSHA256

	if err := handoff.validate(); err != nil {
		return approval1PKIHandoff{}, err
	}

	return handoff, nil
}

func validateApproval1PKIIdentityHandoff(
	handoff approval1PKIHandoff,
) error {
	if !validSHA256Hex(
		handoff.TransportCertificateSHA256,
	) {
		return errors.New(
			"transport certificate SHA-256 is invalid",
		)
	}

	if !validSHA256Hex(
		handoff.BatchCertificateSHA256,
	) {
		return errors.New(
			"batch-signing certificate SHA-256 is invalid",
		)
	}

	if strings.EqualFold(
		handoff.TransportCertificateSHA256,
		handoff.BatchCertificateSHA256,
	) {
		return errors.New(
			"transport and batch-signing certificate identities must be different",
		)
	}

	if strings.TrimSpace(
		handoff.TransportTemplateOID,
	) == "" {
		return errors.New(
			"transport certificate template OID is required",
		)
	}

	if strings.TrimSpace(
		handoff.BatchTemplateOID,
	) == "" {
		return errors.New(
			"batch-signing certificate template OID is required",
		)
	}

	if strings.EqualFold(
		handoff.TransportTemplateOID,
		handoff.BatchTemplateOID,
	) {
		return errors.New(
			"transport and batch-signing certificate template OIDs must be different",
		)
	}

	return nil
}

func executeServer2016Approval1Controller(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
) (Approval1ControllerResult, error) {
	if writer == nil {
		return Approval1ControllerResult{}, errors.New(
			"Approval 1 controller output writer is required",
		)
	}

	if err := validateApproval1ControllerPlan(
		before,
		plan,
	); err != nil {
		return Approval1ControllerResult{}, err
	}

	if err := validateApprovalBoundaryState(
		before,
		plan,
		approval,
		approvalBoundaryInfrastructure,
	); err != nil {
		return Approval1ControllerResult{}, err
	}

	backend, err := newServer2016Approval1Backend(
		before,
		inputs,
	)
	if err != nil {
		return Approval1ControllerResult{}, err
	}
	defer backend.Close()

	return executeApproval1ControllerWithBackend(
		writer,
		before,
		plan,
		inputs,
		approval,
		backend,
	)
}

func newServer2016Approval1Backend(
	before Report,
	inputs PlanInputs,
) (*server2016Approval1Backend, error) {
	if strings.TrimSpace(
		before.AD.DomainController,
	) == "" ||
		strings.EqualFold(
			strings.TrimSpace(
				before.AD.DomainController,
			),
			notKnown,
		) {
		return nil, errors.New(
			"writable Active Directory domain controller is unavailable for Approval 1",
		)
	}

	session, err := openLDAPSession(
		before.AD.DomainController,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open signed/sealed Approval 1 LDAP session: %w",
			err,
		)
	}

	if err := revalidateApproval1ADPreconditions(
		session,
		before,
	); err != nil {
		session.close()
		return nil, fmt.Errorf(
			"Approval 1 AD pre-mutation revalidation failed: %w",
			err,
		)
	}

	backend := &server2016Approval1Backend{
		inputs:  inputs,
		session: session,
	}
	backend.pki.session = session

	return backend, nil
}

func validSHA256Hex(
	value string,
) bool {
	value = strings.TrimSpace(
		value,
	)
	if len(value) != 64 {
		return false
	}

	decoded, err := hex.DecodeString(
		value,
	)
	return err == nil && len(decoded) == 32
}
