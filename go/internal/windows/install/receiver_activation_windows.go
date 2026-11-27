// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

const (
	receiverActivationTimeout                    = 10 * time.Second
	receiverPendingPlanMarker                    = "receiver_pending=true"
	receiverActivationReceiverOrganizationalUnit = "FI Receiver Transport"
)

type ReceiverActivationResult struct {
	CipherSuite           string
	PeerCertificateSHA256 string
	ReceiverAddress       string
	ReceiverName          string
	TLSVersion            string
}

func ProbeApproval1ReceiverActivation(
	result Approval1ControllerResult,
	inputs PlanInputs,
) (ReceiverActivationResult, error) {
	handoff := result.PKI.Handoff
	if err := handoff.validate(); err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"Approval 1 PKI handoff is unavailable for receiver activation: %w",
			err,
		)
	}

	receiverAddress := strings.TrimSpace(inputs.ReceiverAddress)
	receiverName := strings.TrimSpace(inputs.ReceiverName)
	if receiverAddress == "" || receiverName == "" {
		return ReceiverActivationResult{}, errors.New(
			"receiver activation requires the approved receiver address and DNS name",
		)
	}
	if _, _, err := net.SplitHostPort(receiverAddress); err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"receiver activation address must be host:port: %w",
			err,
		)
	}

	sourceID := deploymentConfigExpectedSourceID(result.Rediscovered)
	if sourceID == "" {
		return ReceiverActivationResult{}, errors.New(
			"receiver activation source identity is unavailable from authoritative discovery",
		)
	}

	trust, err := deriveApproval1TransportTrustMaterial(
		handoff.TransportCertificateSHA256,
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"derive receiver-activation transport trust: %w",
			err,
		)
	}
	if !strings.EqualFold(
		trust.RootCertificateSHA256,
		handoff.RootCertificateSHA256,
	) || !strings.EqualFold(
		trust.IssuerCertificateSHA256,
		handoff.TransportIssuerSHA256,
	) || strings.TrimSpace(trust.CRLDistributionPoint) != strings.TrimSpace(handoff.CRLDistributionPoint) {
		return ReceiverActivationResult{}, errors.New(
			"receiver-activation trust material changed after Approval 1",
		)
	}

	session, err := openApproval2TransportTrustLDAPSession(
		result.Rediscovered,
		handoff,
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"open receiver-activation CRL retrieval path: %w",
			err,
		)
	}
	if session != nil {
		defer session.close()
	}

	crlMaterial, err := acquireApproval1TransportCRL(
		session,
		trust,
		time.Now(),
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"acquire receiver-activation transport CRL: %w",
			err,
		)
	}
	if !strings.EqualFold(crlMaterial.SHA256, handoff.CRLSHA256) {
		return ReceiverActivationResult{}, fmt.Errorf(
			"receiver-activation CRL SHA256=%s does not match Approval 1 SHA256=%s",
			crlMaterial.SHA256,
			handoff.CRLSHA256,
		)
	}

	crl, err := x509.ParseRevocationList(crlMaterial.DER)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"parse receiver-activation CRL: %w",
			err,
		)
	}

	return probeReceiverActivation(
		receiverAddress,
		receiverName,
		sourceID,
		handoff.TransportCertificateSHA256,
		handoff.RootCertificateSHA256,
		handoff.TransportIssuerSHA256,
		crl,
	)
}

func ProbeInstalledReceiverActivation(
	report Report,
) (ReceiverActivationResult, error) {
	if report.Config.Presence != presencePresent {
		return ReceiverActivationResult{}, errors.New(
			"installed FI configuration is not authoritatively present",
		)
	}
	if report.Trust.Presence != presencePresent {
		return ReceiverActivationResult{}, errors.New(
			"installed FI transport trust is not authoritatively present",
		)
	}

	crl, err := loadReceiverActivationCRL(
		report.Trust.TransportCRLPath,
		report.Trust.TransportIssuerSHA256,
		time.Now(),
	)
	if err != nil {
		return ReceiverActivationResult{}, err
	}

	return probeReceiverActivation(
		report.Config.ReceiverAddress,
		report.Config.ReceiverName,
		report.Config.SourceID,
		report.Trust.TransportCertificateSHA256,
		report.Trust.RootCertificateSHA256,
		report.Trust.TransportIssuerSHA256,
		crl,
	)
}

func RebuildApproval2ForReceiverPending(
	result Approval1ControllerResult,
	inputs PlanInputs,
) (Approval1ControllerResult, PlanInputs, error) {
	if !result.PKI.Applied || !result.PKI.Durable {
		return result, inputs, errors.New(
			"receiver-pending mode requires a durable Approval 1 PKI identity",
		)
	}
	if err := result.PKI.Handoff.validate(); err != nil {
		return result, inputs, fmt.Errorf(
			"receiver-pending mode requires a complete Approval 1 PKI handoff: %w",
			err,
		)
	}

	sender, found := findService(result.Rediscovered.Services, "FISender")
	if !found || sender.Presence != presenceAbsent {
		return result, inputs, fmt.Errorf(
			"receiver-pending new-install mode requires FISender to be authoritatively absent; observed presence=%s",
			valueOrNotKnown(sender.Presence),
		)
	}

	inputs.ReceiverPending = true
	plan := BuildPlanWithInputs(result.Rediscovered, inputs)
	plan = applyApproval1PKIHandoffToPlan(
		result.Rediscovered,
		plan,
		result.PKI.Handoff,
	)
	if err := validateApproval2ControllerPlan(
		result.Rediscovered,
		plan,
		result.PKI.Handoff,
	); err != nil {
		return result, inputs, fmt.Errorf(
			"receiver-pending Approval 2 plan is invalid: %w",
			err,
		)
	}

	digest, err := ApprovalBoundaryDigest(
		result.Rediscovered,
		plan,
		approvalBoundaryLocal,
	)
	if err != nil {
		return result, inputs, err
	}

	_, required := ApprovalRequirements(plan)
	result.Approval2Plan = plan
	result.Approval2Required = required
	result.Approval2SHA256 = digest
	result.OldPlanInvalidated = true
	return result, inputs, nil
}

func RebuildInstalledApproval2ForReceiverPending(
	report Report,
	inputs PlanInputs,
) (InstallPlan, PlanInputs, error) {
	if report.Config.Presence != presencePresent {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair requires an installed FI configuration",
		)
	}
	if report.Trust.Presence != presencePresent {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair requires installed FI transport trust",
		)
	}

	sender, found := findService(
		report.Services,
		"FISender",
	)
	if !found || sender.Presence == presenceUnknown {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair requires authoritative FISender discovery",
		)
	}

	inputs.ReceiverPending = true
	plan := BuildPlanWithInputs(
		report,
		inputs,
	)

	if plan.HasBlockers() {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair plan contains blockers",
		)
	}
	if plan.HasQuestions() {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair plan contains unanswered questions",
		)
	}

	approval1Required, _ := ApprovalRequirements(
		plan,
	)
	if approval1Required {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair unexpectedly requires Approval 1",
		)
	}

	senderActivationFound := false
	for _, action := range plan.Actions {
		if !strings.EqualFold(
			strings.TrimSpace(action.Target),
			"FISender",
		) {
			continue
		}
		if action.Authority != "SCM" &&
			action.Authority != "RUNTIME" {
			continue
		}

		senderActivationFound = true
		if !strings.Contains(
			action.Detail,
			receiverPendingPlanMarker,
		) {
			return InstallPlan{}, inputs, fmt.Errorf(
				"receiver-pending FISender action is missing the pending marker: authority=%s action=%s detail=%q",
				action.Authority,
				action.Action,
				action.Detail,
			)
		}
	}
	if !senderActivationFound {
		return InstallPlan{}, inputs, errors.New(
			"receiver-pending local repair plan contains no FISender SCM/RUNTIME state",
		)
	}

	return plan, inputs, nil
}

func RequiresReceiverActivation(plan InstallPlan) bool {
	for _, action := range plan.Actions {
		if !strings.EqualFold(strings.TrimSpace(action.Target), "FISender") {
			continue
		}
		if !planActionMutates(action.Action) {
			continue
		}
		if action.Authority == "SCM" || action.Authority == "RUNTIME" {
			return true
		}
	}
	return false
}

func NormalizeReceiverPendingReport(
	report Report,
) (Report, error) {
	sender, found := findService(report.Services, "FISender")
	if !found {
		return report, errors.New(
			"receiver-pending state cannot be proven because FISender discovery is unavailable",
		)
	}
	if sender.Presence != presencePresent ||
		sender.ManagedAccount != "true" ||
		sender.StartType != "Manual" ||
		sender.State != "Stopped" ||
		sender.ProcessID != 0 ||
		sender.SIDType != "NONE" ||
		!strings.EqualFold(
			strings.TrimSpace(sender.BinaryPath),
			`"C:\Program Files\FI\fi-sender.exe"`,
		) {
		return report, fmt.Errorf(
			"receiver-pending FISender state is not exact: presence=%s managed=%s start=%s state=%s pid=%d sid=%s path=%q",
			sender.Presence,
			sender.ManagedAccount,
			sender.StartType,
			sender.State,
			sender.ProcessID,
			sender.SIDType,
			sender.BinaryPath,
		)
	}
	if strings.TrimSpace(sender.Account) == "" {
		return report, errors.New(
			"receiver-pending FISender service account is unavailable",
		)
	}

	processIDs, err := runningProcessIDsByName("fi-sender.exe")
	if err != nil {
		return report, fmt.Errorf(
			"prove receiver-pending sender process absence: %w",
			err,
		)
	}
	if len(processIDs) != 0 {
		return report, fmt.Errorf(
			"receiver-pending FISender is Stopped but fi-sender.exe process(es) remain: %v",
			processIDs,
		)
	}

	normalized := report
	normalized.Checks = append([]Check(nil), report.Checks...)
	for index := range normalized.Checks {
		switch normalized.Checks[index].Name {
		case "FISender service":
			normalized.Checks[index].Status = checkInfo
			normalized.Checks[index].Detail =
				receiverPendingPlanMarker + "; service is intentionally Manual/Stopped until receiver mTLS activation succeeds"
		case "FISender singleton ownership":
			normalized.Checks[index].Status = checkInfo
			normalized.Checks[index].Detail =
				receiverPendingPlanMarker + "; FISender intentionally has no running process"
		}
	}
	return normalized, nil
}

func NormalizeReceiverPendingPlan(
	plan InstallPlan,
) InstallPlan {
	normalized := plan
	normalized.Actions = append([]PlanAction(nil), plan.Actions...)
	for index := range normalized.Actions {
		action := &normalized.Actions[index]
		if !strings.EqualFold(strings.TrimSpace(action.Target), "FISender") {
			continue
		}
		switch action.Authority {
		case "SCM":
			action.Action = planActionNoChange
			action.Detail = receiverPendingPlanMarker + "; FISender matches intentional Manual receiver-pending service configuration"
		case "RUNTIME":
			action.Action = planActionNoChange
			action.Detail = receiverPendingPlanMarker + "; FISender is intentionally Stopped until receiver activation succeeds"
		}
	}
	return normalized
}

func BuildReceiverPendingPlan(
	report Report,
) (InstallPlan, error) {
	normalized, err := NormalizeReceiverPendingReport(report)
	if err != nil {
		return InstallPlan{}, err
	}
	return NormalizeReceiverPendingPlan(BuildPlan(normalized)), nil
}

func receiverPendingFromPlan(plan InstallPlan) bool {
	for _, action := range plan.Actions {
		if strings.EqualFold(strings.TrimSpace(action.Target), "FISender") &&
			strings.Contains(action.Detail, receiverPendingPlanMarker) {
			return true
		}
	}
	return false
}

func loadReceiverActivationCRL(
	path string,
	issuerSHA256 string,
	currentTime time.Time,
) (*x509.RevocationList, error) {
	path = strings.TrimSpace(path)
	if path == "" || strings.EqualFold(path, notKnown) {
		return nil, errors.New("FI transport CRL path is unavailable")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read FI transport CRL %s: %w", path, err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("FI transport CRL must contain exactly one X509 CRL PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse FI transport CRL: %w", err)
	}
	issuer, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreCA,
		issuerSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("load FI transport issuer for CRL validation: %w", err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("validate FI transport CRL signature: %w", err)
	}
	if currentTime.IsZero() || currentTime.Before(crl.ThisUpdate) || !currentTime.Before(crl.NextUpdate) {
		return nil, fmt.Errorf(
			"FI transport CRL is not current: this_update=%s next_update=%s now=%s",
			crl.ThisUpdate.Format(time.RFC3339),
			crl.NextUpdate.Format(time.RFC3339),
			currentTime.Format(time.RFC3339),
		)
	}
	return crl, nil
}

func probeReceiverActivation(
	receiverAddress string,
	receiverName string,
	sourceID string,
	transportCertificateSHA256 string,
	rootCertificateSHA256 string,
	transportIssuerSHA256 string,
	crl *x509.RevocationList,
) (ReceiverActivationResult, error) {
	receiverAddress = strings.TrimSpace(receiverAddress)
	receiverName = strings.TrimSpace(receiverName)
	sourceID = strings.TrimSpace(sourceID)
	if _, _, err := net.SplitHostPort(receiverAddress); err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"receiver activation address must be host:port: %w",
			err,
		)
	}
	if receiverName == "" || sourceID == "" {
		return ReceiverActivationResult{}, errors.New(
			"receiver activation requires receiver name and source identity",
		)
	}
	if crl == nil {
		return ReceiverActivationResult{}, errors.New(
			"receiver activation requires the validated FI transport CRL",
		)
	}

	root, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreRoot,
		rootCertificateSHA256,
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"load FI root CA for receiver activation: %w",
			err,
		)
	}
	issuer, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreCA,
		transportIssuerSHA256,
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"load FI transport issuer for receiver activation: %w",
			err,
		)
	}
	if err := validateReceiverActivationTrustAnchors(root, issuer); err != nil {
		return ReceiverActivationResult{}, err
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"validate receiver-activation CRL signature: %w",
			err,
		)
	}
	now := time.Now()
	if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
		return ReceiverActivationResult{}, fmt.Errorf(
			"receiver-activation CRL is not current: this_update=%s next_update=%s now=%s",
			crl.ThisUpdate.Format(time.RFC3339),
			crl.NextUpdate.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
	}

	identity, err := certstore.LoadLocalMachineSigningIdentity(
		transportCertificateSHA256,
	)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"load FI source transport identity for receiver activation: %w",
			err,
		)
	}
	defer identity.Close()
	if err := validateReceiverActivationSourceIdentity(identity.Certificate, sourceID); err != nil {
		return ReceiverActivationResult{}, err
	}
	transportCertificate, err := identity.TLSCertificate()
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"construct FI receiver-activation TLS identity: %w",
			err,
		)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	config := &tls.Config{
		Certificates: []tls.Certificate{transportCertificate},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		ServerName:   receiverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			return validateReceiverActivationConnection(
				state,
				issuer,
				crl,
				time.Now(),
			)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), receiverActivationTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	rawConnection, err := dialer.DialContext(ctx, "tcp", receiverAddress)
	if err != nil {
		return ReceiverActivationResult{}, fmt.Errorf(
			"dial FI receiver %s: %w",
			receiverAddress,
			err,
		)
	}
	defer rawConnection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConnection.SetDeadline(deadline); err != nil {
			return ReceiverActivationResult{}, fmt.Errorf(
				"set FI receiver activation deadline: %w",
				err,
			)
		}
	}

	connection := tls.Client(rawConnection, config)
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return ReceiverActivationResult{}, fmt.Errorf(
			"FI receiver mTLS activation handshake rejected: %w",
			err,
		)
	}
	state := connection.ConnectionState()
	_ = connection.Close()
	if len(state.PeerCertificates) == 0 {
		return ReceiverActivationResult{}, errors.New(
			"FI receiver mTLS activation completed without a peer certificate",
		)
	}
	peerDigest := sha256.Sum256(state.PeerCertificates[0].Raw)
	return ReceiverActivationResult{
		CipherSuite:           tls.CipherSuiteName(state.CipherSuite),
		PeerCertificateSHA256: strings.ToUpper(hex.EncodeToString(peerDigest[:])),
		ReceiverAddress:       receiverAddress,
		ReceiverName:          receiverName,
		TLSVersion:            receiverActivationTLSVersion(state.Version),
	}, nil
}

func validateReceiverActivationConnection(
	state tls.ConnectionState,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
	currentTime time.Time,
) error {
	if issuer == nil || crl == nil {
		return errors.New("FI receiver activation trust material is incomplete")
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return errors.New("FI receiver certificate did not produce a verified TLS chain")
	}
	verifiedThroughPinnedIssuer := false
	for _, chain := range state.VerifiedChains {
		if len(chain) >= 2 && bytes.Equal(chain[1].Raw, issuer.Raw) {
			verifiedThroughPinnedIssuer = true
			break
		}
	}
	if !verifiedThroughPinnedIssuer {
		return errors.New("FI receiver TLS chain did not verify through the exact pinned transport issuer")
	}

	leaf := state.PeerCertificates[0]
	if leaf.IsCA {
		return errors.New("FI receiver certificate must not be a CA")
	}
	if len(leaf.Subject.OrganizationalUnit) != 1 ||
		leaf.Subject.OrganizationalUnit[0] != receiverActivationReceiverOrganizationalUnit {
		return fmt.Errorf(
			"FI receiver certificate organizational unit must be exactly %q",
			receiverActivationReceiverOrganizationalUnit,
		)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("FI receiver certificate does not permit digital signatures")
	}
	if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) {
		return errors.New("FI receiver certificate issuer does not match pinned transport issuer")
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("validate FI receiver certificate issuer signature: %w", err)
	}
	if receiverActivationCertificateIsRevoked(leaf, crl) {
		return fmt.Errorf("FI receiver certificate serial %s is revoked", leaf.SerialNumber.Text(16))
	}
	if currentTime.IsZero() {
		return errors.New("current time is required for FI receiver validation")
	}
	return nil
}

func validateReceiverActivationSourceIdentity(
	certificate *x509.Certificate,
	sourceID string,
) error {
	if certificate == nil {
		return errors.New("FI source transport certificate is required")
	}
	if certificate.IsCA {
		return errors.New("FI source transport certificate must not be a CA")
	}
	if !strings.EqualFold(certificate.Subject.CommonName, sourceID) {
		return fmt.Errorf(
			"FI source transport certificate common name %q does not match source ID %q",
			certificate.Subject.CommonName,
			sourceID,
		)
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("FI source transport certificate does not permit digital signatures")
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return errors.New("FI source transport certificate does not permit TLS client authentication")
}

func validateReceiverActivationTrustAnchors(
	root *x509.Certificate,
	issuer *x509.Certificate,
) error {
	if root == nil || !root.IsCA || !root.BasicConstraintsValid {
		return errors.New("FI root certificate must be a valid CA")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("FI root certificate self-signature validation failed: %w", err)
	}
	if issuer == nil || !issuer.IsCA || !issuer.BasicConstraintsValid {
		return errors.New("FI transport issuer certificate must be a valid CA")
	}
	if !bytes.Equal(issuer.RawIssuer, root.RawSubject) {
		return errors.New("FI transport issuer does not name the pinned FI root")
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("FI transport issuer signature validation failed: %w", err)
	}
	return nil
}

func receiverActivationCertificateIsRevoked(
	certificate *x509.Certificate,
	crl *x509.RevocationList,
) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func receiverActivationTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
