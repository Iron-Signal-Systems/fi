// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

const receiverTransportOrganizationalUnit = "FI Receiver Transport"

type senderConfig struct {
	BatchSigningCertificateSHA256 string
	ManifestPath                  string
	ReceiverAddress               string
	ReceiverName                  string
	RootCertificateSHA256         string
	SourceID                      string
	StageDir                      string
	Timeout                       time.Duration
	TransportCRLPath              string
	TransportCertificateSHA256    string
	TransportIssuerSHA256         string
}

type senderResult struct {
	AcknowledgementOutcome string
	BatchID                string
	CipherSuite            string
	CleanupDisposition     transportsender.OutboundCleanupDisposition
	RetirementDisposition  transportsender.RetirementDisposition
	SourceID               string
	StageDisposition       transportsender.OutboundFrameDisposition
	TLSVersion             string
}

func main() {
	config, err := parseSenderConfig()
	if err != nil {
		fail(err)
	}

	signalContext, stopSignal := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	defer stopSignal()

	ctx, cancel := context.WithTimeout(signalContext, config.Timeout)
	defer cancel()

	result, err := runSender(ctx, config)
	printSenderResult(result)
	if err != nil {
		fail(err)
	}
}

func dialReceiver(
	ctx context.Context,
	config senderConfig,
	transportCertificate tls.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
) (*tls.Conn, error) {
	roots := x509.NewCertPool()
	roots.AddCert(root)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{transportCertificate},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		ServerName:   config.ReceiverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			return validateReceiverConnection(
				state,
				issuer,
				crl,
				time.Now(),
			)
		},
	}

	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(
		ctx,
		"tcp",
		config.ReceiverAddress,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"dial FI receiver %s: %w",
			config.ReceiverAddress,
			err,
		)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("set FI sender transport deadline: %w", err)
		}
	}

	tlsConnection := tls.Client(connection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = tlsConnection.Close()
		return nil, fmt.Errorf("FI receiver TLS handshake rejected: %w", err)
	}

	return tlsConnection, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func hasExtendedKeyUsage(
	certificate *x509.Certificate,
	usage x509.ExtKeyUsage,
) bool {
	for _, current := range certificate.ExtKeyUsage {
		if current == usage || current == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func loadTransportCRL(path string) (*x509.RevocationList, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read FI transport CRL: %w", err)
	}

	der := encoded
	if block, _ := pem.Decode(encoded); block != nil {
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse FI transport CRL: %w", err)
	}
	return crl, nil
}

func parseSenderConfig() (senderConfig, error) {
	flags := flag.NewFlagSet("fi-sender", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	var config senderConfig
	flags.StringVar(
		&config.BatchSigningCertificateSHA256,
		"batch-signing-cert-sha256",
		"",
		"SHA-256 of FI batch-signing certificate in LocalMachine\\MY; required only when no exact staged retry frame exists",
	)
	flags.StringVar(
		&config.ManifestPath,
		"manifest",
		"",
		"absolute path to one published Phase 1 FI batch manifest",
	)
	flags.StringVar(
		&config.ReceiverAddress,
		"receiver",
		"",
		"FI receiver TCP address, for example 192.168.1.119:8443",
	)
	flags.StringVar(
		&config.ReceiverName,
		"receiver-name",
		"",
		"FI receiver certificate DNS name, for example fi-receiver-a.iss.local",
	)
	flags.StringVar(
		&config.RootCertificateSHA256,
		"root-cert-sha256",
		"",
		"SHA-256 of FI root CA certificate in LocalMachine\\ROOT",
	)
	flags.StringVar(
		&config.SourceID,
		"source",
		"",
		"FI source ID, for example iss-fs-01.iss.local",
	)
	flags.StringVar(
		&config.StageDir,
		"stage-dir",
		"",
		"absolute durable outbound-stage directory",
	)
	flags.DurationVar(
		&config.Timeout,
		"timeout",
		30*time.Second,
		"maximum duration for one FI transport transaction",
	)
	flags.StringVar(
		&config.TransportCRLPath,
		"transport-crl",
		"",
		"path to the current FI Transport Issuing CA CRL",
	)
	flags.StringVar(
		&config.TransportCertificateSHA256,
		"transport-cert-sha256",
		"",
		"SHA-256 of FI source transport certificate in LocalMachine\\MY",
	)
	flags.StringVar(
		&config.TransportIssuerSHA256,
		"transport-issuer-sha256",
		"",
		"SHA-256 of FI Transport Issuing CA certificate in LocalMachine\\CA",
	)

	if err := flags.Parse(os.Args[1:]); err != nil {
		return senderConfig{}, err
	}
	if flags.NArg() != 0 {
		return senderConfig{}, errors.New("fi-sender does not accept positional arguments")
	}
	if err := validateSenderConfig(config); err != nil {
		return senderConfig{}, err
	}
	return config, nil
}

func prepareOutboundFrame(
	config senderConfig,
) (transportsender.OutboundFrame, error) {
	base := transportsender.OutboundFrameConfig{
		ManifestPath: config.ManifestPath,
		SourceID:     config.SourceID,
		StageDir:     config.StageDir,
	}

	outbound, err := transportsender.PrepareOutboundFrame(base)
	if err == nil {
		return outbound, nil
	}
	if !errors.Is(
		err,
		transportsender.ErrOutboundSigningIdentityRequired,
	) {
		return transportsender.OutboundFrame{}, err
	}
	if config.BatchSigningCertificateSHA256 == "" {
		return transportsender.OutboundFrame{}, errors.New(
			"-batch-signing-cert-sha256 is required because no exact staged retry frame exists",
		)
	}

	identity, err := certstore.LoadLocalMachineSigningIdentity(
		config.BatchSigningCertificateSHA256,
	)
	if err != nil {
		return transportsender.OutboundFrame{}, fmt.Errorf(
			"load FI batch-signing identity: %w",
			err,
		)
	}
	defer identity.Close()

	base.BatchSigningCertificate = identity.Certificate
	base.BatchSigner = identity.Signer
	outbound, err = transportsender.PrepareOutboundFrame(base)
	if err != nil {
		return transportsender.OutboundFrame{}, err
	}
	return outbound, nil
}

func printSenderResult(result senderResult) {
	if result.SourceID == "" {
		return
	}
	fmt.Printf("Source:        %s\n", result.SourceID)
	fmt.Printf("BatchID:       %s\n", result.BatchID)
	fmt.Printf("Stage:         %s\n", result.StageDisposition)
	if result.TLSVersion != "" {
		fmt.Printf("TLS:           %s\n", result.TLSVersion)
		fmt.Printf("CipherSuite:   %s\n", result.CipherSuite)
	}
	if result.AcknowledgementOutcome != "" {
		fmt.Printf("Acknowledged:  %s\n", result.AcknowledgementOutcome)
	}
	if result.RetirementDisposition != "" {
		fmt.Printf("Retirement:    %s\n", result.RetirementDisposition)
	}
	if result.CleanupDisposition != "" {
		fmt.Printf("StageCleanup:  %s\n", result.CleanupDisposition)
	}
}

func runSender(
	ctx context.Context,
	config senderConfig,
) (senderResult, error) {
	if ctx == nil {
		return senderResult{}, errors.New("context is required")
	}

	outbound, err := prepareOutboundFrame(config)
	if err != nil {
		return senderResult{}, fmt.Errorf("prepare exact FI outbound frame: %w", err)
	}
	result := senderResult{
		BatchID:          outbound.Sent.Descriptor.BatchID,
		SourceID:         outbound.Sent.Descriptor.SourceID,
		StageDisposition: outbound.Disposition,
	}

	root, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreRoot,
		config.RootCertificateSHA256,
	)
	if err != nil {
		return result, fmt.Errorf("load FI root CA from Windows certificate store: %w", err)
	}
	issuer, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreCA,
		config.TransportIssuerSHA256,
	)
	if err != nil {
		return result, fmt.Errorf("load FI transport issuer from Windows certificate store: %w", err)
	}
	if err := validateTrustAnchors(root, issuer); err != nil {
		return result, err
	}

	crl, err := loadTransportCRL(config.TransportCRLPath)
	if err != nil {
		return result, err
	}
	if err := validateTransportCRL(crl, issuer, time.Now()); err != nil {
		return result, err
	}

	transportIdentity, err := certstore.LoadLocalMachineSigningIdentity(
		config.TransportCertificateSHA256,
	)
	if err != nil {
		return result, fmt.Errorf("load FI source transport identity: %w", err)
	}
	defer transportIdentity.Close()
	if err := validateSourceTransportIdentity(
		transportIdentity.Certificate,
		config.SourceID,
	); err != nil {
		return result, err
	}
	transportCertificate, err := transportIdentity.TLSCertificate()
	if err != nil {
		return result, fmt.Errorf("construct FI source TLS identity: %w", err)
	}

	connection, err := dialReceiver(
		ctx,
		config,
		transportCertificate,
		root,
		issuer,
		crl,
	)
	if err != nil {
		return result, err
	}
	defer connection.Close()

	state := connection.ConnectionState()
	result.TLSVersion = tlsVersion(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	transaction, err := transportsender.SendAndRetirePreparedFrame(
		connection,
		outbound,
		config.ManifestPath,
	)
	result.RetirementDisposition = transaction.Retirement.Disposition
	if acknowledgement, authorizationErr := transaction.Authorization.Acknowledgement(); authorizationErr == nil {
		result.AcknowledgementOutcome = string(acknowledgement.Outcome)
	}
	if err != nil {
		return result, err
	}

	cleanup, err := transportsender.CleanupRetiredOutboundFrame(
		outbound,
		config.ManifestPath,
		transaction.Authorization,
	)
	result.CleanupDisposition = cleanup.Disposition
	if err != nil {
		return result, fmt.Errorf("clean retired FI outbound stage: %w", err)
	}

	return result, nil
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func validateReceiverConnection(
	state tls.ConnectionState,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
	currentTime time.Time,
) error {
	if issuer == nil {
		return errors.New("FI transport issuer is required for receiver validation")
	}
	if crl == nil {
		return errors.New("FI transport CRL is required for receiver validation")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("FI receiver certificate is required")
	}
	if len(state.VerifiedChains) == 0 {
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
		return errors.New(
			"FI receiver TLS chain did not verify through the exact pinned transport issuer",
		)
	}

	leaf := state.PeerCertificates[0]
	if leaf.IsCA {
		return errors.New("FI receiver certificate must not be a CA")
	}
	if len(leaf.Subject.OrganizationalUnit) != 1 ||
		leaf.Subject.OrganizationalUnit[0] != receiverTransportOrganizationalUnit {
		return fmt.Errorf(
			"FI receiver certificate organizational unit must be exactly %q",
			receiverTransportOrganizationalUnit,
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
	if certificateIsRevoked(leaf, crl) {
		return fmt.Errorf(
			"FI receiver certificate serial %s is revoked",
			leaf.SerialNumber.Text(16),
		)
	}
	if currentTime.IsZero() {
		return errors.New("current time is required for FI receiver validation")
	}
	return nil
}

func validateSenderConfig(config senderConfig) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "-manifest", value: config.ManifestPath},
		{name: "-receiver", value: config.ReceiverAddress},
		{name: "-receiver-name", value: config.ReceiverName},
		{name: "-root-cert-sha256", value: config.RootCertificateSHA256},
		{name: "-source", value: config.SourceID},
		{name: "-stage-dir", value: config.StageDir},
		{name: "-transport-crl", value: config.TransportCRLPath},
		{name: "-transport-cert-sha256", value: config.TransportCertificateSHA256},
		{name: "-transport-issuer-sha256", value: config.TransportIssuerSHA256},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if config.Timeout <= 0 {
		return errors.New("-timeout must be greater than zero")
	}
	if strings.ContainsAny(config.SourceID, `/\\`) ||
		config.SourceID == "." ||
		config.SourceID == ".." {
		return errors.New("invalid FI source ID")
	}
	if _, _, err := net.SplitHostPort(config.ReceiverAddress); err != nil {
		return fmt.Errorf("-receiver must be host:port: %w", err)
	}
	return nil
}

func validateSourceTransportIdentity(
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
	if len(certificate.Subject.OrganizationalUnit) != 1 ||
		certificate.Subject.OrganizationalUnit[0] != transporttrust.TransportOrganizationalUnit {
		return fmt.Errorf(
			"FI source transport certificate organizational unit must be exactly %q",
			transporttrust.TransportOrganizationalUnit,
		)
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("FI source transport certificate does not permit digital signatures")
	}
	if !hasExtendedKeyUsage(certificate, x509.ExtKeyUsageClientAuth) {
		return errors.New("FI source transport certificate does not permit TLS client authentication")
	}
	return nil
}

func validateTransportCRL(
	crl *x509.RevocationList,
	issuer *x509.Certificate,
	currentTime time.Time,
) error {
	if crl == nil {
		return errors.New("FI transport CRL is required")
	}
	if issuer == nil {
		return errors.New("FI transport issuer is required")
	}
	if currentTime.IsZero() {
		return errors.New("current time is required for FI transport CRL validation")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("FI transport CRL signature validation failed: %w", err)
	}
	if crl.ThisUpdate.After(currentTime) {
		return fmt.Errorf(
			"FI transport CRL is not yet valid: thisUpdate=%s",
			crl.ThisUpdate.UTC().Format(time.RFC3339),
		)
	}
	if crl.NextUpdate.IsZero() {
		return errors.New("FI transport CRL nextUpdate is required")
	}
	if !crl.NextUpdate.After(currentTime) {
		return fmt.Errorf(
			"FI transport CRL is expired: nextUpdate=%s",
			crl.NextUpdate.UTC().Format(time.RFC3339),
		)
	}
	return nil
}

func validateTrustAnchors(
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

func certificateIsRevoked(
	certificate *x509.Certificate,
	crl *x509.RevocationList,
) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
