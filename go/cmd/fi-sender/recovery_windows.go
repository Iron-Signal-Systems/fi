// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

// tryRecovery handles either an already-staged exact recovery transaction or a
// newly negotiated adaptive backlog transaction. handled=false means the queue
// should continue with ordinary one-batch FI transport.
func tryRecovery(
	ctx context.Context,
	config senderConfig,
	queue *transportsender.PublishedBatchQueue,
) (bool, error) {
	if ctx == nil {
		return false, errors.New("context is required")
	}
	attemptStarted := time.Now()

	staged, stagedFound, err := transportrecovery.FindStagedFrame(config.StageDir)
	if err != nil {
		return false, fmt.Errorf("inspect FI staged recovery transaction: %w", err)
	}
	if stagedFound {
		if staged.Descriptor.SourceID != config.SourceID {
			return false, errors.New("staged FI recovery source does not match configured source")
		}
		if err := transportsender.RecoveryStageMatchesSpool(staged, config.SpoolDir); err != nil {
			return false, fmt.Errorf("validate staged FI recovery against source spool: %w", err)
		}
		return runStagedRecovery(ctx, config, queue, staged, attemptStarted)
	}

	if config.RecoveryThresholdBytes == 0 {
		return false, nil
	}
	plan, err := transportsender.PlanRecovery(queue)
	if err != nil {
		return false, err
	}
	if plan.PendingMembers < 2 || plan.ProposedMembers < 2 || plan.PendingCanonicalBytes <= config.RecoveryThresholdBytes {
		return false, nil
	}

	started := attemptStarted
	fmt.Printf("Recovery:       NEGOTIATING\n")
	fmt.Printf("RecoveryPending:%d members / %d canonical bytes\n", plan.PendingMembers, plan.PendingCanonicalBytes)
	fmt.Printf("RecoveryProposed:%d oldest members\n", plan.ProposedMembers)

	offer, err := transportsender.RecoveryOfferFromPlan(config.SourceID, plan)
	if err != nil {
		return false, err
	}
	connection, closeTransport, err := dialAuthenticatedSenderTransport(ctx, config)
	if err != nil {
		return false, err
	}
	defer closeTransport()

	if err := transportrecovery.WriteOffer(connection, offer); err != nil {
		return false, wrapRecoveryTransportError(err, "send FI recovery offer")
	}
	decision, err := transportrecovery.ReadDecision(connection)
	if err != nil {
		return false, wrapRecoveryTransportError(err, "read FI recovery decision")
	}
	if !decision.Accepted {
		fmt.Printf("Recovery:       REJECTED (%s)\n", decision.Reason)
		return false, nil
	}

	index, err := transportsender.SelectRecoveryIndex(plan, decision.MaxMembers, decision.MaxCanonicalBytes)
	if err != nil {
		fmt.Printf("Recovery:       NORMAL_FALLBACK (%v)\n", err)
		return false, nil
	}

	identity, err := certstore.LoadLocalMachineSigningIdentity(config.BatchSigningCertificateSHA256)
	if err != nil {
		return false, fmt.Errorf("load FI batch-signing identity for recovery: %w", err)
	}
	defer identity.Close()

	recoveryID, err := transportrecovery.NewRecoveryID()
	if err != nil {
		return false, err
	}
	var prepared transportrecovery.PreparedFrame
	for {
		prepared, err = transportrecovery.PrepareFrame(transportrecovery.PrepareConfig{
			BatchSigner:             identity.Signer,
			BatchSigningCertificate: identity.Certificate,
			Index:                   index,
			MaxEncodedBytes:         decision.MaxEncodedBytes,
			RecoveryID:              recoveryID,
			SourceID:                config.SourceID,
			StageDir:                config.StageDir,
		})
		if err == nil {
			break
		}
		if !errors.Is(err, transportrecovery.ErrEncodedLimitExceeded) {
			return false, fmt.Errorf("prepare FI recovery frame: %w", err)
		}
		next, ok := transportsender.HalveRecoveryIndex(index)
		if !ok {
			fmt.Printf("Recovery:       NORMAL_FALLBACK (oldest recovery range exceeds encoded limit)\n")
			return false, nil
		}
		index = next
	}

	fmt.Printf("Recovery:       PREPARED\n")
	fmt.Printf("RecoveryID:     %s\n", prepared.Descriptor.RecoveryID)
	fmt.Printf("RecoveryMembers: %d\n", prepared.Descriptor.MemberCount)
	fmt.Printf("RecoveryBytes:  %d canonical / %d encoded\n", prepared.Descriptor.CanonicalBytes, prepared.Descriptor.EncodedDataBytes)

	return finishRecovery(connection, config, queue, prepared, started)
}

func runStagedRecovery(
	ctx context.Context,
	config senderConfig,
	queue *transportsender.PublishedBatchQueue,
	prepared transportrecovery.PreparedFrame,
	started time.Time,
) (bool, error) {
	descriptor := prepared.Descriptor
	offer := transportrecovery.Offer{
		Version:               "fi-recovery-offer/0.1",
		SourceID:              descriptor.SourceID,
		PendingMembers:        descriptor.MemberCount,
		PendingCanonicalBytes: descriptor.CanonicalBytes,
		OldestBatchID:         descriptor.FirstBatchID,
		NewestBatchID:         descriptor.LastBatchID,
		ProposedMembers:       descriptor.MemberCount,
	}
	connection, closeTransport, err := dialAuthenticatedSenderTransport(ctx, config)
	if err != nil {
		return false, err
	}
	defer closeTransport()
	if err := transportrecovery.WriteOffer(connection, offer); err != nil {
		return false, wrapRecoveryTransportError(err, "send staged FI recovery offer")
	}
	decision, err := transportrecovery.ReadDecision(connection)
	if err != nil {
		return false, wrapRecoveryTransportError(err, "read staged FI recovery decision")
	}
	if !decision.Accepted {
		return false, fmt.Errorf("receiver rejected already-staged FI recovery transaction: %s", decision.Reason)
	}
	if descriptor.MemberCount > decision.MaxMembers || descriptor.CanonicalBytes > decision.MaxCanonicalBytes || descriptor.EncodedDataBytes > decision.MaxEncodedBytes {
		return false, errors.New("receiver recovery limits no longer permit already-staged exact recovery transaction")
	}
	fmt.Printf("Recovery:       RETRY\n")
	fmt.Printf("RecoveryID:     %s\n", descriptor.RecoveryID)
	fmt.Printf("RecoveryMembers:%d\n", descriptor.MemberCount)
	return finishRecovery(connection, config, queue, prepared, started)
}

func finishRecovery(
	connection *tls.Conn,
	config senderConfig,
	queue *transportsender.PublishedBatchQueue,
	prepared transportrecovery.PreparedFrame,
	started time.Time,
) (bool, error) {
	if err := transportrecovery.SendPreparedFrame(connection, prepared); err != nil {
		return false, wrapRecoveryTransportError(err, "send exact FI recovery frame")
	}
	authorization, err := transportsender.VerifyRecoveryAcknowledgement(connection, prepared)
	if err != nil {
		return false, wrapRecoveryTransportError(err, "verify FI recovery acknowledgement")
	}
	ack, _ := authorization.Acknowledgement()
	retirement, err := transportsender.RetireRecoveryMembers(config.SpoolDir, prepared, authorization)
	if err != nil {
		return false, fmt.Errorf("retire FI recovery member set after %s: %w", ack.Outcome, err)
	}
	if err := transportrecovery.RemovePreparedFrame(prepared); err != nil {
		return false, fmt.Errorf("clean retired FI recovery stage frame: %w", err)
	}
	if err := transportsender.AdvanceRecoveryQueue(queue, prepared); err != nil {
		return false, fmt.Errorf("advance FI queue after recovery retirement: %w", err)
	}
	fmt.Printf("Acknowledged:  %s\n", ack.Outcome)
	fmt.Printf("RetiredMembers: %d\n", retirement.Members)
	fmt.Printf("RetiredFiles:  %d manifests / %d data\n", retirement.ManifestsRemoved, retirement.DataRemoved)
	elapsed := time.Since(started)
	if elapsed < 0 {
		elapsed = 0
	}
	fmt.Printf("RecoveryElapsed:%s\n", elapsed.Round(time.Millisecond))
	if elapsed > 0 {
		rateMiB := (float64(prepared.Descriptor.CanonicalBytes) / (1024 * 1024)) / elapsed.Seconds()
		fmt.Printf("RecoveryRate:  %.2f canonical MiB/s\n", rateMiB)
	}
	return true, nil
}

func dialAuthenticatedSenderTransport(
	ctx context.Context,
	config senderConfig,
) (*tls.Conn, func(), error) {
	root, err := certstore.LoadLocalMachineCertificate(certstore.StoreRoot, config.RootCertificateSHA256)
	if err != nil {
		return nil, func() {}, fmt.Errorf("load FI root CA for authenticated sender transport: %w", err)
	}
	issuer, err := certstore.LoadLocalMachineCertificate(certstore.StoreCA, config.TransportIssuerSHA256)
	if err != nil {
		return nil, func() {}, fmt.Errorf("load FI transport issuer for authenticated sender transport: %w", err)
	}
	if err := validateTrustAnchors(root, issuer); err != nil {
		return nil, func() {}, err
	}
	crl, err := loadTransportCRL(config.TransportCRLPath)
	if err != nil {
		return nil, func() {}, err
	}
	if err := validateTransportCRL(crl, issuer, time.Now()); err != nil {
		return nil, func() {}, err
	}
	transportIdentity, err := certstore.LoadLocalMachineSigningIdentity(config.TransportCertificateSHA256)
	if err != nil {
		return nil, func() {}, fmt.Errorf("load FI source transport identity for authenticated sender transport: %w", err)
	}
	if err := validateSourceTransportIdentity(transportIdentity.Certificate, config.SourceID); err != nil {
		_ = transportIdentity.Close()
		return nil, func() {}, err
	}
	transportCertificate, err := transportIdentity.TLSCertificate()
	if err != nil {
		_ = transportIdentity.Close()
		return nil, func() {}, err
	}
	connection, err := dialReceiver(ctx, config, transportCertificate, root, issuer, crl)
	if err != nil {
		_ = transportIdentity.Close()
		return nil, func() {}, err
	}
	closeTransport := func() {
		_ = connection.Close()
		_ = transportIdentity.Close()
	}
	return connection, closeTransport, nil
}

func wrapRecoveryTransportError(err error, operation string) error {
	wrapped := fmt.Errorf("%s: %w", operation, err)
	if retryableSenderNetworkError(err) {
		return fmt.Errorf("%w: %w", transportsender.ErrRetryableTransport, wrapped)
	}
	return wrapped
}

func recoveryAttemptContext(parent context.Context, config senderConfig) (context.Context, context.CancelFunc) {
	timeout := config.RecoveryTimeout
	if timeout <= 0 {
		timeout = 2 * time.Hour
	}
	return context.WithTimeout(parent, timeout)
}

func recoveryTLSState(connection *tls.Conn) (string, string) {
	state := connection.ConnectionState()
	return tlsVersion(state.Version), tls.CipherSuiteName(state.CipherSuite)
}

func recoveryTrustSummary(root, issuer *x509.Certificate) string {
	if root == nil || issuer == nil {
		return "not_known"
	}
	return issuer.Subject.CommonName + " -> " + root.Subject.CommonName
}
