// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "trust" {
		runTrustCommand(os.Args[2:])
		return
	}

	runTransportCommand()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func printTransportUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-receiver -transport-listen -bind <address:port> -custody-root <path> -max-data-bytes <bytes> [-recovery-max-canonical-bytes <bytes> -recovery-max-encoded-bytes <bytes> -recovery-max-members <count>] [-generation-enable -generation-custody-root <path> -generation-recorded-root <path> -generation-max-canonical-bytes <bytes> -generation-max-encoded-bytes <bytes> -generation-max-manifest-bytes <bytes>] -source <source-id>",
	)
}

func printTrustParseState(
	name string,
	state receivertrust.ParseState,
) {
	result := "INVALID"
	if state.Parsed {
		result = "PARSED"
	}

	fmt.Printf("%-23s %s\n", name, result)

	if !state.Parsed && state.Detail != "" {
		fmt.Printf("  %s\n", state.Detail)
	}
}

func printTrustValidationState(
	name string,
	state receivertrust.ValidationState,
) {
	result := "INVALID"
	if state.Valid {
		result = "VALID"
	}

	fmt.Printf("%-23s %s\n", name, result)

	if !state.Valid && state.Detail != "" {
		fmt.Printf("  %s\n", state.Detail)
	}
}

func printTrustState(name string, present bool) {
	state := "MISSING"
	if present {
		state = "PRESENT"
	}

	fmt.Printf("%-23s %s\n", name, state)
}

func printTrustUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-receiver trust status",
	)
}

func runTransportCommand() {
	flags := flag.NewFlagSet(
		"fi-receiver",
		flag.ContinueOnError,
	)
	flags.SetOutput(os.Stderr)

	transportListen := flags.Bool(
		"transport-listen",
		false,
		"accept one authenticated FI transport connection",
	)

	bindAddress := flags.String(
		"bind",
		"",
		"receiver bind address, for example 192.168.1.119:8443",
	)

	custodyRoot := flags.String(
		"custody-root",
		"",
		"durable receiver custody root directory",
	)

	maxDataBytes := flags.Uint64(
		"max-data-bytes",
		0,
		"maximum FI batch data payload accepted per transport transaction",
	)

	recoveryMaxCanonicalBytes := flags.Uint64(
		"recovery-max-canonical-bytes",
		0,
		"maximum canonical bytes accepted in one negotiated FI recovery transaction; 0 disables recovery",
	)
	recoveryMaxEncodedBytes := flags.Uint64(
		"recovery-max-encoded-bytes",
		0,
		"maximum encoded bytes accepted in one negotiated FI recovery transaction; 0 disables recovery",
	)
	recoveryMaxMembers := flags.Uint64(
		"recovery-max-members",
		0,
		"maximum original published batches accepted in one negotiated FI recovery transaction; 0 disables recovery",
	)

	generationEnable := flags.Bool(
		"generation-enable",
		false,
		"explicitly enable FI generation transport and startup recovery",
	)
	generationCustodyRoot := flags.String(
		"generation-custody-root",
		"",
		"durable FI generation FIGT custody root; requires -generation-enable",
	)
	generationRecordedRoot := flags.String(
		"generation-recorded-root",
		"",
		"durable FI generation recorded-receipt root; requires -generation-enable",
	)
	generationReadyRoot := flags.String(
		"generation-ready-root",
		"",
		"non-authoritative FI generation ingest-ready root; requires -generation-enable",
	)
	generationMaxCanonicalBytes := flags.Uint64(
		"generation-max-canonical-bytes",
		0,
		"maximum canonical bytes accepted in one FI generation; requires -generation-enable",
	)
	generationMaxEncodedBytes := flags.Uint64(
		"generation-max-encoded-bytes",
		0,
		"maximum encoded bytes accepted in one FI generation; requires -generation-enable",
	)
	generationMaxManifestBytes := flags.Uint64(
		"generation-max-manifest-bytes",
		0,
		"maximum collector manifest bytes accepted inside one FI generation; requires -generation-enable",
	)

	sourceID := flags.String(
		"source",
		"",
		"authorized FI source ID, for example iss-fs-01.iss.local",
	)

	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if !*transportListen {
		printTransportUsage()
		os.Exit(2)
	}

	if flags.NArg() != 0 {
		printTransportUsage()
		os.Exit(2)
	}

	if *bindAddress == "" {
		fail(errors.New("-bind is required"))
	}

	if *custodyRoot == "" {
		fail(errors.New("-custody-root is required"))
	}

	if *maxDataBytes == 0 {
		fail(errors.New("-max-data-bytes must be greater than zero"))
	}

	generationOptions := generationRuntimeOptions{
		CustodyRoot:       *generationCustodyRoot,
		Enabled:           *generationEnable,
		MaxCanonicalBytes: *generationMaxCanonicalBytes,
		MaxEncodedBytes:   *generationMaxEncodedBytes,
		MaxManifestBytes:  *generationMaxManifestBytes,
		ReadyRoot:         *generationReadyRoot,
		RecordedRoot:      *generationRecordedRoot,
	}

	if err := generationOptions.validate(); err != nil {
		fail(err)
	}

	if err := validateSourceID(*sourceID); err != nil {
		fail(err)
	}

	readiness := receivertrust.InspectReadiness()
	if !readiness.Ready {
		detail := readiness.Detail
		if detail == "" {
			detail = "unspecified trust validation failure"
		}

		fail(fmt.Errorf(
			"receiver trust not ready: %s",
			detail,
		))
	}

	sourceConfigPath := filepath.Join(
		receivertrust.SourceRegistryPath,
		*sourceID+".conf",
	)

	sourceConfig, err := transporttrust.LoadSourceConfig(sourceConfigPath)
	if err != nil {
		fail(err)
	}

	if !strings.EqualFold(
		sourceConfig.Authorization.SourceID,
		*sourceID,
	) {
		fail(fmt.Errorf(
			"source config identity %q does not match requested source %q",
			sourceConfig.Authorization.SourceID,
			*sourceID,
		))
	}

	serverCertificate, err := tls.LoadX509KeyPair(
		receivertrust.ReceiverCertPath,
		receivertrust.ReceiverKeyPath,
	)
	if err != nil {
		fail(fmt.Errorf(
			"load receiver TLS identity: %w",
			err,
		))
	}

	root, err := receivertrust.LoadCertificate(
		receivertrust.RootCAPath,
	)
	if err != nil {
		fail(err)
	}

	batchIssuer, err := receivertrust.LoadCertificate(
		receivertrust.BatchIssuerPath,
	)
	if err != nil {
		fail(err)
	}

	batchCRL, err := receivertrust.LoadCRL(
		receivertrust.BatchCRLPath,
	)
	if err != nil {
		fail(err)
	}

	transportIssuer, err := receivertrust.LoadCertificate(
		receivertrust.TransportIssuerPath,
	)
	if err != nil {
		fail(err)
	}

	transportCRL, err := receivertrust.LoadCRL(
		receivertrust.TransportCRLPath,
	)
	if err != nil {
		fail(err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	receiverConfig := transportreceiver.Config{
		BatchCRL:                  batchCRL,
		BatchIssuer:               batchIssuer,
		BindAddress:               *bindAddress,
		CustodyRoot:               *custodyRoot,
		MaxDataBytes:              *maxDataBytes,
		RecoveryMaxCanonicalBytes: *recoveryMaxCanonicalBytes,
		RecoveryMaxEncodedBytes:   *recoveryMaxEncodedBytes,
		RecoveryMaxMembers:        *recoveryMaxMembers,
		Root:                      root,
		ServerCertificate:         serverCertificate,
		Source:                    sourceConfig.Authorization,
		TransportCRL:              transportCRL,
		TransportIssuer:           transportIssuer,
	}

	generationOptions.apply(
		&receiverConfig,
	)

	if generationOptions.Enabled {
		startup, err := transportreceiver.RecoverGenerationStartup(
			receiverConfig,
			time.Now(),
		)
		if err != nil {
			fail(fmt.Errorf(
				"recover FI generation startup state: %w",
				err,
			))
		}

		fmt.Printf(
			"GenerationStartup: discovered=%d new=%d already_recorded=%d ready_published=%d ready_warnings=%d removed_provisional=%d\n",
			startup.Discovered,
			startup.RecordedNew,
			startup.AlreadyRecorded,
			startup.ReadyPublished,
			startup.ReadyWarnings,
			startup.RemovedProvisional,
		)
		if startup.ReadyWarning != "" {
			fmt.Fprintf(
				os.Stderr,
				"WARNING: FI generation startup ingest-ready publication: %s\n",
				startup.ReadyWarning,
			)
		}
	}

	result, err := transportreceiver.ListenOnce(
		ctx,
		receiverConfig,
	)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "FI receiver stopped.")
			return
		}

		fail(err)
	}

	fmt.Printf("Source:        %s\n", result.SourceID)
	if result.Generation {
		fmt.Printf("GenerationID:  %s\n", result.GenerationID)
		fmt.Printf("Artifacts:     %d\n", result.GenerationArtifactCount)
		fmt.Printf("Batches:       %d\n", result.GenerationBatchCount)
		fmt.Printf("Records:       %d\n", result.GenerationRecordCount)
		fmt.Printf("CanonicalBytes:%d\n", result.GenerationCanonicalBytes)
		fmt.Printf("EncodedBytes:  %d\n", result.GenerationEncodedBytes)
		fmt.Printf("GenerationData:%d\n", result.GenerationDataBytes)
		fmt.Printf("RecordedState: %s\n", result.GenerationRecordedState)
		fmt.Printf("GenerationACK: %s\n", result.GenerationAcknowledgement)
		fmt.Printf("TransferSHA256:%s\n", result.GenerationTransferSHA256)
		if result.GenerationReadyWarning != "" {
			fmt.Fprintf(
				os.Stderr,
				"WARNING: FI generation ingest-ready publication: %s\n",
				result.GenerationReadyWarning,
			)
		}
	} else if result.Recovery {
		fmt.Printf("RecoveryID:    %s\n", result.RecoveryID)
		fmt.Printf("Members:       %d\n", result.RecoveryMembers)
		fmt.Printf("CanonicalBytes:%d\n", result.RecoveryCanonicalBytes)
		fmt.Printf("DataBytes:     %d\n", result.DataBytes)
		fmt.Printf("FrameSHA256:   %s\n", result.FrameSHA256)
	} else {
		fmt.Printf("BatchID:       %s\n", result.BatchID)
		fmt.Printf("DataBytes:     %d\n", result.DataBytes)
		fmt.Printf("FrameSHA256:   %s\n", result.FrameSHA256)
	}
	fmt.Printf("Custody:       %s\n", result.CustodyDisposition)
	fmt.Printf("TLS:           %s\n", result.TLSVersion)
	fmt.Printf("CipherSuite:   %s\n", result.CipherSuite)
	fmt.Println("MutualTLS:     true")
	fmt.Println("Authorization: AUTHORIZED")
	fmt.Println("BatchSigning:  AUTHORIZED")
}

func runTrustCommand(args []string) {
	if len(args) != 1 || args[0] != "status" {
		printTrustUsage()
		os.Exit(2)
	}

	status, err := receivertrust.Inspect()
	if err != nil {
		fail(err)
	}

	printTrustState("Root CA", status.RootCA.Present)
	printTrustState(
		"Transport issuing CA",
		status.TransportIssuer.Present,
	)
	printTrustState(
		"Batch signing CA",
		status.BatchIssuer.Present,
	)
	printTrustState(
		"Transport CRL",
		status.TransportCRL.Present,
	)
	printTrustState(
		"Batch signing CRL",
		status.BatchCRL.Present,
	)
	printTrustState(
		"Receiver certificate",
		status.ReceiverCert.Present,
	)
	printTrustState(
		"Receiver private key",
		status.ReceiverKey.Present,
	)
	printTrustState(
		"Source registry",
		status.SourceRegistry.Present,
	)

	fmt.Println()

	if status.Complete {
		fmt.Println("Presence state          COMPLETE")
	} else {
		fmt.Println("Presence state          INCOMPLETE")
	}

	fmt.Println()

	parseStatus := receivertrust.InspectParsing()

	printTrustParseState("Root CA", parseStatus.RootCA)
	printTrustParseState(
		"Transport issuing CA",
		parseStatus.TransportIssuer,
	)
	printTrustParseState(
		"Batch signing CA",
		parseStatus.BatchIssuer,
	)
	printTrustParseState(
		"Transport CRL",
		parseStatus.TransportCRL,
	)
	printTrustParseState(
		"Batch signing CRL",
		parseStatus.BatchCRL,
	)
	printTrustParseState(
		"Receiver certificate",
		parseStatus.ReceiverCert,
	)

	fmt.Println()

	if parseStatus.Complete {
		fmt.Println("Parse state             COMPLETE")
	} else {
		fmt.Println("Parse state             INCOMPLETE")
	}

	fmt.Println()

	rootCAValidation := receivertrust.InspectRootCAValidation()

	printTrustValidationState(
		"Root CA",
		rootCAValidation,
	)

	fmt.Println()
	transportIssuerValidation := receivertrust.InspectTransportIssuerValidation()
	batchIssuerValidation := receivertrust.InspectBatchIssuerValidation()

	printTrustValidationState(
		"Transport issuing CA",
		transportIssuerValidation,
	)
	printTrustValidationState(
		"Batch signing CA",
		batchIssuerValidation,
	)

	fmt.Println()
	fmt.Println("Root CA coverage        STRUCTURE_SELF_SIGNATURE_VALIDITY")
	fmt.Println("Issuing CA coverage     STRUCTURE_ROOT_SIGNATURE_VALIDITY")

	fmt.Println()

	transportCRLValidation := receivertrust.InspectTransportCRLValidation()
	batchCRLValidation := receivertrust.InspectBatchCRLValidation()

	printTrustValidationState(
		"Transport CRL",
		transportCRLValidation,
	)
	printTrustValidationState(
		"Batch signing CRL",
		batchCRLValidation,
	)

	fmt.Println()
	fmt.Println("CRL coverage            ISSUER_SIGNATURE_FRESHNESS")

	fmt.Println()

	receiverCertificateValidation :=
		receivertrust.InspectReceiverCertificateValidation()
	receiverKeyValidation :=
		receivertrust.InspectReceiverKeyValidation()

	printTrustValidationState(
		"Receiver certificate",
		receiverCertificateValidation,
	)
	printTrustValidationState(
		"Receiver private key",
		receiverKeyValidation,
	)

	fmt.Println()
	receiverHostnameValidation :=
		receivertrust.InspectReceiverHostnameValidation()

	printTrustValidationState(
		"Receiver hostname",
		receiverHostnameValidation,
	)

	fmt.Println()
	receiverRevocationValidation :=
		receivertrust.InspectReceiverRevocationValidation()

	printTrustValidationState(
		"Receiver revocation",
		receiverRevocationValidation,
	)

	fmt.Println()
	fmt.Println("Receiver coverage       LEAF_ROLE_OU_FULLCHAIN_SERVER_AUTH_KEY_MATCH_HOSTNAME_REVOCATION")

	fmt.Println()

	sourceRegistryValidation :=
		receivertrust.InspectSourceRegistryValidation()

	printTrustValidationState(
		"Source registry",
		sourceRegistryValidation,
	)

	fmt.Println()
	fmt.Println("Registry coverage       PARSE_FILENAME_UNIQUENESS_CA_PINS")

	fmt.Println()

	trustCustodyValidation :=
		receivertrust.InspectTrustCustodyValidation()

	printTrustValidationState(
		"Trust custody",
		trustCustodyValidation,
	)

	fmt.Println()
	fmt.Println("Custody coverage        OWNER_GROUP_TYPE_RUNTIME_ACCESS_WRITE_PROTECTION_NO_SYMLINKS")

	readiness := receivertrust.EvaluateReadiness(
		receivertrust.ReadinessInput{
			BatchCRL:            batchCRLValidation,
			BatchIssuer:         batchIssuerValidation,
			Parsing:             parseStatus,
			Presence:            status,
			ReceiverCertificate: receiverCertificateValidation,
			ReceiverHostname:    receiverHostnameValidation,
			ReceiverKey:         receiverKeyValidation,
			ReceiverRevocation:  receiverRevocationValidation,
			RootCA:              rootCAValidation,
			SourceRegistry:      sourceRegistryValidation,
			TransportCRL:        transportCRLValidation,
			TransportIssuer:     transportIssuerValidation,
			TrustCustody:        trustCustodyValidation,
		},
	)

	fmt.Println()

	trustState := "NOT_READY"
	if readiness.Ready {
		trustState = "READY"
	}

	fmt.Printf("%-23s %s\n", "Trust state", trustState)

	if !readiness.Ready && readiness.Detail != "" {
		fmt.Printf("  %s\n", readiness.Detail)
	}
}

func validateSourceID(sourceID string) error {
	if sourceID == "" {
		return errors.New("-source is required")
	}

	if strings.ContainsAny(sourceID, `/\`) {
		return errors.New(
			"source ID must not contain path separators",
		)
	}

	if sourceID == "." || sourceID == ".." {
		return errors.New("invalid source ID")
	}

	return nil
}
