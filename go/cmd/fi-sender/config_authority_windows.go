// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func parseSenderConfig() (senderConfig, error) {
	operational, operationalPath, err := config.LoadDefault()
	if err != nil {
		return senderConfig{}, err
	}
	if operational.VersionID != config.Version11 {
		return senderConfig{}, fmt.Errorf(
			"FI sender requires operational configuration version %s; loaded %s from %s",
			config.Version11,
			operational.VersionID,
			operationalPath,
		)
	}

	trust, _, err := config.LoadDefaultTransportTrust()
	if err != nil {
		return senderConfig{}, err
	}

	value := senderConfig{
		BatchSigningCertificateSHA256: trust.BatchSigningCertificateSHA256,
		GenerationInterval:            operational.Sender.GenerationInterval,
		GenerationMaxEncodedBytes:     operational.Sender.GenerationMaxEncodedBytes,
		GenerationTransferTimeout:     operational.Sender.GenerationTransferTimeout,
		PollInterval:                  operational.Sender.PollInterval,
		ReceiverAddress:               operational.Receiver.Address,
		ReceiverName:                  operational.Receiver.Name,
		RecoveryThresholdBytes:        operational.Sender.RecoveryThresholdBytes,
		RecoveryTimeout:               operational.Sender.RecoveryTimeout,
		RetryBackoff:                  operational.Sender.RetryBackoff,
		RootCertificateSHA256:         trust.RootCertificateSHA256,
		SourceID:                      operational.Source.ID,
		SpoolDir:                      operational.Storage.SpoolDir,
		StageDir:                      operational.Storage.StageDir,
		Timeout:                       operational.Receiver.Timeout,
		TransportCRLPath:              trust.TransportCRLPath,
		TransportCertificateSHA256:    trust.TransportCertificateSHA256,
		TransportIssuerSHA256:         trust.TransportIssuerSHA256,
	}

	flags := flag.NewFlagSet("fi-sender", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	flags.StringVar(&value.BatchSigningCertificateSHA256, "batch-signing-cert-sha256", value.BatchSigningCertificateSHA256, "troubleshooting override for FI batch-signing certificate SHA-256")
	flags.StringVar(&value.ManifestPath, "manifest", "", "troubleshooting override: exact published Phase 1 FI batch manifest")
	flags.DurationVar(&value.PollInterval, "poll-interval", value.PollInterval, "troubleshooting override for queue poll interval")
	flags.StringVar(&value.ReceiverAddress, "receiver", value.ReceiverAddress, "troubleshooting override for FI receiver TCP address")
	flags.StringVar(&value.ReceiverName, "receiver-name", value.ReceiverName, "troubleshooting override for FI receiver certificate DNS name")
	flags.DurationVar(&value.GenerationInterval, "generation-interval", value.GenerationInterval, "troubleshooting override for generation sealing cadence")
	flags.Uint64Var(&value.GenerationMaxEncodedBytes, "generation-max-encoded-bytes", value.GenerationMaxEncodedBytes, "troubleshooting override for generation encoded-byte limit")
	flags.DurationVar(&value.GenerationTransferTimeout, "generation-transfer-timeout", value.GenerationTransferTimeout, "troubleshooting override for generation transfer timeout")
	flags.Uint64Var(&value.RecoveryThresholdBytes, "recovery-threshold-bytes", value.RecoveryThresholdBytes, "troubleshooting override for adaptive recovery threshold")
	flags.DurationVar(&value.RecoveryTimeout, "recovery-timeout", value.RecoveryTimeout, "troubleshooting override for adaptive recovery timeout")
	flags.DurationVar(&value.RetryBackoff, "retry-backoff", value.RetryBackoff, "troubleshooting override for retry backoff")
	flags.StringVar(&value.RootCertificateSHA256, "root-cert-sha256", value.RootCertificateSHA256, "troubleshooting override for FI root CA SHA-256")
	flags.StringVar(&value.SourceID, "source", value.SourceID, "troubleshooting override for FI source ID")
	flags.StringVar(&value.SpoolDir, "spool-dir", value.SpoolDir, "troubleshooting override for FI spool directory")
	flags.StringVar(&value.StageDir, "stage-dir", value.StageDir, "troubleshooting override for durable outbound-stage directory")
	flags.DurationVar(&value.Timeout, "timeout", value.Timeout, "troubleshooting override for one FI transport transaction timeout")
	flags.StringVar(&value.TransportCRLPath, "transport-crl", value.TransportCRLPath, "troubleshooting override for FI transport CRL path")
	flags.StringVar(&value.TransportCertificateSHA256, "transport-cert-sha256", value.TransportCertificateSHA256, "troubleshooting override for FI source transport certificate SHA-256")
	flags.StringVar(&value.TransportIssuerSHA256, "transport-issuer-sha256", value.TransportIssuerSHA256, "troubleshooting override for FI transport issuer SHA-256")

	if err := flags.Parse(os.Args[1:]); err != nil {
		return senderConfig{}, err
	}
	if flags.NArg() != 0 {
		return senderConfig{}, errors.New("fi-sender does not accept positional arguments")
	}

	var trustOverrides []string
	var senderOverrides []string
	var storageOverrides []string

	flags.Visit(func(current *flag.Flag) {
		switch current.Name {
		case "batch-signing-cert-sha256",
			"root-cert-sha256",
			"transport-cert-sha256",
			"transport-crl",
			"transport-issuer-sha256":
			trustOverrides = append(trustOverrides, current.Name)
		case "manifest":
			// Exact-manifest troubleshooting changes both sender mode and
			// the configured storage source. Require both authorities.
			senderOverrides = append(senderOverrides, current.Name)
			storageOverrides = append(storageOverrides, current.Name)
		case "spool-dir", "stage-dir":
			storageOverrides = append(storageOverrides, current.Name)
		default:
			senderOverrides = append(senderOverrides, current.Name)
		}
	})

	if len(trustOverrides) != 0 &&
		(!operational.Troubleshoot.Enabled || !operational.Troubleshoot.AllowTrustCLIOverride) {
		return senderConfig{}, fmt.Errorf(
			"manual FI transport-trust overrides are disabled by configuration: %s",
			strings.Join(trustOverrides, ", "),
		)
	}
	if len(storageOverrides) != 0 &&
		(!operational.Troubleshoot.Enabled || !operational.Troubleshoot.AllowStorageCLIOverride) {
		return senderConfig{}, fmt.Errorf(
			"manual FI storage overrides are disabled by configuration: %s",
			strings.Join(storageOverrides, ", "),
		)
	}
	if len(senderOverrides) != 0 &&
		(!operational.Troubleshoot.Enabled || !operational.Troubleshoot.AllowSenderCLIOverride) {
		return senderConfig{}, fmt.Errorf(
			"manual FI sender overrides are disabled by configuration: %s",
			strings.Join(senderOverrides, ", "),
		)
	}

	if len(senderOverrides) != 0 ||
		len(storageOverrides) != 0 ||
		len(trustOverrides) != 0 {
		writeAuthorizedOverrideWarning(
			os.Stderr,
			senderOverrides,
			storageOverrides,
			trustOverrides,
		)
	}

	manifestVisited := false
	spoolVisited := false
	generationIntervalVisited := false
	recoveryThresholdVisited := false

	flags.Visit(func(current *flag.Flag) {
		switch current.Name {
		case "manifest":
			manifestVisited = true
		case "spool-dir":
			spoolVisited = true
		case "generation-interval":
			generationIntervalVisited = true
		case "recovery-threshold-bytes":
			recoveryThresholdVisited = true
		}
	})

	if manifestVisited && !spoolVisited {
		value.SpoolDir = ""

		// Exact-manifest mode is not queue/generation mode. Remove configured
		// queue-only defaults unless the operator explicitly supplied them,
		// in which case normal validation must reject the contradiction.
		if !generationIntervalVisited {
			value.GenerationInterval = 0
		}
		if !recoveryThresholdVisited {
			value.RecoveryThresholdBytes = 0
		}
	}

	if err := validateSenderConfig(value); err != nil {
		return senderConfig{}, err
	}
	return value, nil
}

func writeAuthorizedOverrideWarning(
	writer io.Writer,
	senderOverrides []string,
	storageOverrides []string,
	trustOverrides []string,
) {
	if writer == nil {
		return
	}

	fmt.Fprintf(
		writer,
		"WARNING: FI troubleshooting CLI override authorized by configuration; sender=[%s] storage=[%s] trust=[%s]\n",
		strings.Join(senderOverrides, ", "),
		strings.Join(storageOverrides, ", "),
		strings.Join(trustOverrides, ", "),
	)
}
