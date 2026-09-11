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
		"usage: fi-receiver -transport-listen -bind <address:port> -source <source-id>",
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

	if err := validateSourceID(*sourceID); err != nil {
		fail(err)
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

	result, err := transportreceiver.ListenOnce(
		ctx,
		transportreceiver.Config{
			BindAddress:       *bindAddress,
			CRL:               transportCRL,
			Root:              root,
			ServerCertificate: serverCertificate,
			Source:            sourceConfig.Authorization,
			TransportIssuer:   transportIssuer,
		},
	)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "FI receiver stopped.")
			return
		}

		fail(err)
	}

	fmt.Printf("Source:        %s\n", result.SourceID)
	fmt.Printf("TLS:           %s\n", result.TLSVersion)
	fmt.Printf("CipherSuite:   %s\n", result.CipherSuite)
	fmt.Println("MutualTLS:     true")
	fmt.Println("Authorization: AUTHORIZED")
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
		return
	}

	fmt.Println("Parse state             INCOMPLETE")
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
