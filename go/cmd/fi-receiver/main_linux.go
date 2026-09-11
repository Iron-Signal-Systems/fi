// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

func loadCertificate(path string) (*x509.Certificate, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read certificate %q: %w",
			path,
			err,
		)
	}

	block, rest := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf(
			"%q does not contain PEM data",
			path,
		)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf(
			"%q contains PEM type %q, want CERTIFICATE",
			path,
			block.Type,
		)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"%q contains unexpected data after the certificate",
			path,
		)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse certificate %q: %w",
			path,
			err,
		)
	}

	return certificate, nil
}

func loadCRL(path string) (*x509.RevocationList, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read CRL %q: %w",
			path,
			err,
		)
	}

	block, rest := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf(
			"%q does not contain PEM data",
			path,
		)
	}

	if block.Type != "X509 CRL" {
		return nil, fmt.Errorf(
			"%q contains PEM type %q, want X509 CRL",
			path,
			block.Type,
		)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"%q contains unexpected data after the CRL",
			path,
		)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse CRL %q: %w",
			path,
			err,
		)
	}

	return crl, nil
}

func printTransportUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-receiver -transport-listen -bind <address:port> -source <source-id>",
	)
}

func printTrustUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-receiver trust status",
	)
}

func printTrustState(name string, present bool) {
	state := "MISSING"
	if present {
		state = "PRESENT"
	}

	fmt.Printf("%-23s %s\n", name, state)
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

	root, err := loadCertificate(receivertrust.RootCAPath)
	if err != nil {
		fail(err)
	}

	transportIssuer, err := loadCertificate(
		receivertrust.TransportIssuerPath,
	)
	if err != nil {
		fail(err)
	}

	transportCRL, err := loadCRL(
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
		return
	}

	fmt.Println("Presence state          INCOMPLETE")
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
