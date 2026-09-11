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

	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	receiverCertPath    = "/etc/fi/pki/receiver/certs/fi-receiver-tls-fullchain.pem"
	receiverKeyPath     = "/etc/fi/pki/receiver/private/fi-receiver-tls.key.pem"
	rootCAPath          = "/etc/fi/pki/trust/fi-root-ca.crt.pem"
	sourceConfigRoot    = "/etc/fi/sources"
	transportCRLPath    = "/etc/fi/pki/trust/fi-transport-ca.crl.pem"
	transportIssuerPath = "/etc/fi/pki/trust/fi-transport-ca.crt.pem"
)

func main() {
	transportListen := flag.Bool(
		"transport-listen",
		false,
		"accept one authenticated FI transport connection",
	)

	bindAddress := flag.String(
		"bind",
		"",
		"receiver bind address, for example 192.168.1.119:8443",
	)

	sourceID := flag.String(
		"source",
		"",
		"authorized FI source ID, for example iss-fs-01.iss.local",
	)

	flag.Parse()

	if !*transportListen {
		printUsage()
		os.Exit(2)
	}

	if flag.NArg() != 0 {
		printUsage()
		os.Exit(2)
	}

	if *bindAddress == "" {
		fail(errors.New("-bind is required"))
	}

	if err := validateSourceID(*sourceID); err != nil {
		fail(err)
	}

	sourceConfigPath := filepath.Join(
		sourceConfigRoot,
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
		receiverCertPath,
		receiverKeyPath,
	)
	if err != nil {
		fail(fmt.Errorf("load receiver TLS identity: %w", err))
	}

	root, err := loadCertificate(rootCAPath)
	if err != nil {
		fail(err)
	}

	transportIssuer, err := loadCertificate(transportIssuerPath)
	if err != nil {
		fail(err)
	}

	transportCRL, err := loadCRL(transportCRLPath)
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

func printUsage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-receiver -transport-listen -bind <address:port> -source <source-id>",
	)
}

func validateSourceID(sourceID string) error {
	if sourceID == "" {
		return errors.New("-source is required")
	}

	if strings.ContainsAny(sourceID, `/\`) {
		return errors.New("source ID must not contain path separators")
	}

	if sourceID == "." || sourceID == ".." {
		return errors.New("invalid source ID")
	}

	return nil
}
