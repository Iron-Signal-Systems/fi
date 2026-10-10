// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/releaselab"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error

	switch os.Args[1] {
	case "init":
		err = runInit(
			os.Args[2:],
		)
	case "sign":
		err = runSign(
			os.Args[2:],
		)
	case "sign-package":
		err = runSignPackage(
			os.Args[2:],
		)
	case "sign-installer":
		err = runSignInstaller(
			os.Args[2:],
		)
	case "trust-root":
		err = runTrustRoot(
			os.Args[2:],
		)
	case "untrust-root":
		err = runUntrustRoot(
			os.Args[2:],
		)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"ERROR:",
			err,
		)
		os.Exit(1)
	}
}

func runInit(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"init",
		flag.ContinueOnError,
	)
	output := flags.String(
		"out",
		"",
		"directory for development release private keys and metadata",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*output) == "" {
		return fmt.Errorf(
			"-out is required",
		)
	}

	result, err := releaselab.Initialize(
		*output,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"FI DEVELOPMENT RELEASE LAB INITIALIZED",
	)
	fmt.Println(
		"Private-key directory:",
		result.OutputDirectory,
	)
	fmt.Println(
		"Policy authority SPKI SHA256:",
		result.PolicyAuthoritySPKISHA256,
	)
	fmt.Println(
		"Release signer certificate SHA256:",
		result.ReleaseSignerCertSHA256,
	)
	fmt.Println(
		"Release signer SPKI SHA256:",
		result.ReleaseSignerSPKISHA256,
	)
	fmt.Println(
		"Development code-signing root certificate SHA256:",
		result.CodeSigningRootCertSHA256,
	)
	fmt.Println()
	fmt.Println(
		"These are development-only keys. Do not copy the private-key directory to an FI source server.",
	)
	return nil
}

func runSign(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"sign",
		flag.ContinueOnError,
	)
	keys := flags.String(
		"keys",
		"",
		"development release private-key directory created by init",
	)
	manifest := flags.String(
		"manifest",
		"",
		"manifest.json input path",
	)
	output := flags.String(
		"out",
		"",
		"public release-artifact output directory",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*keys) == "" ||
		strings.TrimSpace(*manifest) == "" ||
		strings.TrimSpace(*output) == "" {
		return fmt.Errorf(
			"-keys, -manifest, and -out are required",
		)
	}

	if err := releaselab.SignPackagePublicMetadata(
		*keys,
		*manifest,
		*output,
	); err != nil {
		return err
	}

	root, err := filepath.Abs(
		*output,
	)
	if err != nil {
		return err
	}
	fmt.Println(
		"FI DEVELOPMENT PUBLIC RELEASE METADATA CREATED",
	)
	fmt.Println(
		"Output:",
		root,
	)
	fmt.Println(
		"Private keys were not copied to the output directory.",
	)
	return nil
}

func runSignPackage(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"sign-package",
		flag.ContinueOnError,
	)
	keys := flags.String(
		"keys",
		"",
		"development release private-key directory created by init",
	)
	releaseID := flags.String(
		"release-id",
		"",
		"release_id for the signed FI Windows source package",
	)
	installer := flags.String(
		"installer",
		"",
		"unsigned fi-install.exe input; the source file is copied and is not modified",
	)
	binaryRoot := flags.String(
		"bin",
		"",
		"directory containing unsigned fi-collector.exe, fi-usn-reader.exe, fi-obj-reader.exe, and fi-sender.exe inputs",
	)
	output := flags.String(
		"out",
		"",
		"new output directory for the complete signed package",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*keys) == "" ||
		strings.TrimSpace(*releaseID) == "" ||
		strings.TrimSpace(*installer) == "" ||
		strings.TrimSpace(*binaryRoot) == "" ||
		strings.TrimSpace(*output) == "" {
		return fmt.Errorf(
			"-keys, -release-id, -installer, -bin, and -out are required",
		)
	}

	result, err := releaselab.BuildSignedPackage(
		*keys,
		*releaseID,
		*installer,
		*binaryRoot,
		*output,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"FI DEVELOPMENT AUTHENTICODE PACKAGE CREATED",
	)
	fmt.Println(
		"Output:",
		result.OutputDirectory,
	)
	fmt.Println(
		"Manifest:",
		result.ManifestPath,
	)
	for _, payload := range result.Payloads {
		fmt.Printf(
			"%s %s SHA256=%s\n",
			payload.Role,
			payload.Name,
			payload.SHA256,
		)
	}
	fmt.Println()
	fmt.Println(
		"Source executables were not modified. Private keys were not copied to the package.",
	)
	fmt.Println(
		"Development Authenticode signatures are intentionally not timestamped.",
	)
	return nil
}

func runSignInstaller(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"sign-installer",
		flag.ContinueOnError,
	)
	keys := flags.String(
		"keys",
		"",
		"development release private-key directory created by init",
	)
	installer := flags.String(
		"installer",
		"",
		"unsigned fi-install.exe input; the source file is copied and is not modified",
	)
	output := flags.String(
		"out",
		"",
		"new signed fi-install.exe output path",
	)
	if err := flags.Parse(
		args,
	); err != nil {
		return err
	}
	if strings.TrimSpace(
		*keys,
	) == "" ||
		strings.TrimSpace(
			*installer,
		) == "" ||
		strings.TrimSpace(
			*output,
		) == "" {
		return fmt.Errorf(
			"-keys, -installer, and -out are required",
		)
	}

	hash, err := releaselab.BuildSignedInstaller(
		*keys,
		*installer,
		*output,
	)
	if err != nil {
		return err
	}

	absoluteOutput, err := filepath.Abs(
		*output,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"FI DEVELOPMENT AUTHENTICODE INSTALLER CREATED",
	)
	fmt.Println(
		"Output:",
		absoluteOutput,
	)
	fmt.Println(
		"SHA256:",
		hash,
	)
	fmt.Println()
	fmt.Println(
		"Source installer was not modified.",
	)
	fmt.Println(
		"Development Authenticode signature is intentionally not timestamped.",
	)
	return nil
}

func runTrustRoot(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"trust-root",
		flag.ContinueOnError,
	)
	certificate := flags.String(
		"cert",
		"",
		"development code-signing root certificate",
	)
	crl := flags.String(
		"crl",
		"",
		"development code-signing CRL",
	)
	confirm := flags.Bool(
		"confirm-lab-root-install",
		false,
		"required explicit acknowledgement that a development root and CRL will be added to LocalMachine stores",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf(
			"-confirm-lab-root-install is required",
		)
	}
	if strings.TrimSpace(*certificate) == "" {
		return fmt.Errorf(
			"-cert is required",
		)
	}
	if strings.TrimSpace(*crl) == "" {
		return fmt.Errorf(
			"-crl is required",
		)
	}

	state, err := releaselab.TrustDevelopmentCodeSigningMaterial(
		*certificate,
		*crl,
	)
	if err != nil {
		return err
	}
	fmt.Println(
		"Installed DEVELOPMENT code-signing root into LocalMachine\\ROOT",
	)
	fmt.Println(
		"Installed DEVELOPMENT code-signing CRL into LocalMachine\\CA",
	)
	fmt.Println(
		"Certificate SHA256:",
		state.RootCertificateSHA256,
	)
	fmt.Println(
		"CRL SHA256:",
		state.CRLSHA256,
	)
	return nil
}

func runUntrustRoot(
	args []string,
) error {
	flags := flag.NewFlagSet(
		"untrust-root",
		flag.ContinueOnError,
	)
	certificateHash := flags.String(
		"cert-sha256",
		"",
		"exact development root certificate SHA-256",
	)
	crlHash := flags.String(
		"crl-sha256",
		"",
		"exact development CRL SHA-256",
	)
	confirm := flags.Bool(
		"confirm-lab-root-remove",
		false,
		"required explicit acknowledgement that the matching development root and CRL will be removed from LocalMachine stores",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf(
			"-confirm-lab-root-remove is required",
		)
	}
	if strings.TrimSpace(*certificateHash) == "" {
		return fmt.Errorf(
			"-cert-sha256 is required",
		)
	}
	if strings.TrimSpace(*crlHash) == "" {
		return fmt.Errorf(
			"-crl-sha256 is required",
		)
	}

	if err := releaselab.UntrustDevelopmentCodeSigningMaterial(
		*certificateHash,
		*crlHash,
	); err != nil {
		return err
	}
	fmt.Println(
		"Removed DEVELOPMENT code-signing CRL from LocalMachine\\CA",
	)
	fmt.Println(
		"Removed DEVELOPMENT code-signing root from LocalMachine\\ROOT",
	)
	return nil
}

func usage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: fi-release-lab <init|sign|sign-package|sign-installer|trust-root|untrust-root> [options]",
	)
}
