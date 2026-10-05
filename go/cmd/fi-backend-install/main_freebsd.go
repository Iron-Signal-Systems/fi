// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
)

type invocation struct {
	command    string
	configPath string
}

// -----------------------------------------------------------------------------
// Command line
// -----------------------------------------------------------------------------

func configPath(
	args []string,
	input io.Reader,
	output io.Writer,
) (string, error) {
	switch len(args) {
	case 0:
		fmt.Fprint(
			output,
			"Configuration file: ",
		)

		reader := bufio.NewReader(input)

		value, err := reader.ReadString('\n')
		if err != nil && len(value) == 0 {
			return "", fmt.Errorf(
				"read configuration path: %w",
				err,
			)
		}

		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf(
				"configuration path cannot be empty",
			)
		}

		return value, nil

	case 1:
		value := strings.TrimSpace(args[0])
		if value == "" {
			return "", fmt.Errorf(
				"configuration path cannot be empty",
			)
		}

		return value, nil

	default:
		return "", fmt.Errorf(
			"expected zero or one configuration-file argument",
		)
	}
}

func parseInvocation(
	args []string,
	input io.Reader,
	output io.Writer,
) (invocation, error) {
	if len(args) == 0 {
		path, err := configPath(
			nil,
			input,
			output,
		)

		return invocation{
			command:    "validate",
			configPath: path,
		}, err
	}

	switch args[0] {
	case "apply-zfs-hierarchy", "apply-zfs-root", "preflight", "validate":
		path, err := configPath(
			args[1:],
			input,
			output,
		)

		return invocation{
			command:    args[0],
			configPath: path,
		}, err

	default:
		if len(args) != 1 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install [validate|preflight|apply-zfs-root|apply-zfs-hierarchy] [configuration-file]",
			)
		}

		return invocation{
			command:    "validate",
			configPath: args[0],
		}, nil
	}
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	fmt.Fprintln(
		os.Stdout,
		"FI Backend Installer",
	)
	fmt.Fprintln(os.Stdout)

	request, err := parseInvocation(
		os.Args[1:],
		os.Stdin,
		os.Stdout,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"FI INSTALLER INPUT BLOCKED: %v\n",
			err,
		)
		os.Exit(1)
	}

	config, err := backendinstall.LoadConfig(
		request.configPath,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"FI CONFIGURATION BLOCKED: %v\n",
			err,
		)
		os.Exit(1)
	}

	switch request.command {
	case "apply-zfs-root":
		_, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := backendinstall.ApplyFIRoot(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI ZFS ROOT APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI ZFS root apply complete.",
		)

	case "apply-zfs-hierarchy":
		_, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := backendinstall.ApplyFIHierarchy(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI ZFS HIERARCHY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI ZFS hierarchy apply complete.",
		)

	case "preflight":
		report, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := report.WriteText(
			os.Stdout,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT OUTPUT FAILED: %v\n",
				err,
			)
			os.Exit(2)
		}

	case "validate":
		printConfigSummary(
			os.Stdout,
			config,
		)

	default:
		fmt.Fprintf(
			os.Stderr,
			"FI INSTALLER INTERNAL ERROR: unsupported command: %s\n",
			request.command,
		)
		os.Exit(2)
	}
}

// -----------------------------------------------------------------------------
// Configuration output
// -----------------------------------------------------------------------------

func printConfigSummary(
	output io.Writer,
	config backendinstall.Config,
) {
	fmt.Fprintln(output)
	fmt.Fprintln(
		output,
		"Configuration accepted:",
	)

	fmt.Fprintf(
		output,
		"    host:               %s\n",
		config.Value("FI_HOSTNAME"),
	)

	fmt.Fprintf(
		output,
		"    host admin:         %s %s\n",
		config.Value("FI_HOST_ADMIN_IF"),
		config.Value("FI_HOST_ADMIN_ADDRESS"),
	)

	fmt.Fprintf(
		output,
		"    host gateway:       %s\n",
		config.Value("FI_HOST_ADMIN_GATEWAY"),
	)

	fmt.Fprintf(
		output,
		"    receiver external:  %s %s\n",
		config.Value("FI_RECEIVER_EXTERNAL_IF"),
		config.Value("FI_RECEIVER_EXTERNAL_ADDRESS"),
	)

	fmt.Fprintf(
		output,
		"    receiver gateway:   %s\n",
		config.Value("FI_RECEIVER_EXTERNAL_GATEWAY"),
	)

	fmt.Fprintf(
		output,
		"    source:             %s\n",
		config.Value("FI_RUNTIME_SOURCE_ID"),
	)

	fmt.Fprintln(output)
	fmt.Fprintln(
		output,
		"PREVALIDATION ONLY: no host state has been modified.",
	)
}
