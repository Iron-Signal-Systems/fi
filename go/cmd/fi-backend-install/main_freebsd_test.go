// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfigPathArgument(t *testing.T) {
	path, err := configPath(
		[]string{"/root/fi-backend.conf"},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"configPath() error = %v",
			err,
		)
	}

	if path != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath() = %q",
			path,
		)
	}
}

func TestConfigPathPrompt(t *testing.T) {
	var output bytes.Buffer

	path, err := configPath(
		nil,
		strings.NewReader("/root/fi-backend.conf\n"),
		&output,
	)
	if err != nil {
		t.Fatalf(
			"configPath() error = %v",
			err,
		)
	}

	if path != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath() = %q",
			path,
		)
	}

	if output.String() != "Configuration file: " {
		t.Fatalf(
			"prompt = %q",
			output.String(),
		)
	}
}

func TestParseInvocationExplicitPreflight(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"preflight",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "preflight" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationLegacyConfigArgument(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "validate" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationRejectsTooManyArguments(t *testing.T) {
	_, err := parseInvocation(
		[]string{
			"preflight",
			"one",
			"two",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal(
			"parseInvocation() expected usage error",
		)
	}
}

func TestParseInvocationExplicitApplyZFSRoot(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-zfs-root",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-zfs-root" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyZFSHierarchy(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-zfs-hierarchy",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-zfs-hierarchy" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyJailRoots(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-jail-roots",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-jail-roots" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitApplyJailSubstrate(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-jail-substrate",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-jail-substrate" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitApplyIdentities(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-identities",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-identities" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitApplyDirectories(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-directories",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-directories" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitInspectHostUpdate(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"inspect-host-update",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "inspect-host-update" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitCheckHostUpdate(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"check-host-update",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "check-host-update" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitApplySORPackage(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-sor-package",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-sor-package" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplySORPostgreSQL(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-sor-postgresql",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-sor-postgresql" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitInitializeSORPostgreSQL(
	t *testing.T,
) {
	request, err := parseInvocation(
		[]string{
			"initialize-sor-postgresql",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command !=
		"initialize-sor-postgresql" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath !=
		"/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitInitializeSORDatabase(
	t *testing.T,
) {
	request, err := parseInvocation(
		[]string{
			"initialize-sor-database",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command !=
		"initialize-sor-database" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath !=
		"/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitVerifySORPostgreSQL(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-sor-postgresql",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-sor-postgresql" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitVerifySORDatabase(
	t *testing.T,
) {
	request, err :=
		parseInvocation(
			[]string{
				"verify-sor-database",
				"/root/fi-backend.conf",
			},
			strings.NewReader(""),
			&bytes.Buffer{},
		)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command !=
		"verify-sor-database" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath !=
		"/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyDevfs(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-devfs",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-devfs" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitVerifyDevfs(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-devfs",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-devfs" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyHostFiles(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-host-files",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-host-files" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitVerifyHostFiles(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-host-files",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-host-files" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyNetwork(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-network",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-network" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitVerifyNetwork(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-network",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-network" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationExplicitApplyPF(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-pf",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-pf" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitVerifyPF(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-pf",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-pf" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyLifecycle(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-lifecycle",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-lifecycle" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitVerifyLifecycle(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"verify-lifecycle",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "verify-lifecycle" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitUpdateHostFiles(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"update-host-files",
			"/root/fi-backend.conf",
			"/root/fi-approved-prior-host-files",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "update-host-files" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}

	if request.approvedPriorHostFiles != "/root/fi-approved-prior-host-files" {
		t.Fatalf(
			"approvedPriorHostFiles = %q",
			request.approvedPriorHostFiles,
		)
	}
}

func TestParseInvocationUpdateHostFilesRequiresPriorDirectory(t *testing.T) {
	_, err := parseInvocation(
		[]string{
			"update-host-files",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)

	if err == nil {
		t.Fatal(
			"update-host-files accepted missing approved-prior directory",
		)
	}
}

func TestParseInvocationRuntimeCommands(
	t *testing.T,
) {
	commands := []string{
		"apply-runtime",
		"verify-runtime",
	}

	for _, command := range commands {
		t.Run(
			command,
			func(t *testing.T) {
				request, err := parseInvocation(
					[]string{
						command,
						"/root/fi-backend.conf",
					},
					strings.NewReader(""),
					&bytes.Buffer{},
				)
				if err != nil {
					t.Fatalf(
						"parseInvocation() error = %v",
						err,
					)
				}

				if request.command != command {
					t.Fatalf(
						"command = %q, want %q",
						request.command,
						command,
					)
				}

				if request.configPath !=
					"/root/fi-backend.conf" {
					t.Fatalf(
						"configPath = %q",
						request.configPath,
					)
				}
			},
		)
	}
}

func TestParseInvocationRuntimeTransitionCommands(
	t *testing.T,
) {
	commands := []string{
		"adopt-runtime",
		"update-runtime",
	}

	for _, command := range commands {
		t.Run(
			command,
			func(t *testing.T) {
				request, err := parseInvocation(
					[]string{
						command,
						"/root/fi-backend.conf",
						"/root/approved-runtime",
					},
					strings.NewReader(""),
					&bytes.Buffer{},
				)
				if err != nil {
					t.Fatalf(
						"parseInvocation() error = %v",
						err,
					)
				}

				if request.command != command {
					t.Fatalf(
						"command = %q, want %q",
						request.command,
						command,
					)
				}

				if request.configPath !=
					"/root/fi-backend.conf" {
					t.Fatalf(
						"configPath = %q",
						request.configPath,
					)
				}

				if request.approvedPriorRuntime !=
					"/root/approved-runtime" {
					t.Fatalf(
						"approvedPriorRuntime = %q",
						request.approvedPriorRuntime,
					)
				}
			},
		)
	}
}

func TestParseInvocationRuntimeTransitionRequiresPrior(
	t *testing.T,
) {
	commands := []string{
		"adopt-runtime",
		"update-runtime",
	}

	for _, command := range commands {
		t.Run(
			command,
			func(t *testing.T) {
				_, err := parseInvocation(
					[]string{
						command,
						"/root/fi-backend.conf",
					},
					strings.NewReader(""),
					&bytes.Buffer{},
				)

				if err == nil {
					t.Fatal(
						"parseInvocation accepted runtime transition without approved prior directory",
					)
				}
			},
		)
	}
}
