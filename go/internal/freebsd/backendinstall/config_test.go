// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"strings"
	"testing"
)

const fixturePath = "../../../../tools/deployment/freebsd/verify/fixtures/fi-bootstrap.test.conf"

func TestLoadConfigAcceptanceFixture(t *testing.T) {
	config, err := LoadConfig(fixturePath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if got := config.Value("FI_HOST_ADMIN_ADDRESS"); got != "192.168.1.218/24" {
		t.Fatalf("FI_HOST_ADMIN_ADDRESS = %q", got)
	}

	if got := config.Value("FI_RECEIVER_EXTERNAL_ADDRESS"); got != "192.168.1.219/24" {
		t.Fatalf("FI_RECEIVER_EXTERNAL_ADDRESS = %q", got)
	}
}

func TestParseConfigRejectsDuplicateKey(t *testing.T) {
	fixture := readFixture(t)
	fixture += "\nFI_HOSTNAME=\"duplicate.invalid\"\n"

	_, err := ParseConfig(strings.NewReader(fixture))
	if err == nil {
		t.Fatal("ParseConfig() expected duplicate-key error")
	}

	if !strings.Contains(err.Error(), "duplicate configuration key") {
		t.Fatalf("ParseConfig() error = %v", err)
	}
}

func TestParseConfigRejectsUnknownKey(t *testing.T) {
	fixture := readFixture(t)
	fixture += "\nFI_UNKNOWN=\"value\"\n"

	_, err := ParseConfig(strings.NewReader(fixture))
	if err == nil {
		t.Fatal("ParseConfig() expected unknown-key error")
	}

	if !strings.Contains(err.Error(), "unknown configuration key") {
		t.Fatalf("ParseConfig() error = %v", err)
	}
}

func TestValidateConfigRejectsAdminGatewayOutsideSubnet(t *testing.T) {
	config := parseFixtureReplacement(
		t,
		`FI_HOST_ADMIN_GATEWAY="192.168.1.1"`,
		`FI_HOST_ADMIN_GATEWAY="10.1.1.1"`,
	)

	err := ValidateConfig(config)
	if err == nil {
		t.Fatal("ValidateConfig() expected gateway error")
	}

	if !strings.Contains(err.Error(), "FI_HOST_ADMIN_GATEWAY") {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
}

func TestValidateConfigRejectsAdminReceiverAddressCollision(t *testing.T) {
	config := parseFixtureReplacement(
		t,
		`FI_HOST_ADMIN_ADDRESS="192.168.1.218/24"`,
		`FI_HOST_ADMIN_ADDRESS="192.168.1.219/24"`,
	)

	err := ValidateConfig(config)
	if err == nil {
		t.Fatal("ValidateConfig() expected address collision")
	}

	if !strings.Contains(
		err.Error(),
		"FI_HOST_ADMIN_ADDRESS conflicts with FI_RECEIVER_EXTERNAL_ADDRESS",
	) {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
}

func TestValidateConfigRejectsAdminReceiverInterfaceCollision(t *testing.T) {
	config := parseFixtureReplacement(
		t,
		`FI_HOST_ADMIN_IF="vtnet0"`,
		`FI_HOST_ADMIN_IF="vtnet1"`,
	)

	err := ValidateConfig(config)
	if err == nil {
		t.Fatal("ValidateConfig() expected interface collision")
	}
}

func TestValidateConfigRejectsInternalAdminOverlap(t *testing.T) {
	fixture := readFixture(t)

	replacements := [][2]string{
		{
			`FI_HOST_ADMIN_ADDRESS="192.168.1.218/24"`,
			`FI_HOST_ADMIN_ADDRESS="10.77.10.218/24"`,
		},
		{
			`FI_HOST_ADMIN_GATEWAY="192.168.1.1"`,
			`FI_HOST_ADMIN_GATEWAY="10.77.10.1"`,
		},
	}

	for _, replacement := range replacements {
		if strings.Count(fixture, replacement[0]) != 1 {
			t.Fatalf(
				"fixture anchor count for %q != 1",
				replacement[0],
			)
		}

		fixture = strings.Replace(
			fixture,
			replacement[0],
			replacement[1],
			1,
		)
	}

	config, err := ParseConfig(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	err = ValidateConfig(config)
	if err == nil {
		t.Fatal("ValidateConfig() expected internal-network overlap")
	}

	if !strings.Contains(err.Error(), "overlaps FI_MGMT_NETWORK") {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
}

func parseFixtureReplacement(
	t *testing.T,
	old string,
	replacement string,
) Config {
	t.Helper()

	fixture := readFixture(t)

	if strings.Count(fixture, old) != 1 {
		t.Fatalf("fixture anchor count for %q != 1", old)
	}

	fixture = strings.Replace(fixture, old, replacement, 1)

	config, err := ParseConfig(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	return config
}

func readFixture(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", fixturePath, err)
	}

	return string(content)
}

func TestValidateConfigRejectsNetworkContractViolations(t *testing.T) {
	tests := []struct {
		name         string
		replacements [][2]string
	}{
		{
			name: "overlapping internal networks",
			replacements: [][2]string{
				{
					`FI_WORK_NETWORK="10.77.20.0/24"`,
					`FI_WORK_NETWORK="10.77.10.128/25"`,
				},
				{
					`FI_RECEIVER_WORK_ADDRESS="10.77.20.20/24"`,
					`FI_RECEIVER_WORK_ADDRESS="10.77.10.140/25"`,
				},
				{
					`FI_INGEST_WORK_ADDRESS="10.77.20.21/24"`,
					`FI_INGEST_WORK_ADDRESS="10.77.10.141/25"`,
				},
				{
					`FI_SOR_DB_WORK_ADDRESS="10.77.20.22/24"`,
					`FI_SOR_DB_WORK_ADDRESS="10.77.10.142/25"`,
				},
			},
		},
		{
			name: "interface prefix mismatch",
			replacements: [][2]string{
				{
					`FI_RECEIVER_MGMT_ADDRESS="10.77.10.20/24"`,
					`FI_RECEIVER_MGMT_ADDRESS="10.77.10.20/16"`,
				},
			},
		},
		{
			name: "management gateway address collision",
			replacements: [][2]string{
				{
					`FI_RECEIVER_MGMT_ADDRESS="10.77.10.20/24"`,
					`FI_RECEIVER_MGMT_ADDRESS="10.77.10.1/24"`,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := readFixture(t)

			for _, replacement := range test.replacements {
				if strings.Count(fixture, replacement[0]) != 1 {
					t.Fatalf(
						"fixture anchor count for %q != 1",
						replacement[0],
					)
				}

				fixture = strings.Replace(
					fixture,
					replacement[0],
					replacement[1],
					1,
				)
			}

			config, err := ParseConfig(
				strings.NewReader(fixture),
			)
			if err != nil {
				t.Fatalf(
					"ParseConfig() error = %v",
					err,
				)
			}

			if err := ValidateConfig(config); err == nil {
				t.Fatal(
					"ValidateConfig() expected network-contract error",
				)
			}
		})
	}
}

func TestValidateConfigRejectsNonCanonicalAbsolutePaths(t *testing.T) {
	tests := []struct {
		name        string
		replacement string
	}{
		{
			name:        "parent component",
			replacement: `FI_RECEIVER_ROOT="/usr/local/jails/containers/../fi-receiver"`,
		},
		{
			name:        "current component",
			replacement: `FI_RECEIVER_ROOT="/usr/local/jails/containers/./fi-receiver"`,
		},
		{
			name:        "duplicate separator",
			replacement: `FI_RECEIVER_ROOT="/usr/local/jails//containers/fi-receiver"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := parseFixtureReplacement(
				t,
				`FI_RECEIVER_ROOT="/usr/local/jails/containers/fi-receiver"`,
				test.replacement,
			)

			err := ValidateConfig(config)
			if err == nil {
				t.Fatal(
					"ValidateConfig() expected non-canonical path error",
				)
			}
		})
	}
}

func TestValidateConfigRejectsNameAndIdentityContractViolations(t *testing.T) {
	longLabel := strings.Repeat("a", 64)

	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "hostname label exceeds 63 characters",
			old:         `FI_HOSTNAME="fi-test.invalid"`,
			replacement: `FI_HOSTNAME="` + longLabel + `.invalid"`,
		},
		{
			name:        "DNS label exceeds 63 characters",
			old:         `FI_HOST_DNS_SEARCH="iss.local"`,
			replacement: `FI_HOST_DNS_SEARCH="` + longLabel + `.local"`,
		},
		{
			name:        "runtime UID below allocation range",
			old:         `FI_RUNTIME_UID="4100"`,
			replacement: `FI_RUNTIME_UID="999"`,
		},
		{
			name:        "runtime UID above allocation range",
			old:         `FI_RUNTIME_UID="4100"`,
			replacement: `FI_RUNTIME_UID="32001"`,
		},
		{
			name:        "runtime GID below allocation range",
			old:         `FI_RUNTIME_GID="4100"`,
			replacement: `FI_RUNTIME_GID="999"`,
		},
		{
			name:        "runtime GID above allocation range",
			old:         `FI_RUNTIME_GID="4100"`,
			replacement: `FI_RUNTIME_GID="32001"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := parseFixtureReplacement(
				t,
				test.old,
				test.replacement,
			)

			if err := ValidateConfig(config); err == nil {
				t.Fatal(
					"ValidateConfig() expected contract error",
				)
			}
		})
	}
}
