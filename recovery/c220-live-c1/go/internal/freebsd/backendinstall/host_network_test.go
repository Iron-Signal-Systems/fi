// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func TestBuildHostNetworkPlan(t *testing.T) {
	config, err := LoadConfig(
		fixturePath,
	)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := buildHostNetworkPlan(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.Bridges) != 2 {
		t.Fatalf(
			"bridge count = %d",
			len(plan.Bridges),
		)
	}

	if plan.Bridges[0].Name != "bridge10" ||
		plan.Bridges[0].Address != "10.77.10.1/24" {
		t.Fatalf(
			"management bridge = %#v",
			plan.Bridges[0],
		)
	}

	if plan.Bridges[1].Name != "bridge20" ||
		plan.Bridges[1].Address != "10.77.20.1/24" {
		t.Fatalf(
			"work bridge = %#v",
			plan.Bridges[1],
		)
	}

	if len(plan.Files) != 2 {
		t.Fatalf(
			"network file count = %d",
			len(plan.Files),
		)
	}

	netif := string(
		plan.Files[0].Content,
	)

	for _, expected := range []string{
		`ifconfig_bridge10="inet 10.77.10.1/24 up"`,
		`ifconfig_bridge20="inet 10.77.20.1/24 up"`,
		`cloned_interfaces="${cloned_interfaces} bridge20"`,
	} {
		if !strings.Contains(
			netif,
			expected,
		) {
			t.Fatalf(
				"netif policy lacks %q",
				expected,
			)
		}
	}

	routing := string(
		plan.Files[1].Content,
	)

	if !strings.Contains(
		routing,
		`gateway_enable="YES"`,
	) {
		t.Fatal(
			"routing policy does not enable IPv4 forwarding",
		)
	}
}

func TestClassifyHostNetworkBridgeOutputMatch(t *testing.T) {
	spec := hostNetworkBridgeSpec{
		Address: "10.77.10.1/24",
		Name:    "bridge10",
	}

	output := `bridge10: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
    ether 02:00:00:00:00:10
    inet 10.77.10.1/24 broadcast 10.77.10.255
    groups: bridge
`

	state := classifyHostNetworkBridgeOutput(
		spec,
		output,
	)

	if state != hostNetworkBridgeMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestClassifyHostNetworkBridgeOutputRejectsAddressDrift(t *testing.T) {
	spec := hostNetworkBridgeSpec{
		Address: "10.77.20.1/24",
		Name:    "bridge20",
	}

	output := `bridge20: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
    ether 02:00:00:00:00:20
    inet 10.77.20.99/24 broadcast 10.77.20.255
    groups: bridge
`

	state := classifyHostNetworkBridgeOutput(
		spec,
		output,
	)

	if state != hostNetworkBridgeForeign {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestClassifyHostNetworkBridgeOutputRejectsMember(t *testing.T) {
	spec := hostNetworkBridgeSpec{
		Address: "10.77.10.1/24",
		Name:    "bridge10",
	}

	output := `bridge10: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
    ether 02:00:00:00:00:10
    inet 10.77.10.1/24 broadcast 10.77.10.255
    member: eprm0a flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
    groups: bridge
`

	state := classifyHostNetworkBridgeOutput(
		spec,
		output,
	)

	if state != hostNetworkBridgeForeign {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestValidateConfigRejectsWorkHostAddressCollision(t *testing.T) {
	config := parseFixtureReplacement(
		t,
		`FI_WORK_HOST_ADDRESS="10.77.20.1/24"`,
		`FI_WORK_HOST_ADDRESS="10.77.20.20/24"`,
	)

	if err := ValidateConfig(
		config,
	); err == nil {
		t.Fatal(
			"ValidateConfig() accepted workload host/jail collision",
		)
	}
}
