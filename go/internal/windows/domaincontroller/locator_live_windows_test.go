// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package domaincontroller

import (
	"os"
	"strings"
	"testing"
)

func TestLiveDomainControllerDiscovery(
	t *testing.T,
) {
	if strings.TrimSpace(
		os.Getenv(
			"FI_LIVE_DOMAIN_CONTROLLER",
		),
	) != "1" {
		t.Skip(
			"set FI_LIVE_DOMAIN_CONTROLLER=1 to run live DC locator acceptance",
		)
	}

	domainDNS :=
		strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_DOMAIN_DNS",
			),
		)

	if domainDNS == "" {
		t.Fatal(
			"FI_LIVE_DOMAIN_DNS is required",
		)
	}

	general, err :=
		Discover(
			domainDNS,
		)
	if err != nil {
		t.Fatalf(
			"general DC discovery: %v",
			err,
		)
	}

	writable, err :=
		DiscoverWritable(
			domainDNS,
		)
	if err != nil {
		t.Fatalf(
			"writable DC discovery: %v",
			err,
		)
	}

	t.Logf(
		"general_dc=%q forest=%q dc_site=%q client_site=%q",
		general.DomainController,
		general.ForestDNS,
		general.DCSite,
		general.ClientSite,
	)

	t.Logf(
		"writable_dc=%q forest=%q dc_site=%q client_site=%q",
		writable.DomainController,
		writable.ForestDNS,
		writable.DCSite,
		writable.ClientSite,
	)
}
