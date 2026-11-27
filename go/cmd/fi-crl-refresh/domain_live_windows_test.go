// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

func TestLiveComputerDNSDomain(
	t *testing.T,
) {
	if strings.TrimSpace(
		os.Getenv(
			"FI_LIVE_CRL_REFRESH_DOMAIN",
		),
	) != "1" {
		t.Skip(
			"set FI_LIVE_CRL_REFRESH_DOMAIN=1 to run live DNS-domain discovery",
		)
	}

	domain, err :=
		computerDNSDomain()
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(
		domain,
	) == "" {
		t.Fatal(
			"live DNS domain is empty",
		)
	}

	t.Logf(
		"domain_dns=%q",
		domain,
	)
}
