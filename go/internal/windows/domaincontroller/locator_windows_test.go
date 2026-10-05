// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package domaincontroller

import "testing"

func TestDiscoverRejectsEmptyDomain(
	t *testing.T,
) {
	if _, err := Discover(
		"   ",
	); err == nil {
		t.Fatal(
			"empty domain DNS name was unexpectedly accepted",
		)
	}
}

func TestDiscoverWritableRejectsEmptyDomain(
	t *testing.T,
) {
	if _, err := DiscoverWritable(
		"",
	); err == nil {
		t.Fatal(
			"empty writable-domain DNS name was unexpectedly accepted",
		)
	}
}

func TestDiscoveryFlags(
	t *testing.T,
) {
	base :=
		dsDirectoryServiceRequired |
			dsIsDNSName |
			dsReturnDNSName

	if got := discoveryFlags(
		false,
	); got != base {
		t.Fatalf(
			"general discovery flags=%#x want=%#x",
			got,
			base,
		)
	}

	if got := discoveryFlags(
		true,
	); got != base|dsWritableRequired {
		t.Fatalf(
			"writable discovery flags=%#x want=%#x",
			got,
			base|dsWritableRequired,
		)
	}
}
