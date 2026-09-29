// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"syscall"
	"testing"
)

func TestLiveApproval2GMSANativeProcedureAvailability(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_GMSA_EXPORTS",
	) != "1" {
		t.Skip(
			"set FI_LIVE_GMSA_EXPORTS=1 to characterize managed-service-account exports",
		)
	}

	type library struct {
		dll  *syscall.LazyDLL
		name string
	}

	libraries := []library{
		{
			dll: syscall.NewLazyDLL(
				"logoncli.dll",
			),
			name: "logoncli.dll",
		},
		{
			dll: syscall.NewLazyDLL(
				"netapi32.dll",
			),
			name: "netapi32.dll",
		},
	}

	procedures := []string{
		"NetAddServiceAccount",
		"NetIsServiceAccount",
		"NetRemoveServiceAccount",
	}

	for _, procedure := range procedures {
		found := 0

		for _, library := range libraries {
			proc := library.dll.NewProc(
				procedure,
			)

			err := proc.Find()
			if err != nil {
				t.Logf(
					"%s!%s unavailable: %v",
					library.name,
					procedure,
					err,
				)
				continue
			}

			found++

			t.Logf(
				"%s!%s available",
				library.name,
				procedure,
			)
		}

		if found == 0 {
			t.Fatalf(
				"%s is unavailable from both characterized DLLs",
				procedure,
			)
		}
	}
}
