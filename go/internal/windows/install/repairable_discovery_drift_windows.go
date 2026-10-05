// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

func normalizeRepairableApproval2DiscoveryDrift(
	report *Report,
) {
	if report == nil {
		return
	}

	refresherService, found :=
		findService(
			report.Services,
			"FICRLRefresher",
		)

	if !found ||
		refresherService.Presence != presenceAbsent {
		return
	}

	_, refresher, _, _, err :=
		desiredACLAccounts(
			*report,
		)
	if err != nil {
		return
	}

	rightsDetail :=
		"account=" +
			refresher +
			" rights= expected=SeServiceLogonRight only"

	aclDetail :=
		refresher +
			" Read/Execute without write/ACL administration missing"

	for index := range report.Checks {
		check :=
			&report.Checks[index]

		if check.Status != checkFail {
			continue
		}

		switch check.Name {
		case "FICRLRefresher direct-right contract":
			if check.Detail == rightsDetail {
				check.Status =
					checkInfo
			}

		case "FI config directory desired ACL contract",
			"FI program directory desired ACL contract":

			if check.Detail == aclDetail {
				check.Status =
					checkInfo
			}
		}
	}
}
