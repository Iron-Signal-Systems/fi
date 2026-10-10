// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

type WindowsProfile struct {
	BuildNumber uint32
	Name        string
}

func ProfileForBuild(buildNumber uint32) (WindowsProfile, bool) {
	switch buildNumber {
	case 14393:
		return WindowsProfile{
			BuildNumber: buildNumber,
			Name:        "Windows Server 2016",
		}, true
	case 17763:
		return WindowsProfile{
			BuildNumber: buildNumber,
			Name:        "Windows Server 2019",
		}, true
	case 20348:
		return WindowsProfile{
			BuildNumber: buildNumber,
			Name:        "Windows Server 2022",
		}, true
	case 26100:
		return WindowsProfile{
			BuildNumber: buildNumber,
			Name:        "Windows Server 2025",
		}, true
	default:
		return WindowsProfile{
			BuildNumber: buildNumber,
			Name:        "not_known",
		}, false
	}
}

func installerMutationSupportedBuild(
	buildNumber uint32,
) bool {
	_, ok := ProfileForBuild(
		buildNumber,
	)

	return ok
}

// objReaderRightsMutationEnabledBuild controls the exact builds on which the
// installer may apply the FIObjReader least-privilege rights contract.
//
// Build 14393 is accepted. Build 17763 is enabled on this characterization
// branch so the same contract can be proven on the controlled Server 2019 lab
// target. Server 2022 and Server 2025 remain fail-closed until their separate
// FIObjReader acceptance runs are complete.
func objReaderRightsMutationEnabledBuild(
	buildNumber uint32,
) bool {
	switch buildNumber {
	case 14393, 17763:
		return true
	default:
		return false
	}
}
