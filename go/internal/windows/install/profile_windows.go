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
// Builds 14393 and 17763 retain their accepted installer rights contract.
// Build 20348 is enabled for Server 2022, including its accepted installer run.
// Build 26100 is enabled by the separately characterized Server 2025 contract,
// sharing the exact FIObjReader rights gate with 20348. Candidate-specific
// release acceptance remains separate from this exact-build policy gate.
func objReaderRightsMutationEnabledBuild(
	buildNumber uint32,
) bool {
	if buildNumber == 26100 {
		return objReaderRightsMutationEnabledBuild(20348)
	}

	switch buildNumber {
	case 14393, 17763, 20348:
		return true
	default:
		return false
	}
}
