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
