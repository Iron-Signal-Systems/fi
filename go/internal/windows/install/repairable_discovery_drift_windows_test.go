// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestACLDiscoveryFailureStatus(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		err   error
		label string
		want  string
	}{
		{
			err:   windows.ERROR_FILE_NOT_FOUND,
			label: "FI CRL active file",
			want:  checkInfo,
		},
		{
			err:   windows.ERROR_PATH_NOT_FOUND,
			label: "FI CRL refresher journal directory",
			want:  checkInfo,
		},
		{
			err:   windows.ERROR_FILE_NOT_FOUND,
			label: "FI config directory",
			want:  checkFail,
		},
		{
			err: errors.New(
				"access denied",
			),
			label: "FI CRL active file",
			want:  checkFail,
		},
	}

	for _, test := range tests {
		got :=
			aclDiscoveryFailureStatus(
				test.label,
				test.err,
			)

		if got != test.want {
			t.Fatalf(
				"label=%q err=%v status=%s want=%s",
				test.label,
				test.err,
				got,
				test.want,
			)
		}
	}
}

func TestNormalizeRepairableApproval2DiscoveryDrift(
	t *testing.T,
) {
	t.Parallel()

	var report Report

	report.Host.Computer =
		"AdminBox"

	report.Join.Name =
		"ISS"

	report.Services =
		[]ServiceState{
			{
				Name:     "FICRLRefresher",
				Presence: presenceAbsent,
			},
		}

	const refresher = `ISS\gFI-CRL-ADMINBOX$`

	report.Checks =
		[]Check{
			{
				Name: "FICRLRefresher direct-right contract",
				Detail: "account=" +
					refresher +
					" rights= expected=SeServiceLogonRight only",
				Status: checkFail,
			},
			{
				Name: "FI config directory desired ACL contract",
				Detail: refresher +
					" Read/Execute without write/ACL administration missing",
				Status: checkFail,
			},
			{
				Name: "FI program directory desired ACL contract",
				Detail: refresher +
					" Read/Execute without write/ACL administration missing",
				Status: checkFail,
			},
		}

	normalizeRepairableApproval2DiscoveryDrift(
		&report,
	)

	for _, check := range report.Checks {
		if check.Status != checkInfo {
			t.Fatalf(
				"%s status=%s want=%s detail=%s",
				check.Name,
				check.Status,
				checkInfo,
				check.Detail,
			)
		}
	}
}

func TestNormalizeRepairableApproval2DiscoveryDriftFailsClosed(
	t *testing.T,
) {
	t.Parallel()

	var report Report

	report.Host.Computer =
		"AdminBox"

	report.Join.Name =
		"ISS"

	report.Services =
		[]ServiceState{
			{
				Name:     "FICRLRefresher",
				Presence: presenceAbsent,
			},
		}

	const refresher = `ISS\gFI-CRL-ADMINBOX$`

	report.Checks =
		[]Check{
			{
				Name: "FICRLRefresher direct-right contract",
				Detail: "account=" +
					refresher +
					" rights=SeBackupPrivilege expected=SeServiceLogonRight only",
				Status: checkFail,
			},
			{
				Name: "FI config directory desired ACL contract",
				Detail: refresher +
					" Read/Execute without write/ACL administration missing; SYSTEM FullControl missing",
				Status: checkFail,
			},
		}

	normalizeRepairableApproval2DiscoveryDrift(
		&report,
	)

	for _, check := range report.Checks {
		if check.Status != checkFail {
			t.Fatalf(
				"%s status=%s want=%s detail=%s",
				check.Name,
				check.Status,
				checkFail,
				check.Detail,
			)
		}
	}

	report.Services[0].Presence =
		presencePresent

	report.Checks =
		[]Check{
			{
				Name: "FICRLRefresher direct-right contract",
				Detail: "account=" +
					refresher +
					" rights= expected=SeServiceLogonRight only",
				Status: checkFail,
			},
			{
				Name: "FI program directory desired ACL contract",
				Detail: refresher +
					" Read/Execute without write/ACL administration missing",
				Status: checkFail,
			},
		}

	normalizeRepairableApproval2DiscoveryDrift(
		&report,
	)

	for _, check := range report.Checks {
		if check.Status != checkFail {
			t.Fatalf(
				"present service %s status=%s want=%s",
				check.Name,
				check.Status,
				checkFail,
			)
		}
	}
}
