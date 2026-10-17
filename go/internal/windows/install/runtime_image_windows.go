// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"path/filepath"
	"strings"
)

func expectedFIServiceExecutablePath(
	name string,
) (string, bool) {
	switch name {
	case "FICollector":
		return `C:\Program Files\FI\fi-collector.exe`, true
	case "FIUSNReader":
		return `C:\Program Files\FI\fi-usn-reader.exe`, true
	case "FIObjReader":
		return `C:\Program Files\FI\fi-obj-reader.exe`, true
	case "FICRLRefresher":
		return `C:\Program Files\FI\fi-crl-refresher.exe`, true
	case "FISender":
		return `C:\Program Files\FI\fi-sender.exe`, true
	default:
		return "", false
	}
}

func fiServiceBinaryPathForExecutable(
	name string,
	executable string,
) (string, error) {
	executable =
		strings.TrimSpace(
			executable,
		)

	if executable == "" {
		return "", fmt.Errorf(
			"service %s executable path is empty",
			name,
		)
	}

	switch name {
	case "FICollector":
		return `"` + executable + `" -service`, nil

	case "FIUSNReader",
		"FIObjReader",
		"FICRLRefresher",
		"FISender":

		return `"` + executable + `"`, nil

	default:
		return "", fmt.Errorf(
			"unknown FI service %q",
			name,
		)
	}
}

func sameWindowsExecutablePath(
	left string,
	right string,
) bool {
	left =
		strings.TrimSpace(
			left,
		)

	right =
		strings.TrimSpace(
			right,
		)

	if left == "" ||
		right == "" ||
		left == notKnown ||
		right == notKnown {
		return false
	}

	return strings.EqualFold(
		filepath.Clean(
			left,
		),
		filepath.Clean(
			right,
		),
	)
}
