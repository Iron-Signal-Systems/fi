// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package securityevent

import (
	"fmt"
	"strings"
)

func isDriveLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func driveRootAliases(root, device, volumeGUID string) ([]string, error) {
	if len(root) < 3 || !isDriveLetter(root[0]) || root[1] != ':' ||
		(root[2] != '\\' && root[2] != '/') {
		return nil, fmt.Errorf("not an absolute drive-letter governed root: %q", root)
	}
	const harddiskPrefix = `\device\harddiskvolume`
	deviceLower := strings.ToLower(device)
	if !strings.HasPrefix(deviceLower, harddiskPrefix) || strings.ContainsRune(device, 0) {
		return nil, fmt.Errorf("unrecognized direct NTFS device path for governed root %q", root)
	}
	deviceNumber := deviceLower[len(harddiskPrefix):]
	if deviceNumber == "" {
		return nil, fmt.Errorf("NTFS device number is missing for governed root %q", root)
	}
	for _, digit := range deviceNumber {
		if digit < '0' || digit > '9' {
			return nil, fmt.Errorf("invalid NTFS device path for governed root %q", root)
		}
	}
	if !strings.HasPrefix(strings.ToLower(volumeGUID), `\\?\volume{`) ||
		!strings.HasSuffix(volumeGUID, `}\`) || strings.ContainsRune(volumeGUID, 0) {
		return nil, fmt.Errorf("unrecognized volume GUID path for governed root %q", root)
	}
	relative := strings.TrimLeft(strings.ReplaceAll(root[2:], "/", `\`), `\`)
	join := func(prefix string) string {
		if relative == "" {
			return strings.TrimRight(prefix, `\`)
		}
		return strings.TrimRight(prefix, `\`) + `\` + relative
	}
	return []string{join(device), join(volumeGUID)}, nil
}
