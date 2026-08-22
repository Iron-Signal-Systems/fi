// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

// This file owns caller-path validation and governed-root containment rules.
// Caller text is validated before Windows opens it, but the final containment
// decision uses paths resolved from open handles rather than trusting the
// caller's original strings.

// validateLocalAbsolutePath accepts only local drive-absolute paths supported by
// the direct NTFS collector.
//
// Named-stream paths such as C:\file.txt:Zone.Identifier are rejected. FI opens
// the base NTFS object and enumerates its streams separately.
func validateLocalAbsolutePath(path []uint16) error {
	if len(path) == 0 {
		return ErrInvalidPath
	}
	for _, unit := range path {
		if unit == 0 {
			return ErrInvalidPath
		}
	}

	switch {
	case isDriveAbsolutePath(path):
		if containsColonAfter(path, 1) {
			return ErrStreamQualifiedPath
		}
		return nil
	case isExtendedDrivePath(path):
		if containsColonAfter(path, 5) {
			return ErrStreamQualifiedPath
		}
		return nil
	default:
		return ErrUnsafePathForm
	}
}

func containsColonAfter(path []uint16, driveColon int) bool {
	for i := driveColon + 1; i < len(path); i++ {
		if path[i] == ':' {
			return true
		}
	}
	return false
}

func isDriveAbsolutePath(path []uint16) bool {
	return len(path) >= 3 && isASCIILetter(path[0]) && path[1] == ':' && path[2] == '\\'
}

func isExtendedDrivePath(path []uint16) bool {
	return len(path) >= 7 &&
		hasASCIIPrefix(path, `\\?\`) &&
		isASCIILetter(path[4]) &&
		path[5] == ':' &&
		path[6] == '\\'
}

func localAbsoluteRootLength(path []uint16) (int, bool) {
	switch {
	case isDriveAbsolutePath(path):
		return 3, true
	case isExtendedDrivePath(path):
		return 7, true
	default:
		return 0, false
	}
}

// parentLocalAbsolutePath returns the lexical parent of an already-validated
// local drive-absolute caller path without converting the path through UTF-8.
// This preserves the exact UTF-16 code units used by the Windows collector.
func parentLocalAbsolutePath(path []uint16) ([]uint16, error) {
	if err := validateLocalAbsolutePath(path); err != nil {
		return nil, err
	}
	rootLength, ok := localAbsoluteRootLength(path)
	if !ok {
		return nil, ErrUnsafePathForm
	}

	end := len(path)
	for end > rootLength && path[end-1] == '\\' {
		end--
	}
	if end <= rootLength {
		return append([]uint16(nil), path[:rootLength]...), nil
	}

	for index := end - 1; index >= rootLength; index-- {
		if path[index] == '\\' {
			return append([]uint16(nil), path[:index]...), nil
		}
	}
	return append([]uint16(nil), path[:rootLength]...), nil
}

func isASCIILetter(unit uint16) bool {
	return (unit >= 'A' && unit <= 'Z') || (unit >= 'a' && unit <= 'z')
}

func hasASCIIPrefix(path []uint16, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for index := range prefix {
		if path[index] != uint16(prefix[index]) {
			return false
		}
	}
	return true
}

func trimTrailingSeparators(value []uint16) []uint16 {
	end := len(value)
	for end > 0 && value[end-1] == '\\' {
		end--
	}
	return value[:end]
}

func equalUTF16(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasUTF16Prefix(value, prefix []uint16) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range prefix {
		if value[index] != prefix[index] {
			return false
		}
	}
	return true
}

// pathContainedBy compares normalized volume-GUID paths returned from open
// Windows handles.
//
// Equality is allowed because the governed root itself is a valid target.
// Prefix matches require a path separator boundary so \Data does not authorize
// \Database.
func pathContainedBy(root, target []uint16) bool {
	root = trimTrailingSeparators(root)
	target = trimTrailingSeparators(target)
	if len(root) == 0 || len(target) == 0 {
		return false
	}
	if equalUTF16(root, target) {
		return true
	}
	return len(target) > len(root) &&
		hasUTF16Prefix(target, root) &&
		target[len(root)] == '\\'
}
