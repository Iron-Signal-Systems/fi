package ntfs

func validateLocalAbsolutePath(path []uint16) error {
	if len(path) == 0 {
		return ErrInvalidPath
	}
	for _, unit := range path {
		if unit == 0 {
			return ErrInvalidPath
		}
	}
	if isDriveAbsolutePath(path) || isExtendedDrivePath(path) {
		return nil
	}
	return ErrUnsafePathForm
}

func isDriveAbsolutePath(path []uint16) bool {
	return len(path) >= 3 && isASCIILetter(path[0]) && path[1] == ':' && path[2] == '\\'
}

func isExtendedDrivePath(path []uint16) bool {
	return len(path) >= 7 && hasASCIIPrefix(path, `\\?\`) && isASCIILetter(path[4]) && path[5] == ':' && path[6] == '\\'
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

// pathContainedBy compares handle-derived normalized volume-GUID paths. It never
// uses caller-supplied string-prefix containment.
func pathContainedBy(root, target []uint16) bool {
	root = trimTrailingSeparators(root)
	target = trimTrailingSeparators(target)
	if len(root) == 0 || len(target) == 0 {
		return false
	}
	if equalUTF16(root, target) {
		return true
	}
	return len(target) > len(root) && hasUTF16Prefix(target, root) && target[len(root)] == '\\'
}
