// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package securityevent

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

type GovernedScope struct {
	ScopeID      string
	GovernedRoot string
}

func SelectEvent(value records.WindowsSecurityEventObservation, scopes []GovernedScope) (records.WindowsSecurityEventObservation, bool) {
	eventID, err := strconv.ParseUint(value.EventID, 10, 32)
	if err != nil {
		return value, false
	}

	switch uint32(eventID) {
	case 1102, 4719:
		value.ScopeBasis = records.WindowsSecurityScopeHostMonitoringChange
		return value, true

	case 4660:
		// Event 4660 does not carry the object path. Preserve it as an unresolved
		// delete so the backend can correlate HandleId/ProcessId with nearby file
		// access events instead of silently dropping a possible governed delete.
		value.ScopeBasis = records.WindowsSecurityScopeUnresolvedFileDeleteIncluded
		return value, true

	case 4664:
		matched := matchPaths([]string{value.FileName, value.LinkName}, scopes)
		if len(matched) == 0 {
			return value, false
		}
		value.ScopeBasis = records.WindowsSecurityScopeHardLinkPathMatched
		value.MatchedScopes = matched
		return value, true

	case 4656, 4663, 4670, 4907:
		if value.ObjectType != "" && !strings.EqualFold(value.ObjectType, "File") {
			return value, false
		}
		matched := matchPaths([]string{value.ObjectName}, scopes)
		if len(matched) == 0 {
			return value, false
		}
		value.ScopeBasis = records.WindowsSecurityScopePathMatched
		value.MatchedScopes = matched
		return value, true
	}
	return value, false
}

func matchPaths(paths []string, scopes []GovernedScope) []records.WindowsSecurityMatchedScope {
	result := []records.WindowsSecurityMatchedScope{}
	seen := map[string]bool{}
	for _, candidate := range paths {
		if candidate == "" {
			continue
		}
		for _, scope := range scopes {
			if pathWithinRoot(candidate, scope.GovernedRoot) && !seen[scope.ScopeID] {
				seen[scope.ScopeID] = true
				result = append(result, records.WindowsSecurityMatchedScope{ScopeID: scope.ScopeID, GovernedRoot: scope.GovernedRoot})
			}
		}
	}
	return result
}

func pathWithinRoot(candidate, root string) bool {
	candidate = strings.TrimRight(filepath.Clean(strings.TrimSpace(candidate)), `\`)
	root = strings.TrimRight(filepath.Clean(strings.TrimSpace(root)), `\`)
	if strings.EqualFold(candidate, root) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(root)+`\`)
}
