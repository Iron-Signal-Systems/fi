// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package scopeidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// GovernedRootScopeID returns FI's canonical stable scope identifier for one
// configured governed root.
func GovernedRootScopeID(governedRoot string) string {
	canonical := strings.TrimRight(strings.TrimSpace(governedRoot), `\`)
	if len(canonical) == 2 && canonical[1] == ':' {
		canonical += `\`
	}
	canonical = strings.ToLower(canonical)

	digest := sha256.Sum256([]byte(canonical))
	return "root-" + hex.EncodeToString(digest[:16])
}
