// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows && 386

package directory

import (
	"context"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// WLDAP32 uses the C calling convention on 32-bit Windows. FI's current Windows
// collector target is 64-bit; do not silently call the API with the wrong ABI.
func CollectCurrentDomainPrincipals(context.Context, string, []string) (records.DirectoryPrincipalSnapshot, error) {
	return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("Windows LDAP collection is not supported on 32-bit FI builds")
}
