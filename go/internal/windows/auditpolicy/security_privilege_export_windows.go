// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package auditpolicy

// WithSecurityPrivilege temporarily enables SeSecurityPrivilege already held by
// the caller. It restores the prior privilege state even if work fails.
func WithSecurityPrivilege(work func() error) error { return withSecurityPrivilege(work) }
