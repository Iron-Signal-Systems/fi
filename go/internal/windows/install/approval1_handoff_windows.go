// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

func (backend *server2016Approval1Backend) PKIHandoff() approval1PKIHandoff {
	if backend == nil {
		return approval1PKIHandoff{}
	}

	return backend.handoff
}
