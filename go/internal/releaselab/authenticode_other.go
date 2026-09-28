// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package releaselab

import "fmt"

func SignAuthenticodeFile(
	keysDirectory string,
	filePath string,
) error {
	return fmt.Errorf(
		"Authenticode signing is supported only on Windows; keys=%s file=%s",
		keysDirectory,
		filePath,
	)
}
