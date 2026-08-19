// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package ntfs

import "context"

func CollectPath(context.Context, string, string, string) (Observation, error) {
	return Observation{}, ErrUnsupportedPlatform
}
