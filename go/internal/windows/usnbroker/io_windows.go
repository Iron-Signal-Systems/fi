// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"io"

	"golang.org/x/sys/windows"
)

type handleIO struct {
	handle windows.Handle
}

func (value handleIO) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	var read uint32
	err := windows.ReadFile(value.handle, buffer, &read, nil)
	if err == windows.ERROR_BROKEN_PIPE {
		return int(read), io.EOF
	}
	return int(read), err
}

func (value handleIO) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	var written uint32
	err := windows.WriteFile(value.handle, buffer, &written, nil)
	return int(written), err
}
