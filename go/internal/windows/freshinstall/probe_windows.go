// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// NativeInspector checks the actual local Windows SCM and directory entries.
// It never creates, stops, reconfigures or deletes services or files. The
// manager handle is opened once to keep results from multiple SCM instances
// within one snapshot (not to guarantee a transaction or prevent races).
type NativeInspector struct {
	manager *mgr.Mgr
}

// OpenNativeInspector fails closed if SCM access cannot be established.
// Do not interpret an inaccessible SCM as an empty FI installation.
func OpenNativeInspector() (*NativeInspector, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to Windows service control manager for FI fresh-install check: %w", err)
	}
	return &NativeInspector{manager: manager}, nil
}

func (n *NativeInspector) Close() error {
	if n == nil || n.manager == nil {
		return nil
	}
	err := n.manager.Disconnect()
	n.manager = nil
	return err
}

func (n *NativeInspector) Service(name string) (Presence, error) {
	if n == nil || n.manager == nil {
		return Unknown, errors.New("Windows service control manager is unavailable")
	}
	service, err := n.manager.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return Absent, nil
		}
		return Unknown, fmt.Errorf("inspect FI service %q: %w", name, err)
	}
	if err := service.Close(); err != nil {
		return Unknown, fmt.Errorf("release FI service %q query handle: %w", name, err)
	}
	return Present, nil
}

// Lstat deliberately does not follow a file/dir symlink at the named path;
// any FI-owned path or reparse point is a collision requiring manual review.
// Errors such as access denied must never be mistaken for absence.
func (n *NativeInspector) Path(path string) (Presence, error) {
	if n == nil {
		return Unknown, errors.New("native FI filesystem inspector is unavailable")
	}
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return Present, nil
	case errors.Is(err, os.ErrNotExist):
		return Absent, nil
	default:
		return Unknown, fmt.Errorf("inspect FI footprint %q: %w", path, err)
	}
}
