// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var spoolPathKernel32 = syscall.NewLazyDLL(
	"kernel32.dll",
)

var spoolPathGetFinalPathNameByHandleW = spoolPathKernel32.NewProc(
	"GetFinalPathNameByHandleW",
)

func resolveDirectoryPath(
	path string,
) (string, error) {
	file, err :=
		os.Open(path)

	if err != nil {
		return "", err
	}

	defer file.Close()

	const initialCharacters = 1024

	buffer :=
		make(
			[]uint16,
			initialCharacters,
		)

	for {
		result, _, callErr :=
			spoolPathGetFinalPathNameByHandleW.Call(
				file.Fd(),
				uintptr(
					unsafe.Pointer(
						&buffer[0],
					),
				),
				uintptr(len(buffer)),
				0,
			)

		if result == 0 {
			if callErr != nil &&
				callErr != syscall.Errno(0) {
				return "", fmt.Errorf(
					"GetFinalPathNameByHandleW: %w",
					callErr,
				)
			}

			return "", errors.New(
				"GetFinalPathNameByHandleW failed",
			)
		}

		if result < uintptr(len(buffer)) {
			value :=
				syscall.UTF16ToString(
					buffer[:int(result)],
				)

			switch {
			case strings.HasPrefix(
				value,
				`\\?\UNC\`,
			):
				value =
					`\\` +
						strings.TrimPrefix(
							value,
							`\\?\UNC\`,
						)

			case strings.HasPrefix(
				value,
				`\\?\`,
			):
				value =
					strings.TrimPrefix(
						value,
						`\\?\`,
					)
			}

			if !filepath.IsAbs(value) {
				return "", errors.New(
					"resolved FI spool path is not absolute",
				)
			}

			return filepath.Clean(value), nil
		}

		required :=
			int(result) + 1

		if required <= len(buffer) ||
			required > 32768 {
			return "", errors.New(
				"resolved FI spool path exceeds supported length",
			)
		}

		buffer =
			make(
				[]uint16,
				required,
			)
	}
}

// resolveDirectoryIdentityPath returns the physical directory identity even
// when a configured Windows junction currently points at a missing target.
//
// The normal path uses GetFinalPathNameByHandleW. If the target is temporarily
// absent during rollover recovery, os.Readlink reads the junction reparse
// target itself without requiring that target directory to exist.
func resolveDirectoryIdentityPath(
	path string,
) (
	string,
	error,
) {
	resolved, err :=
		resolveDirectoryPath(
			path,
		)
	if err == nil {
		return resolved, nil
	}

	target, readlinkErr :=
		os.Readlink(
			path,
		)
	if readlinkErr != nil {
		return "", errors.Join(
			fmt.Errorf(
				"resolve existing FI spool target: %w",
				err,
			),
			fmt.Errorf(
				"read FI spool reparse target: %w",
				readlinkErr,
			),
		)
	}

	switch {
	case strings.HasPrefix(
		target,
		`\??\UNC\`,
	):
		target =
			`\\` +
				strings.TrimPrefix(
					target,
					`\??\UNC\`,
				)

	case strings.HasPrefix(
		target,
		`\\?\UNC\`,
	):
		target =
			`\\` +
				strings.TrimPrefix(
					target,
					`\\?\UNC\`,
				)

	case strings.HasPrefix(
		target,
		`\??\`,
	):
		target =
			strings.TrimPrefix(
				target,
				`\??\`,
			)

	case strings.HasPrefix(
		target,
		`\\?\`,
	):
		target =
			strings.TrimPrefix(
				target,
				`\\?\`,
			)
	}

	if !filepath.IsAbs(
		target,
	) {
		target =
			filepath.Join(
				filepath.Dir(
					path,
				),
				target,
			)
	}

	if !filepath.IsAbs(
		target,
	) {
		return "", errors.New(
			"resolved FI spool reparse target is not absolute",
		)
	}

	target =
		filepath.Clean(
			target,
		)

	// The junction target itself may legitimately be missing during interrupted
	// rollover recovery. Its parent must still exist. Resolve that parent
	// through GetFinalPathNameByHandleW so Windows 8.3 aliases are normalized
	// before reconstructing the missing physical spool path.
	targetParent :=
		filepath.Dir(
			target,
		)

	resolvedParent, err :=
		resolveDirectoryPath(
			targetParent,
		)
	if err != nil {
		return "", fmt.Errorf(
			"resolve physical FI spool target parent: %w",
			err,
		)
	}

	return filepath.Join(
		resolvedParent,
		filepath.Base(
			target,
		),
	), nil
}
