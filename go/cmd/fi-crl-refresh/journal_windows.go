// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func appendRefreshJournal(
	path string,
	record refreshJournalRecord,
) error {
	path = filepath.Clean(
		strings.TrimSpace(
			path,
		),
	)

	if path == "." ||
		path == "" {
		return errors.New(
			"CRL refresh journal path is required",
		)
	}

	if !filepath.IsAbs(
		path,
	) {
		return fmt.Errorf(
			"CRL refresh journal path must be absolute: %q",
			path,
		)
	}

	pathUTF16, err :=
		windows.UTF16PtrFromString(
			path,
		)
	if err != nil {
		return fmt.Errorf(
			"encode CRL refresh journal path: %w",
			err,
		)
	}

	handle, err :=
		windows.CreateFile(
			pathUTF16,
			windows.FILE_APPEND_DATA|
				windows.FILE_READ_ATTRIBUTES|
				windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|
				windows.FILE_FLAG_WRITE_THROUGH,
			0,
		)
	if err != nil {
		return fmt.Errorf(
			"open pre-created CRL refresh journal for native append: %w",
			err,
		)
	}

	closeHandle := func() error {
		if err := windows.CloseHandle(
			handle,
		); err != nil {
			return fmt.Errorf(
				"close CRL refresh journal handle: %w",
				err,
			)
		}

		return nil
	}

	var info windows.ByHandleFileInformation

	if err :=
		windows.GetFileInformationByHandle(
			handle,
			&info,
		); err != nil {
		return errors.Join(
			fmt.Errorf(
				"inspect opened CRL refresh journal: %w",
				err,
			),
			closeHandle(),
		)
	}

	if info.FileAttributes&
		windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(
			fmt.Errorf(
				"CRL refresh journal must not be a reparse point: %q",
				path,
			),
			closeHandle(),
		)
	}

	if info.FileAttributes&
		windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return errors.Join(
			fmt.Errorf(
				"CRL refresh journal must be a regular file: %q",
				path,
			),
			closeHandle(),
		)
	}

	encoded, err :=
		json.Marshal(
			record,
		)
	if err != nil {
		return errors.Join(
			fmt.Errorf(
				"encode CRL refresh journal record: %w",
				err,
			),
			closeHandle(),
		)
	}

	encoded = append(
		encoded,
		'\n',
	)

	remaining := encoded

	for len(
		remaining,
	) != 0 {
		var written uint32

		if err :=
			windows.WriteFile(
				handle,
				remaining,
				&written,
				nil,
			); err != nil {
			return errors.Join(
				fmt.Errorf(
					"append CRL refresh journal: %w",
					err,
				),
				closeHandle(),
			)
		}

		if written == 0 {
			return errors.Join(
				errors.New(
					"append CRL refresh journal made no forward progress",
				),
				closeHandle(),
			)
		}

		if int(
			written,
		) > len(
			remaining,
		) {
			return errors.Join(
				fmt.Errorf(
					"append CRL refresh journal reported invalid write length=%d remaining=%d",
					written,
					len(
						remaining,
					),
				),
				closeHandle(),
			)
		}

		remaining =
			remaining[written:]
	}

	return closeHandle()
}
