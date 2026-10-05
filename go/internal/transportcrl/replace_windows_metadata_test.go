// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportcrl

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReplaceExistingFileWithBackupPreservesDACLAndMetadata(
	t *testing.T,
) {
	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"active.crl.pem",
	)

	replacement := filepath.Join(
		directory,
		"replacement.crl.pem",
	)

	backup := filepath.Join(
		directory,
		"backup.crl.pem",
	)

	const oldContent = "old-active-crl"

	const newContent = "new-candidate-crl"

	if err := os.WriteFile(
		active,
		[]byte(
			oldContent,
		),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		replacement,
		[]byte(
			newContent,
		),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	// Make the two DACLs deliberately different while retaining unrestricted
	// access to both test files. If ReplaceFileW merely adopts the candidate's
	// DACL instead of preserving the active file's DACL, this test detects it.
	setReplacementTestDACL(
		t,
		active,
		"D:P(A;;GA;;;WD)",
	)

	setReplacementTestDACL(
		t,
		replacement,
		"D:P(A;;GA;;;WD)(A;;GR;;;BU)",
	)

	activeDACLBefore :=
		replacementTestDACL(
			t,
			active,
		)

	replacementDACLBefore :=
		replacementTestDACL(
			t,
			replacement,
		)

	if activeDACLBefore ==
		replacementDACLBefore {
		t.Fatalf(
			"test setup produced identical DACLs: %q",
			activeDACLBefore,
		)
	}

	activeCreation :=
		time.Date(
			2020,
			time.January,
			2,
			3,
			4,
			5,
			123456700,
			time.UTC,
		)

	replacementCreation :=
		time.Date(
			2024,
			time.June,
			7,
			8,
			9,
			10,
			765432100,
			time.UTC,
		)

	setReplacementTestCreationTime(
		t,
		active,
		activeCreation,
	)

	setReplacementTestCreationTime(
		t,
		replacement,
		replacementCreation,
	)

	activeCreationBefore :=
		replacementTestCreationTime(
			t,
			active,
		)

	replacementCreationBefore :=
		replacementTestCreationTime(
			t,
			replacement,
		)

	if activeCreationBefore ==
		replacementCreationBefore {
		t.Fatal(
			"test setup produced identical creation times",
		)
	}

	setReplacementTestNotContentIndexed(
		t,
		active,
		true,
	)

	setReplacementTestNotContentIndexed(
		t,
		replacement,
		false,
	)

	if !replacementTestNotContentIndexed(
		t,
		active,
	) {
		t.Fatal(
			"active test file did not retain NOT_CONTENT_INDEXED setup attribute",
		)
	}

	if replacementTestNotContentIndexed(
		t,
		replacement,
	) {
		t.Fatal(
			"replacement test file unexpectedly has NOT_CONTENT_INDEXED setup attribute",
		)
	}

	if err := ReplaceExistingFileWithBackup(
		active,
		replacement,
		backup,
	); err != nil {
		t.Fatal(err)
	}

	activeContent, err :=
		os.ReadFile(
			active,
		)
	if err != nil {
		t.Fatal(err)
	}

	if string(
		activeContent,
	) != newContent {
		t.Fatalf(
			"active content=%q want=%q",
			activeContent,
			newContent,
		)
	}

	backupContent, err :=
		os.ReadFile(
			backup,
		)
	if err != nil {
		t.Fatal(err)
	}

	if string(
		backupContent,
	) != oldContent {
		t.Fatalf(
			"backup content=%q want=%q",
			backupContent,
			oldContent,
		)
	}

	if _, err := os.Stat(
		replacement,
	); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"replacement path still exists after ReplaceFileW: err=%v",
			err,
		)
	}

	activeDACLAfter :=
		replacementTestDACL(
			t,
			active,
		)

	if activeDACLAfter !=
		activeDACLBefore {
		t.Fatalf(
			"active DACL changed:`n before=%q`n after=%q`n candidate=%q",
			activeDACLBefore,
			activeDACLAfter,
			replacementDACLBefore,
		)
	}

	backupDACL :=
		replacementTestDACL(
			t,
			backup,
		)

	if backupDACL !=
		activeDACLBefore {
		t.Fatalf(
			"backup DACL=%q want previous active DACL=%q",
			backupDACL,
			activeDACLBefore,
		)
	}

	activeCreationAfter :=
		replacementTestCreationTime(
			t,
			active,
		)

	if activeCreationAfter !=
		activeCreationBefore {
		t.Fatalf(
			"active creation time changed: before=%d after=%d replacement_before=%d",
			activeCreationBefore,
			activeCreationAfter,
			replacementCreationBefore,
		)
	}

	backupCreation :=
		replacementTestCreationTime(
			t,
			backup,
		)

	if backupCreation !=
		activeCreationBefore {
		t.Fatalf(
			"backup creation time=%d want previous active creation time=%d",
			backupCreation,
			activeCreationBefore,
		)
	}

	if !replacementTestNotContentIndexed(
		t,
		active,
	) {
		t.Fatal(
			"active file lost NOT_CONTENT_INDEXED attribute during replacement",
		)
	}

	if !replacementTestNotContentIndexed(
		t,
		backup,
	) {
		t.Fatal(
			"backup file lost previous active NOT_CONTENT_INDEXED attribute",
		)
	}
}

func replacementTestCreationTime(
	t *testing.T,
	path string,
) int64 {
	t.Helper()

	file, err :=
		os.Open(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	var creation windows.Filetime

	if err := windows.GetFileTime(
		windows.Handle(
			file.Fd(),
		),
		&creation,
		nil,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	return creation.Nanoseconds()
}

func replacementTestDACL(
	t *testing.T,
	path string,
) string {
	t.Helper()

	descriptor, err :=
		windows.GetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
	if err != nil {
		t.Fatal(err)
	}

	return descriptor.String()
}

func replacementTestNotContentIndexed(
	t *testing.T,
	path string,
) bool {
	t.Helper()

	pointer, err :=
		windows.UTF16PtrFromString(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	attributes, err :=
		windows.GetFileAttributes(
			pointer,
		)
	if err != nil {
		t.Fatal(err)
	}

	return attributes&
		windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0
}

func setReplacementTestCreationTime(
	t *testing.T,
	path string,
	value time.Time,
) {
	t.Helper()

	file, err :=
		os.OpenFile(
			path,
			os.O_RDWR,
			0,
		)
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	creation :=
		windows.NsecToFiletime(
			value.UnixNano(),
		)

	if err := windows.SetFileTime(
		windows.Handle(
			file.Fd(),
		),
		&creation,
		nil,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func setReplacementTestDACL(
	t *testing.T,
	path string,
	sddl string,
) {
	t.Helper()

	descriptor, err :=
		windows.SecurityDescriptorFromString(
			sddl,
		)
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err :=
		descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func setReplacementTestNotContentIndexed(
	t *testing.T,
	path string,
	enabled bool,
) {
	t.Helper()

	pointer, err :=
		windows.UTF16PtrFromString(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	attributes, err :=
		windows.GetFileAttributes(
			pointer,
		)
	if err != nil {
		t.Fatal(err)
	}

	if enabled {
		attributes |=
			windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	} else {
		attributes &^=
			windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	}

	if attributes == 0 {
		attributes =
			windows.FILE_ATTRIBUTE_NORMAL
	}

	if err := windows.SetFileAttributes(
		pointer,
		attributes,
	); err != nil {
		t.Fatal(err)
	}
}
