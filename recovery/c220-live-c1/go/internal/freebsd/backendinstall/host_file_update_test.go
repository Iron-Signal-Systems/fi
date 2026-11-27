// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostFileUpdateAdvancesApprovedPrior(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"fi-test.conf",
	)

	current := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=new",
	)

	prior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=old",
	)

	writeHostFileUpdateTestFile(
		t,
		target,
		prior.Content,
		prior.Mode,
	)

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(target),
		),
		prior.Content,
		0o600,
	)

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			current,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	); err != nil {
		t.Fatalf(
			"updateHostFileSpecs() error = %v",
			err,
		)
	}

	if state := classifyHostFile(
		current,
	); state != hostFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestHostFileUpdateExactSecondUpdateIsNoOp(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"fi-test.conf",
	)

	current := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=new",
	)

	prior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=old",
	)

	writeHostFileUpdateTestFile(
		t,
		target,
		prior.Content,
		prior.Mode,
	)

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(target),
		),
		prior.Content,
		0o600,
	)

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			current,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	); err != nil {
		t.Fatal(err)
	}

	before, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	); err != nil {
		t.Fatal(err)
	}

	after, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(
		before,
		after,
	) {
		t.Fatal(
			"exact second update replaced already-current host file",
		)
	}
}

func TestHostFileUpdateLayerPreclassificationPreventsPartialTransition(
	t *testing.T,
) {
	directory := t.TempDir()

	firstTarget := filepath.Join(
		directory,
		"first.conf",
	)

	secondTarget := filepath.Join(
		directory,
		"second.conf",
	)

	firstCurrent := testHostFileUpdateSpec(
		firstTarget,
		"first-role",
		"payload=new-first",
	)

	firstPrior := testHostFileUpdateSpec(
		firstTarget,
		"first-role",
		"payload=old-first",
	)

	secondCurrent := testHostFileUpdateSpec(
		secondTarget,
		"second-role",
		"payload=new-second",
	)

	secondPrior := testHostFileUpdateSpec(
		secondTarget,
		"second-role",
		"payload=old-second",
	)

	secondUnauthorized := testHostFileUpdateSpec(
		secondTarget,
		"second-role",
		"payload=unauthorized-second",
	)

	writeHostFileUpdateTestFile(
		t,
		firstTarget,
		firstPrior.Content,
		firstPrior.Mode,
	)

	writeHostFileUpdateTestFile(
		t,
		secondTarget,
		secondUnauthorized.Content,
		secondUnauthorized.Mode,
	)

	firstBefore, err := os.Lstat(
		firstTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(firstTarget),
		),
		firstPrior.Content,
		0o600,
	)

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(secondTarget),
		),
		secondPrior.Content,
		0o600,
	)

	specs := []hostFileSpec{
		firstCurrent,
		secondCurrent,
	}

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		specs,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = updateHostFileSpecs(
		specs,
		priorSpecs,
	)
	if err == nil {
		t.Fatal(
			"update accepted unapproved later resource",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not match approved prior version",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	firstAfter, err := os.Lstat(
		firstTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(
		firstBefore,
		firstAfter,
	) {
		t.Fatal(
			"earlier approved file changed before later failure",
		)
	}

	content, err := os.ReadFile(
		firstTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(firstPrior.Content) {
		t.Fatal(
			"earlier approved file content changed before later failure",
		)
	}
}

func TestHostFileUpdateRejectsAbsentResource(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"missing.conf",
	)

	current := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=new",
	)

	prior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=old",
	)

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(target),
		),
		prior.Content,
		0o600,
	)

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			current,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	)
	if err == nil {
		t.Fatal(
			"update accepted absent live resource",
		)
	}

	if !strings.Contains(
		err.Error(),
		"is absent and is not eligible for update",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestHostFileUpdateRequiresCompletePriorSnapshot(t *testing.T) {
	directory := t.TempDir()

	first := testHostFileUpdateSpec(
		filepath.Join(
			directory,
			"first.conf",
		),
		"first-role",
		"payload=first",
	)

	second := testHostFileUpdateSpec(
		filepath.Join(
			directory,
			"second.conf",
		),
		"second-role",
		"payload=second",
	)

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(first.Target),
		),
		first.Content,
		0o600,
	)

	_, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			first,
			second,
		},
	)
	if err == nil {
		t.Fatal(
			"incomplete approved-prior snapshot was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"incomplete or contains extra resources",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func testHostFileUpdateSpec(
	target string,
	role string,
	payload string,
) hostFileSpec {
	content := "" +
		hostFileMarker +
		"\n" +
		"# FI-ROLE: " +
		role +
		"\n" +
		payload +
		"\n"

	return hostFileSpec{
		Content: []byte(content),
		GID:     uint64(os.Getegid()),
		Mode:    0o644,
		Role:    role,
		Target:  target,
		UID:     uint64(os.Geteuid()),
	}
}

func writeHostFileUpdateTestFile(
	t *testing.T,
	path string,
	content []byte,
	mode os.FileMode,
) {
	t.Helper()

	if err := os.WriteFile(
		path,
		content,
		mode,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chown(
		path,
		os.Geteuid(),
		os.Getegid(),
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		path,
		mode,
	); err != nil {
		t.Fatal(err)
	}
}

func TestHostFileUpdateRejectsForeignCollision(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"fi-test.conf",
	)

	current := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=new",
	)

	prior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=old",
	)

	foreignContent := []byte(
		"foreign-content\n",
	)

	if err := os.WriteFile(
		target,
		foreignContent,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(target),
		),
		prior.Content,
		0o600,
	)

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			current,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	before, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	)
	if err == nil {
		t.Fatal(
			"update accepted foreign live collision",
		)
	}

	if !strings.Contains(
		err.Error(),
		"collides with a non-FI resource",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	after, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(
		before,
		after,
	) {
		t.Fatal(
			"foreign live file was replaced",
		)
	}

	content, err := os.ReadFile(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(foreignContent) {
		t.Fatal(
			"foreign live file content changed",
		)
	}
}

func TestHostFileUpdateRejectsWrongApprovedPrior(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"fi-test.conf",
	)

	current := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=new",
	)

	livePrior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=approved-live-prior",
	)

	wrongPrior := testHostFileUpdateSpec(
		target,
		"test-host-file",
		"payload=different-prior",
	)

	writeHostFileUpdateTestFile(
		t,
		target,
		livePrior.Content,
		livePrior.Mode,
	)

	priorDirectory := filepath.Join(
		directory,
		"prior",
	)

	if err := os.Mkdir(
		priorDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeHostFileUpdateTestFile(
		t,
		filepath.Join(
			priorDirectory,
			filepath.Base(target),
		),
		wrongPrior.Content,
		0o600,
	)

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		priorDirectory,
		[]hostFileSpec{
			current,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	before, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = updateHostFileSpecs(
		[]hostFileSpec{
			current,
		},
		priorSpecs,
	)
	if err == nil {
		t.Fatal(
			"update accepted wrong approved-prior content",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not match approved prior version",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	after, err := os.Lstat(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(
		before,
		after,
	) {
		t.Fatal(
			"live file was replaced under wrong approved prior",
		)
	}

	content, err := os.ReadFile(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(livePrior.Content) {
		t.Fatal(
			"live file content changed under wrong approved prior",
		)
	}
}
