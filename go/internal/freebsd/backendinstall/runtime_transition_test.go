// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAdoptRuntimeSpecsReplacesApprovedForeign(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	legacy := []byte(
		"legacy runtime\n",
	)

	if err := os.WriteFile(
		target,
		legacy,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			spec.PriorName,
		),
		legacy,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := adoptRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		priorDirectory,
	); err != nil {
		t.Fatalf(
			"adoptRuntimeSpecs() error = %v",
			err,
		)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestAdoptRuntimeSpecsRejectsUnapprovedForeign(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	if err := os.WriteFile(
		target,
		[]byte("live foreign\n"),
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			spec.PriorName,
		),
		[]byte("different prior\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := adoptRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		priorDirectory,
	); err == nil {
		t.Fatal(
			"adoptRuntimeSpecs accepted unapproved foreign target",
		)
	}
}

func TestAdoptRuntimeSpecsRejectsAbsent(
	t *testing.T,
) {
	spec := runtimeTestFileSpec(
		filepath.Join(
			t.TempDir(),
			"runtime",
		),
	)
	spec.PriorName = "runtime.prior"

	if err := adoptRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		t.TempDir(),
	); err == nil {
		t.Fatal(
			"adoptRuntimeSpecs accepted absent target",
		)
	}
}

func TestUpdateRuntimeSpecsAdvancesApprovedManagedPrior(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	priorContent := []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"old\n",
	)

	spec.Content = []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"new\n",
	)

	if err := os.WriteFile(
		target,
		priorContent,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			spec.PriorName,
		),
		priorContent,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := updateRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		priorDirectory,
	); err != nil {
		t.Fatalf(
			"updateRuntimeSpecs() error = %v",
			err,
		)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestUpdateRuntimeSpecsRejectsWrongManagedPrior(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	livePrior := []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"actual-old\n",
	)

	approvedPrior := []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"different-old\n",
	)

	spec.Content = []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"new\n",
	)

	if err := os.WriteFile(
		target,
		livePrior,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			spec.PriorName,
		),
		approvedPrior,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := updateRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		priorDirectory,
	); err == nil {
		t.Fatal(
			"updateRuntimeSpecs accepted wrong approved prior",
		)
	}
}

func TestUpdateRuntimeSpecsRejectsForeign(
	t *testing.T,
) {
	target := filepath.Join(
		t.TempDir(),
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	if err := os.WriteFile(
		target,
		[]byte("foreign\n"),
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if err := updateRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		t.TempDir(),
	); err == nil {
		t.Fatal(
			"updateRuntimeSpecs accepted foreign target",
		)
	}
}

func TestUpdateRuntimeSpecsRejectsPriorWithoutMarker(
	t *testing.T,
) {
	target := filepath.Join(
		t.TempDir(),
		"runtime",
	)

	spec := runtimeTestFileSpec(
		target,
	)
	spec.PriorName = "runtime.prior"

	live := []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"old\n",
	)

	spec.Content = []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"new\n",
	)

	if err := os.WriteFile(
		target,
		live,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			spec.PriorName,
		),
		[]byte("old\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := updateRuntimeSpecs(
		[]runtimeFileSpec{
			spec,
		},
		priorDirectory,
	); err == nil {
		t.Fatal(
			"updateRuntimeSpecs accepted unmanaged approved prior",
		)
	}
}

func TestAdoptRuntimeSpecsPreclassifiesCompleteLayer(
	t *testing.T,
) {
	directory := t.TempDir()

	firstTarget := filepath.Join(
		directory,
		"first",
	)

	secondTarget := filepath.Join(
		directory,
		"second",
	)

	first := runtimeTestFileSpec(
		firstTarget,
	)
	first.PriorName = "first.prior"

	second := runtimeTestFileSpec(
		secondTarget,
	)
	second.PriorName = "second.prior"

	legacy := []byte(
		"legacy first\n",
	)

	if err := os.WriteFile(
		firstTarget,
		legacy,
		first.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			first.PriorName,
		),
		legacy,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := adoptRuntimeSpecs(
		[]runtimeFileSpec{
			first,
			second,
		},
		priorDirectory,
	); err == nil {
		t.Fatal(
			"adoptRuntimeSpecs accepted incomplete layer",
		)
	}

	content, err := os.ReadFile(
		firstTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(legacy) {
		t.Fatal(
			"first runtime resource mutated before complete-layer preclassification",
		)
	}

	if state := classifyRuntimeFile(
		first,
	); state != runtimeFileForeignCollision {
		t.Fatalf(
			"first state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestUpdateRuntimeSpecsPreclassifiesCompleteLayer(
	t *testing.T,
) {
	directory := t.TempDir()

	firstTarget := filepath.Join(
		directory,
		"first",
	)

	secondTarget := filepath.Join(
		directory,
		"second",
	)

	first := runtimeTestFileSpec(
		firstTarget,
	)
	first.PriorName = "first.prior"

	second := runtimeTestFileSpec(
		secondTarget,
	)
	second.PriorName = "second.prior"

	firstPrior := []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"old\n",
	)

	first.Content = []byte(
		runtimeFileMarker +
			"\n" +
			"# FI-ROLE: test\n" +
			"new\n",
	)

	if err := os.WriteFile(
		firstTarget,
		firstPrior,
		first.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		secondTarget,
		[]byte("foreign second\n"),
		second.Mode,
	); err != nil {
		t.Fatal(err)
	}

	priorDirectory := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(
			priorDirectory,
			first.PriorName,
		),
		firstPrior,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := updateRuntimeSpecs(
		[]runtimeFileSpec{
			first,
			second,
		},
		priorDirectory,
	); err == nil {
		t.Fatal(
			"updateRuntimeSpecs accepted unsafe complete layer",
		)
	}

	content, err := os.ReadFile(
		firstTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(firstPrior) {
		t.Fatal(
			"first runtime resource mutated before complete-layer preclassification",
		)
	}

	priorSpec := first
	priorSpec.Content = firstPrior

	if state := classifyRuntimeFile(
		priorSpec,
	); state != runtimeFileOwnedMatch {
		t.Fatalf(
			"first state against prior = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestRuntimeFinalVerificationRejectsParentDrift(
	t *testing.T,
) {
	directory := t.TempDir()

	parent := filepath.Join(
		directory,
		"runtime-parent",
	)

	if err := os.Mkdir(
		parent,
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(
		parent,
	)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"parent stat is not syscall.Stat_t",
		)
	}

	target := filepath.Join(
		parent,
		"runtime",
	)

	fileSpec := runtimeTestFileSpec(
		target,
	)

	if err := publishAbsentRuntimeFile(
		fileSpec,
	); err != nil {
		t.Fatal(err)
	}

	plan := runtimePlan{
		Files: []runtimeFileSpec{
			fileSpec,
		},
		Parents: []lifecycleParentSpec{
			{
				GID: uint64(
					stat.Gid,
				),
				Mode: 0o755,
				Path: parent,
				Role: "test-runtime-parent",
				UID: uint64(
					stat.Uid,
				),
			},
		},
	}

	if err := verifyRuntimePlan(
		plan,
	); err != nil {
		t.Fatalf(
			"initial verifyRuntimePlan() error = %v",
			err,
		)
	}

	if err := os.Chmod(
		parent,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := verifyRuntimePlan(
		plan,
	); err == nil {
		t.Fatal(
			"verifyRuntimePlan accepted parent metadata drift",
		)
	}

	if state := classifyRuntimeFile(
		fileSpec,
	); state != runtimeFileOwnedMatch {
		t.Fatalf(
			"runtime file state = %s, want OWNED_MATCH",
			state,
		)
	}
}
