// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestApproval2OperationalDirectoryPathsIncludeCollectorWorkDirectory(
	t *testing.T,
) {
	t.Parallel()

	tests :=
		[]struct {
			name      string
			spoolName string
		}{
			{
				name:      "default spool name",
				spoolName: "spool",
			},
			{
				name:      "non-default spool name",
				spoolName: "customer-spool",
			},
		}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				t.Parallel()

				root :=
					t.TempDir()

				spoolDir :=
					filepath.Join(
						root,
						test.spoolName,
					)

				proposal :=
					ConfigState{
						Path: filepath.Join(
							root,
							"config",
							"fi.conf",
						),
						SpoolDir: spoolDir,
						StageDir: filepath.Join(
							root,
							"stage",
						),
						StateDir: filepath.Join(
							root,
							"state",
						),
					}

				directories, err :=
					approval2OperationalDirectoryPaths(
						proposal,
						approval1PKIHandoff{},
					)
				if err != nil {
					t.Fatal(err)
				}

				want :=
					filepath.Join(
						root,
						".fi-"+
							test.spoolName+
							"-collector-work",
					)

				found := false

				for _, path := range directories {
					if filepath.Clean(
						path,
					) == filepath.Clean(
						want,
					) {
						found = true
						break
					}
				}

				if !found {
					t.Fatalf(
						"collector work directory %q absent from Approval-2 directories: %v",
						want,
						directories,
					)
				}
			},
		)
	}
}

func TestCollectorWorkDirectoryAbsenceIsRepairable(
	t *testing.T,
) {
	t.Parallel()

	got :=
		aclDiscoveryFailureStatus(
			collectorWorkDirectoryACLLabel,
			windows.ERROR_PATH_NOT_FOUND,
		)

	if got != checkInfo {
		t.Fatalf(
			"collector work absence status=%s want=%s",
			got,
			checkInfo,
		)
	}
}

func TestCollectorWorkDirectoryPathUsesConfiguredSpoolSibling(
	t *testing.T,
) {
	t.Parallel()

	root :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			root,
			"custom-active",
		)

	if _, err :=
		os.Lstat(
			spoolDir,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"test spool unexpectedly exists: %v",
			err,
		)
	}

	got, err :=
		collectorWorkDirectoryPath(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	want :=
		filepath.Join(
			root,
			".fi-custom-active-collector-work",
		)

	if filepath.Clean(
		got,
	) != filepath.Clean(
		want,
	) {
		t.Fatalf(
			"collector work directory=%q want=%q",
			got,
			want,
		)
	}
}

func TestPlanACLsReconcilesCollectorWorkDirectory(
	t *testing.T,
) {
	t.Parallel()

	root :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			root,
			"spool",
		)

	report :=
		Report{
			Config: ConfigState{
				SpoolDir: spoolDir,
				StageDir: filepath.Join(
					root,
					"stage",
				),
				StateDir: filepath.Join(
					root,
					"state",
				),
			},
		}

	target :=
		collectorWorkDirectoryTarget(
			spoolDir,
		)

	if strings.TrimSpace(
		target,
	) == "" ||
		strings.EqualFold(
			target,
			notKnown,
		) {
		t.Fatalf(
			"collector work target unavailable: %q",
			target,
		)
	}

	var plan InstallPlan

	planACLs(
		&plan,
		report,
	)

	for _, action := range plan.Actions {
		if action.Authority != "ACL" ||
			!strings.EqualFold(
				action.Target,
				target,
			) {
			continue
		}

		if action.Action !=
			planActionReconcile {
			t.Fatalf(
				"collector work ACL action=%s want=%s",
				action.Action,
				planActionReconcile,
			)
		}

		return
	}

	t.Fatalf(
		"collector work ACL target %q was not planned: %+v",
		target,
		plan.Actions,
	)
}

func TestPlannedACLTargetsIncludeCollectorWorkDirectory(
	t *testing.T,
) {
	t.Parallel()

	root :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			root,
			"spool",
		)

	report :=
		Report{
			Config: ConfigState{
				Path: filepath.Join(
					root,
					"config",
					"fi.conf",
				),
				SpoolDir: spoolDir,
				StageDir: filepath.Join(
					root,
					"stage",
				),
				StateDir: filepath.Join(
					root,
					"state",
				),
			},
		}

	want :=
		filepath.Join(
			root,
			".fi-spool-collector-work",
		)

	for _, target := range plannedACLTargets(
		report,
	) {
		if target.Label !=
			collectorWorkDirectoryACLLabel {
			continue
		}

		if filepath.Clean(
			target.Path,
		) != filepath.Clean(
			want,
		) {
			t.Fatalf(
				"collector work ACL path=%q want=%q",
				target.Path,
				want,
			)
		}

		return
	}

	t.Fatal(
		"collector work directory missing from planned ACL targets",
	)
}


func TestApproval2OperationalDirectoryPathsIncludeGenerationRawRoot(
    t *testing.T,
) {
    t.Parallel()

    root := t.TempDir()
    spoolDir := filepath.Join(root, "spool")

    proposal := ConfigState{
        Path:     filepath.Join(root, "config", "fi.conf"),
        SpoolDir: spoolDir,
        StageDir: filepath.Join(root, "stage"),
        StateDir: filepath.Join(root, "state"),
    }

    paths, err := approval2OperationalDirectoryPaths(
        proposal,
        approval1PKIHandoff{},
    )
    if err != nil {
        t.Fatal(err)
    }

    want := filepath.Join(root, "generation-raw")

    for _, path := range paths {
        if strings.EqualFold(
            filepath.Clean(path),
            filepath.Clean(want),
        ) {
            return
        }
    }

    t.Fatalf(
        "raw generation root %q absent from installer directories: %v",
        want,
        paths,
    )
}

func TestPlanACLsIncludesRawAndParentACLTargets(
    t *testing.T,
) {
    t.Parallel()

    root := t.TempDir()
    spoolDir := filepath.Join(root, "spool")

    report := Report{
        Config: ConfigState{
            Path:     filepath.Join(root, "config", "fi.conf"),
            SpoolDir: spoolDir,
            StageDir: filepath.Join(root, "stage"),
            StateDir: filepath.Join(root, "state"),
        },
    }

    var plan InstallPlan
    planACLs(&plan, report)

    required := []string{
        root,
        filepath.Join(root, "generation-raw"),
    }

    for _, want := range required {
        found := false

        for _, action := range plan.Actions {
            if action.Authority == "ACL" &&
                strings.EqualFold(
                    filepath.Clean(action.Target),
                    filepath.Clean(want),
                ) &&
                action.Action == planActionReconcile {
                found = true
                break
            }
        }

        if !found {
            t.Errorf(
                "required spool parent/raw generation ACL target %q missing",
                want,
            )
        }
    }
}