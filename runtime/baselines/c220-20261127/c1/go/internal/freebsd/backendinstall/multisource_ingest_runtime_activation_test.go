// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func TestM1IngestRuntimeNamespaceActivationContract(
	t *testing.T,
) {
	config := loadTestConfig(t)

	plan, err := buildRuntimePlan(config)
	if err != nil {
		t.Fatal(err)
	}

	runtimeConfig := runtimeTestSpecByRole(
		t, plan, "ingest-worker-runtime-config",
	)

	if !strings.Contains(
		string(runtimeConfig.Content),
		`fi_ingest_worker_namespaces="NO"`,
	) {
		t.Fatal("installer enabled namespaced ingest by default")
	}

	runner := runtimeTestSpecByRole(
		t, plan, "ingest-worker-runner",
	)

	source := string(runner.Content)

	required := []string{
		`fi_ingest_worker_namespaces:-NO`,
		`mount -p | awk`,
		`state_root="/var/db/fi/ingest"`,
		`"$state_root/quarantine"`,
		`"$state_root/history"`,
		`-generation-source-namespaces`,
		`-quarantine-state-root "$state_root/quarantine"`,
		`exec "$BINARY" "$@"`,
	}

	for _, value := range required {
		if !strings.Contains(source, value) {
			t.Fatalf(
				"missing runtime activation protection: %q",
				value,
			)
		}
	}

	if strings.Contains(source, "quarantine-release") {
		t.Fatal("normal worker runner invokes maintenance release")
	}

	t.Log("PASS: Installer retains disabled namespace default")
	t.Log("PASS: Namespaced startup requires persistent storage")
	t.Log("PASS: Maintenance release remains separate")
}
