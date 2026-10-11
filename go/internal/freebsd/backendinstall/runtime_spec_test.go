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

func TestRuntimePlanExactContract(
	t *testing.T,
) {
	config := loadTestConfig(t)

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		t.Fatalf(
			"buildRuntimePlan() error = %v",
			err,
		)
	}

	if len(plan.Parents) != 6 {
		t.Fatalf(
			"parent count = %d, want 6",
			len(plan.Parents),
		)
	}

	if len(plan.Files) != 6 {
		t.Fatalf(
			"file count = %d, want 6",
			len(plan.Files),
		)
	}

	expected := map[string]struct {
		mode   os.FileMode
		target string
	}{
		"receiver-supervisor": {
			mode: 0o555,
			target: filepath.Join(
				config.Value("FI_RECEIVER_ROOT"),
				"usr/local/libexec/fi-receiver-supervisor",
			),
		},
		"receiver-rc-service": {
			mode: 0o555,
			target: filepath.Join(
				config.Value("FI_RECEIVER_ROOT"),
				"usr/local/etc/rc.d/fi_receiver",
			),
		},
		"receiver-runtime-config": {
			mode: 0o644,
			target: filepath.Join(
				config.Value("FI_RECEIVER_ROOT"),
				"etc/rc.conf.d/fi_receiver",
			),
		},
		"ingest-worker-runner": {
			mode: 0o555,
			target: filepath.Join(
				config.Value("FI_INGEST_ROOT"),
				"usr/local/libexec/fi-ingest-worker-run",
			),
		},
		"ingest-worker-rc-service": {
			mode: 0o555,
			target: filepath.Join(
				config.Value("FI_INGEST_ROOT"),
				"usr/local/etc/rc.d/fi_ingest_worker",
			),
		},
		"ingest-worker-runtime-config": {
			mode: 0o644,
			target: filepath.Join(
				config.Value("FI_INGEST_ROOT"),
				"etc/rc.conf.d/fi_ingest_worker",
			),
		},
	}

	for _, spec := range plan.Files {
		want, exists := expected[spec.Role]
		if !exists {
			t.Fatalf(
				"unexpected runtime role: %s",
				spec.Role,
			)
		}

		if spec.Target != want.target {
			t.Fatalf(
				"%s target = %q, want %q",
				spec.Role,
				spec.Target,
				want.target,
			)
		}

		if spec.Mode != want.mode ||
			spec.UID != 0 ||
			spec.GID != 0 {
			t.Fatalf(
				"%s metadata = %d:%d %o",
				spec.Role,
				spec.UID,
				spec.GID,
				spec.Mode,
			)
		}

		if hostFileTokenPattern.Match(
			spec.Content,
		) {
			t.Fatalf(
				"%s contains unresolved token",
				spec.Role,
			)
		}

		if !containsExactLine(
			spec.Content,
			runtimeFileMarker,
		) {
			t.Fatalf(
				"%s lacks runtime marker",
				spec.Role,
			)
		}

		if !containsExactLine(
			spec.Content,
			"# FI-ROLE: "+spec.Role,
		) {
			t.Fatalf(
				"%s lacks exact role marker",
				spec.Role,
			)
		}
	}
}

func TestRuntimePlanDerivedAddresses(
	t *testing.T,
) {
	config := loadTestConfig(t)

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	receiverIP, err := pfAddressOnly(
		"FI_RECEIVER_EXTERNAL_ADDRESS",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	receiver := runtimeTestSpecByRole(
		t,
		plan,
		"receiver-runtime-config",
	)

	receiverContent := string(
		receiver.Content,
	)

	if !strings.Contains(
		receiverContent,
		`fi_receiver_bind="`+receiverIP+`:8443"`,
	) {
		t.Fatal(
			"receiver runtime config lacks exact address-only bind",
		)
	}

	if strings.Contains(
		receiverContent,
		config.Value(
			"FI_RECEIVER_EXTERNAL_ADDRESS",
		),
	) {
		t.Fatal(
			"receiver runtime config retained CIDR address",
		)
	}

	ingest := runtimeTestSpecByRole(
		t,
		plan,
		"ingest-worker-runtime-config",
	)

	ingestContent := string(
		ingest.Content,
	)

	if strings.Contains(
		ingestContent,
		"fi_ingest_worker_source",
	) ||
		strings.Contains(
			ingestContent,
			"FI_RUNTIME_SOURCE_ID",
		) {
		t.Fatal(
			"ingest runtime config retained single-source state",
		)
	}

	if !strings.Contains(
		ingestContent,
		"host="+sorIP+" port=5432",
	) {
		t.Fatal(
			"ingest runtime config lacks exact SOR address",
		)
	}

	if strings.Contains(
		ingestContent,
		config.Value(
			"FI_SOR_DB_WORK_ADDRESS",
		),
	) {
		t.Fatal(
			"ingest runtime config retained SOR CIDR address",
		)
	}
}

func TestRuntimeReceiverUsesPersistentBoundedListener(
	t *testing.T,
) {
	config := loadTestConfig(t)

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	supervisor := runtimeTestSpecByRole(
		t,
		plan,
		"receiver-supervisor",
	)

	supervisorContent := string(
		supervisor.Content,
	)

	if strings.Contains(
		supervisorContent,
		"while :",
	) {
		t.Fatal(
			"receiver runtime retained one-transaction restart loop",
		)
	}

	if !strings.Contains(
		supervisorContent,
		`exec "$BINARY" \`,
	) {
		t.Fatal(
			"receiver runtime does not exec persistent receiver",
		)
	}

	if !strings.Contains(
		supervisorContent,
		`-max-concurrent-connections "$fi_receiver_max_concurrent_connections"`,
	) {
		t.Fatal(
			"receiver runtime does not pass concurrency bound",
		)
	}

	runtimeConfig := runtimeTestSpecByRole(
		t,
		plan,
		"receiver-runtime-config",
	)

	if !strings.Contains(
		string(runtimeConfig.Content),
		`fi_receiver_max_concurrent_connections="8"`,
	) {
		t.Fatal(
			"receiver runtime config lacks default concurrency bound",
		)
	}
}

func TestRuntimeStaticAssetsRemainExact(
	t *testing.T,
) {
	cases := []struct {
		actual string
		path   string
	}{
		{
			runtimeAssetReceiverSupervisor,
			"../../../../tools/deployment/freebsd/runtime.d/fi-receiver-supervisor.sh",
		},
		{
			runtimeAssetReceiverRCService,
			"../../../../tools/deployment/freebsd/runtime.d/fi-receiver.rc.d",
		},
		{
			runtimeAssetReceiverRCConfig,
			"../../../../tools/deployment/freebsd/runtime.d/fi-receiver.rc.conf.template",
		},
		{
			runtimeAssetIngestRunner,
			"../../../../tools/deployment/freebsd/runtime.d/fi-ingest-worker-run.sh",
		},
		{
			runtimeAssetIngestRCService,
			"../../../../tools/deployment/freebsd/runtime.d/fi-ingest-worker.rc.d",
		},
		{
			runtimeAssetIngestRCConfig,
			"../../../../tools/deployment/freebsd/runtime.d/fi-ingest-worker.rc.conf.template",
		},
	}

	if len(cases) != 6 {
		t.Fatalf(
			"runtime asset case count = %d, want 6",
			len(cases),
		)
	}

	seen := make(
		map[string]bool,
		len(cases),
	)

	for _, test := range cases {
		if seen[test.path] {
			t.Fatalf(
				"duplicate runtime asset source: %s",
				test.path,
			)
		}

		seen[test.path] = true

		expected, err := os.ReadFile(
			test.path,
		)
		if err != nil {
			t.Fatal(err)
		}

		if test.actual != string(expected) {
			t.Fatalf(
				"embedded runtime asset differs from source: %s",
				test.path,
			)
		}
	}
}

func TestRenderRuntimeAssetRejectsUnknownToken(
	t *testing.T,
) {
	config := loadTestConfig(t)

	values, err := runtimeRenderValues(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = renderRuntimeAsset(
		runtimeFileMarker+
			"\n@FI_NOT_A_REAL_KEY@\n",
		values,
	)

	if err == nil {
		t.Fatal(
			"renderRuntimeAsset accepted unknown token",
		)
	}
}

func runtimeTestSpecByRole(
	t *testing.T,
	plan runtimePlan,
	role string,
) runtimeFileSpec {
	t.Helper()

	for _, spec := range plan.Files {
		if spec.Role == role {
			return spec
		}
	}

	t.Fatalf(
		"runtime role not found: %s",
		role,
	)

	return runtimeFileSpec{}
}

func TestRuntimeApprovedPriorNames(
	t *testing.T,
) {
	config := loadTestConfig(t)

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		"receiver-supervisor":          "fi-receiver-supervisor",
		"receiver-rc-service":          "rc.d.fi_receiver",
		"receiver-runtime-config":      "rc.conf.d.fi_receiver",
		"ingest-worker-runner":         "fi-ingest-worker-run",
		"ingest-worker-rc-service":     "rc.d.fi_ingest_worker",
		"ingest-worker-runtime-config": "rc.conf.d.fi_ingest_worker",
	}

	if len(plan.Files) != len(expected) {
		t.Fatalf(
			"runtime file count = %d, want %d",
			len(plan.Files),
			len(expected),
		)
	}

	seen := make(
		map[string]bool,
		len(plan.Files),
	)

	for _, spec := range plan.Files {
		want, exists := expected[spec.Role]
		if !exists {
			t.Fatalf(
				"unexpected runtime role: %s",
				spec.Role,
			)
		}

		if spec.PriorName != want {
			t.Fatalf(
				"%s PriorName = %q, want %q",
				spec.Role,
				spec.PriorName,
				want,
			)
		}

		if spec.PriorName == "" {
			t.Fatalf(
				"%s has empty approved-prior name",
				spec.Role,
			)
		}

		if seen[spec.PriorName] {
			t.Fatalf(
				"duplicate approved-prior name: %s",
				spec.PriorName,
			)
		}

		seen[spec.PriorName] = true
	}
}
