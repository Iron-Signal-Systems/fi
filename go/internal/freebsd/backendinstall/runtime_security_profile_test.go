// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func TestManagedIngestSecurityProfileP3(t *testing.T) {
	requiredRunner := []string{
		`fi_ingest_worker_security_profile="${fi_ingest_worker_security_profile-P1}"`,
		`P1|P2|P3|P4|P5)`,
		`-security-profile "$fi_ingest_worker_security_profile"`,
	}

	for _, value := range requiredRunner {
		if !strings.Contains(runtimeAssetIngestRunner, value) {
			t.Fatalf("managed runner missing %q", value)
		}
	}

	if !strings.Contains(
		runtimeAssetIngestRCConfig,
		`fi_ingest_worker_security_profile="P3"`,
	) {
		t.Fatal("managed runtime must explicitly select tested P3")
	}
}
