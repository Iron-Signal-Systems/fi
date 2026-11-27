package backendinstall

import (
	"strings"
	"testing"
)

func TestFIIngestRuntimeAdmissionFlags(t *testing.T) {
	requiredRunner := []string{
		`fi_ingest_worker_max_generation_records="${fi_ingest_worker_max_generation_records-0}"`,
		`fi_ingest_worker_max_generation_data_bytes="${fi_ingest_worker_max_generation_data_bytes-0}"`,
		`fi_ingest_worker_max_attempts="${fi_ingest_worker_max_attempts-0}"`,
		`-max-generation-records "$fi_ingest_worker_max_generation_records"`,
		`-max-generation-data-bytes "$fi_ingest_worker_max_generation_data_bytes"`,
		`-max-attempts "$fi_ingest_worker_max_attempts"`,
	}

	for _, expected := range requiredRunner {
		if !strings.Contains(runtimeAssetIngestRunner, expected) {
			t.Fatalf("managed ingest runner missing %q", expected)
		}
	}

	requiredConfig := []string{
		`fi_ingest_worker_max_generation_records="0"`,
		`fi_ingest_worker_max_generation_data_bytes="0"`,
		`fi_ingest_worker_max_attempts="0"`,
	}

	for _, expected := range requiredConfig {
		if !strings.Contains(runtimeAssetIngestRCConfig, expected) {
			t.Fatalf("managed ingest configuration missing %q", expected)
		}
	}
}
