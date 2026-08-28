// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package operation

import (
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"strings"
	"testing"
)

func TestStartFinishComplete(t *testing.T) {
	started, err := Start("manual-test", records.OperationUSNRead)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(started.OperationID, "op-") {
		t.Fatalf("unexpected operation id %q", started.OperationID)
	}

	record, err := started.Finish(records.OperationComplete, "")
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != records.OperationComplete {
		t.Fatalf("unexpected outcome %q", record.Outcome)
	}
	if err := records.ValidateOperationRecord(record); err != nil {
		t.Fatal(err)
	}
}

func TestFinishPartialRequiresReason(t *testing.T) {
	started, err := Start("manual-test", records.OperationReObservation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := started.Finish(records.OperationPartial, ""); err == nil {
		t.Fatal("expected partial operation without reason to fail validation")
	}
}
