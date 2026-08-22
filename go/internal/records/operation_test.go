// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

func TestValidateOperationRecordComplete(t *testing.T) {
	value := validOperationRecordForTest()
	if err := ValidateOperationRecord(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOperationRecordPartialRequiresReason(t *testing.T) {
	value := validOperationRecordForTest()
	value.Outcome = OperationPartial
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected missing reason_code to be rejected")
	}
}

func TestValidateOperationRecordRejectsBackwardTime(t *testing.T) {
	value := validOperationRecordForTest()
	value.StartedAt = "2026-08-22T17:00:02.000000000Z"
	value.FinishedAt = "2026-08-22T17:00:01.000000000Z"
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected backward operation time to be rejected")
	}
}

func TestValidateOperationRecordRejectsUnknownKind(t *testing.T) {
	value := validOperationRecordForTest()
	value.Kind = OperationKind("Magic")
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected unknown operation kind to be rejected")
	}
}

func validOperationRecordForTest() OperationRecord {
	return OperationRecord{
		OperationID: "op-0123456789abcdef0123456789abcdef",
		ScopeID:     "manual-test",
		Kind:        OperationUSNRead,
		StartedAt:   "2026-08-22T17:00:00.000000000Z",
		FinishedAt:  "2026-08-22T17:00:01.000000000Z",
		Outcome:     OperationComplete,
	}
}
