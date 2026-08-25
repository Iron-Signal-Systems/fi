//go:build windows

package securityevent

import "testing"

func TestAssessCheckpointContinuous(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "150", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "100", NewestEventRecordID: "200"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityContinuous {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}

func TestAssessCheckpointOverwrittenGap(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "50", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "100", NewestEventRecordID: "200"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "SecurityLogRecordsOverwritten" {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}

func TestAssessCheckpointResetGap(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "500", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "1", NewestEventRecordID: "25"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "SecurityLogResetOrCleared" {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}
