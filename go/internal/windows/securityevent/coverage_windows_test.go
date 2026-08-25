//go:build windows

package securityevent

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestHasRecommendedAuditACE(t *testing.T) {
	sacl := records.SACLObservation{
		State: records.ObservationStatePresent,
		ACL: records.ACLObservation{
			State: records.ACLStatePresent,
			ACEs: []records.ACEObservation{{
				Type: "2", SID: "S-1-1-0", Mask: "852310", Flags: "195",
			}},
		},
	}
	if !hasRecommendedAuditACE(sacl) {
		t.Fatal("recommended ACE not recognized")
	}
}
