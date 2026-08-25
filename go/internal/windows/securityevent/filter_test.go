package securityevent

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestSelect4656Path(t *testing.T) {
	value := records.WindowsSecurityEventObservation{EventID: "4656", ObjectType: "File", ObjectName: `C:\Program Files\Wireshark\README.txt`}
	selected, ok := SelectEvent(value, []GovernedScope{{ScopeID: "root-a", GovernedRoot: `C:\Program Files\Wireshark`}})
	if !ok || len(selected.MatchedScopes) != 1 || selected.ScopeBasis != records.WindowsSecurityScopePathMatched {
		t.Fatalf("unexpected selection: %+v ok=%t", selected, ok)
	}
}

func TestSelect4660Conservative(t *testing.T) {
	value := records.WindowsSecurityEventObservation{EventID: "4660"}
	selected, ok := SelectEvent(value, nil)
	if !ok || selected.ScopeBasis != records.WindowsSecurityScopeUnresolvedFileDeleteIncluded {
		t.Fatalf("unexpected selection: %+v ok=%t", selected, ok)
	}
}

func TestUnrelatedPathIgnored(t *testing.T) {
	value := records.WindowsSecurityEventObservation{EventID: "4663", ObjectType: "File", ObjectName: `C:\Windows\Temp\x.txt`}
	_, ok := SelectEvent(value, []GovernedScope{{ScopeID: "root-a", GovernedRoot: `C:\Data`}})
	if ok {
		t.Fatal("unrelated event selected")
	}
}
