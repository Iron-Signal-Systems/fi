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

func TestSelect5145SharePath(t *testing.T) {
	value := records.WindowsSecurityEventObservation{
		EventID:            "5145",
		ShareLocalPath:     `\??\C:\Users\jwood.admin\Downloads`,
		RelativeTargetName: `nested\fi-smb-remote-test.txt`,
	}
	selected, ok := SelectEvent(value, []GovernedScope{{
		ScopeID:      "root-a",
		GovernedRoot: `C:\Users\jwood.admin\Downloads`,
	}})
	if !ok || len(selected.MatchedScopes) != 1 || selected.ScopeBasis != records.WindowsSecurityScopeSharePathMatched {
		t.Fatalf("unexpected 5145 selection: %+v ok=%t", selected, ok)
	}
}

func TestSelect5145ParentSharePath(t *testing.T) {
	value := records.WindowsSecurityEventObservation{
		EventID:            "5145",
		ShareLocalPath:     `\??\C:`,
		RelativeTargetName: `Users\jwood.admin\Downloads\fi-smb-admin-share-test.txt`,
	}
	selected, ok := SelectEvent(value, []GovernedScope{{
		ScopeID:      "root-a",
		GovernedRoot: `C:\Users\jwood.admin\Downloads`,
	}})
	if !ok || len(selected.MatchedScopes) != 1 || selected.ScopeBasis != records.WindowsSecurityScopeSharePathMatched {
		t.Fatalf("unexpected parent-share 5145 selection: %+v ok=%t", selected, ok)
	}
}

func TestSelect5145ShareRootIgnored(t *testing.T) {
	value := records.WindowsSecurityEventObservation{
		EventID:            "5145",
		ShareLocalPath:     `\??\C:\Users\jwood.admin\Downloads`,
		RelativeTargetName: `\`,
	}
	if _, ok := SelectEvent(value, []GovernedScope{{
		ScopeID:      "root-a",
		GovernedRoot: `C:\Users\jwood.admin\Downloads`,
	}}); ok {
		t.Fatal("bare 5145 share-root access was selected")
	}
}

func TestSelect5145UnrelatedSharePathIgnored(t *testing.T) {
	value := records.WindowsSecurityEventObservation{
		EventID:            "5145",
		ShareLocalPath:     `\??\C:\Windows`,
		RelativeTargetName: `Temp\x.txt`,
	}
	if _, ok := SelectEvent(value, []GovernedScope{{
		ScopeID:      "root-a",
		GovernedRoot: `C:\Users\jwood.admin\Downloads`,
	}}); ok {
		t.Fatal("unrelated 5145 event selected")
	}
}

func TestUnrelatedPathIgnored(t *testing.T) {
	value := records.WindowsSecurityEventObservation{EventID: "4663", ObjectType: "File", ObjectName: `C:\Windows\Temp\x.txt`}
	_, ok := SelectEvent(value, []GovernedScope{{ScopeID: "root-a", GovernedRoot: `C:\Data`}})
	if ok {
		t.Fatal("unrelated event selected")
	}
}
