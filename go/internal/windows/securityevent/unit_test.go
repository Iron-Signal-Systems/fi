// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package securityevent

import (
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"strings"
	"testing"
	"time"
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

func TestParse4656Failure(t *testing.T) {
	raw := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4656</EventID><Version>1</Version><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-08-24T10:07:23.268969100Z"/><EventRecordID>44</EventRecordID><Channel>Security</Channel><Computer>ISS-FS-01.iss.local</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1</Data><Data Name="SubjectUserName">jwood.admin</Data><Data Name="SubjectDomainName">ISS</Data><Data Name="SubjectLogonId">0x123</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\Program Files\Wireshark\README.txt</Data><Data Name="ProcessId">0x456</Data><Data Name="ProcessName">C:\Windows\notepad.exe</Data><Data Name="AccessMask">0x120089</Data><Data Name="AccessList">%%4416</Data><Data Name="AccessReason">%%4416: %%1802 D:(D;;CC;;;S-1-5-21-1)</Data></EventData></Event>`
	value, err := ParseEvent(raw, time.Date(2026, 8, 24, 10, 8, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if value.AuditResult != records.WindowsSecurityAuditFailure ||
		value.SubjectUserName != "jwood.admin" ||
		value.ObjectName == "" {
		t.Fatalf("unexpected parsed value: %+v", value)
	}
	if value.AccessMask != "0x120089" {
		t.Fatalf("access_mask=%q", value.AccessMask)
	}
	if !strings.Contains(value.AccessReason, "D:(D;;CC;;;S-1-5-21-1)") {
		t.Fatalf("access_reason=%q", value.AccessReason)
	}
}

func TestParse5145RemoteShareAccess(t *testing.T) {
	raw := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5145</EventID><Version>0</Version><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-08-25T22:00:00.123456700Z"/><EventRecordID>29486</EventRecordID><Channel>Security</Channel><Computer>AdminBox.iss.local</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1</Data><Data Name="SubjectUserName">jwood.admin</Data><Data Name="SubjectDomainName">ISS</Data><Data Name="SubjectLogonId">0xd2b5f9e</Data><Data Name="ObjectType">File</Data><Data Name="IpAddress">192.168.1.210</Data><Data Name="IpPort">51090</Data><Data Name="ShareName">\\*\FI-Downloads</Data><Data Name="ShareLocalPath">\??\C:\Users\jwood.admin\Downloads</Data><Data Name="RelativeTargetName">fi-smb-remote-denied.txt</Data><Data Name="AccessMask">0x120089</Data><Data Name="AccessList">%%4416</Data><Data Name="AccessReason">%%4416: %%1801 D:(A;;FA;;;S-1-5-21-1)</Data></EventData></Event>`
	value, err := ParseEvent(raw, time.Date(2026, 8, 25, 22, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if value.AuditResult != records.WindowsSecurityAuditSuccess {
		t.Fatalf("audit_result=%q", value.AuditResult)
	}
	if value.SubjectLogonID != "0xd2b5f9e" || value.SourceIP != "192.168.1.210" || value.SourcePort != "51090" {
		t.Fatalf("unexpected remote context: %+v", value)
	}
	if value.ShareName != `\\*\FI-Downloads` ||
		value.ShareLocalPath != `\??\C:\Users\jwood.admin\Downloads` ||
		value.RelativeTargetName != "fi-smb-remote-denied.txt" {
		t.Fatalf("unexpected share context: %+v", value)
	}
	if value.AccessMask != "0x120089" || value.AccessList != "%%4416" || value.AccessReason == "" {
		t.Fatalf("unexpected access context: %+v", value)
	}
}

func TestParse1102UserData(t *testing.T) {
	raw := `<Event><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><Version>0</Version><TimeCreated SystemTime="2026-08-24T10:00:00Z"/><EventRecordID>45</EventRecordID><Channel>Security</Channel><Computer>ISS-FS-01</Computer></System><UserData><LogFileCleared><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>admin</SubjectUserName><SubjectDomainName>ISS</SubjectDomainName><SubjectLogonId>0x55</SubjectLogonId></LogFileCleared></UserData></Event>`
	observedAt := time.Date(2026, 8, 24, 10, 1, 2, 0, time.UTC)
	value, err := ParseEvent(raw, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if value.SubjectUserName != "admin" || value.AuditResult != records.WindowsSecurityAuditNotApplicable {
		t.Fatalf("unexpected parsed value: %+v", value)
	}
	if value.ObservedAt != "2026-08-24T10:01:02.000000000Z" {
		t.Fatalf("observed_at=%q", value.ObservedAt)
	}
	if value.TimeCreated != "2026-08-24T10:00:00.000000000Z" {
		t.Fatalf("time_created=%q", value.TimeCreated)
	}
}
