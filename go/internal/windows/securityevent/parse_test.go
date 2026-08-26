package securityevent

import (
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

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
