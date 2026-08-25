// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package securityevent

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	CollectionMethod         = records.WindowsSecurityCollectionMethod
	canonicalTimestampLayout = "2006-01-02T15:04:05.000000000Z"
)

var selectedEventIDs = map[uint32]struct{}{
	1102: {},
	4656: {},
	4660: {},
	4663: {},
	4664: {},
	4670: {},
	4719: {},
	4907: {},
}

type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       string `xml:"EventID"`
		Version       string `xml:"Version"`
		Keywords      string `xml:"Keywords"`
		EventRecordID string `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
}

func ParseEvent(rawXML string, observedAt time.Time) (records.WindowsSecurityEventObservation, error) {
	var raw eventXML
	if err := xml.Unmarshal([]byte(rawXML), &raw); err != nil {
		return records.WindowsSecurityEventObservation{}, err
	}
	if raw.System.Provider.Name == "" || raw.System.EventID == "" || raw.System.EventRecordID == "" {
		return records.WindowsSecurityEventObservation{}, errors.New("Security event missing required System fields")
	}

	eventID, err := strconv.ParseUint(strings.TrimSpace(raw.System.EventID), 10, 32)
	if err != nil {
		return records.WindowsSecurityEventObservation{}, fmt.Errorf("Security event ID: %w", err)
	}
	if _, ok := selectedEventIDs[uint32(eventID)]; !ok {
		return records.WindowsSecurityEventObservation{}, fmt.Errorf("unsupported Security event ID %d", eventID)
	}

	timeCreated, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw.System.TimeCreated.SystemTime))
	if err != nil {
		return records.WindowsSecurityEventObservation{}, fmt.Errorf("Security event time: %w", err)
	}

	fields := make([]records.WindowsSecurityEventField, 0, len(raw.EventData.Data)+8)
	for _, item := range raw.EventData.Data {
		if item.Name == "" {
			continue
		}
		fields = append(fields, records.WindowsSecurityEventField{Name: item.Name, Value: strings.TrimSpace(item.Value)})
	}
	if raw.UserData.Inner != "" {
		userFields, err := flattenUserData(raw.UserData.Inner)
		if err != nil {
			return records.WindowsSecurityEventObservation{}, err
		}
		fields = append(fields, userFields...)
	}

	value := records.WindowsSecurityEventObservation{
		ObservedAt:       formatCanonicalTime(observedAt),
		CollectionMethod: CollectionMethod,
		Channel:          strings.TrimSpace(raw.System.Channel),
		Provider:         strings.TrimSpace(raw.System.Provider.Name),
		EventID:          strconv.FormatUint(eventID, 10),
		Version:          strings.TrimSpace(raw.System.Version),
		EventRecordID:    strings.TrimSpace(raw.System.EventRecordID),
		TimeCreated:      formatCanonicalTime(timeCreated),
		Computer:         strings.TrimSpace(raw.System.Computer),
		Keywords:         strings.TrimSpace(raw.System.Keywords),
		AuditResult:      auditResult(raw.System.Keywords, uint32(eventID)),
		MatchedScopes:    []records.WindowsSecurityMatchedScope{},
		Fields:           fields,
		RawXML:           rawXML,
	}
	projectCommonFields(&value)
	return value, nil
}

func formatCanonicalTime(value time.Time) string {
	return value.UTC().Format(canonicalTimestampLayout)
}

func flattenUserData(inner string) ([]records.WindowsSecurityEventField, error) {
	decoder := xml.NewDecoder(strings.NewReader("<UserData>" + inner + "</UserData>"))
	result := []records.WindowsSecurityEventField{}
	depth := 0
	var leafName string
	var leafDepth int
	var text strings.Builder

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			depth++
			if depth >= 3 {
				leafName = value.Name.Local
				leafDepth = depth
				text.Reset()
			}
		case xml.CharData:
			if leafName != "" && depth == leafDepth {
				text.Write([]byte(value))
			}
		case xml.EndElement:
			if leafName != "" && depth == leafDepth && value.Name.Local == leafName {
				v := strings.TrimSpace(text.String())
				if v != "" {
					result = append(result, records.WindowsSecurityEventField{Name: leafName, Value: v})
				}
				leafName = ""
				text.Reset()
			}
			depth--
		}
	}
	return result, nil
}

func projectCommonFields(value *records.WindowsSecurityEventObservation) {
	field := func(names ...string) string {
		for _, name := range names {
			for _, item := range value.Fields {
				if strings.EqualFold(item.Name, name) {
					return item.Value
				}
			}
		}
		return ""
	}

	value.SubjectUserSID = field("SubjectUserSid")
	value.SubjectUserName = field("SubjectUserName")
	value.SubjectDomainName = field("SubjectDomainName")
	value.SubjectLogonID = field("SubjectLogonId")
	value.ObjectServer = field("ObjectServer")
	value.ObjectType = field("ObjectType")
	value.ObjectName = field("ObjectName")
	value.HandleID = field("HandleId")
	value.ProcessID = field("ProcessId")
	value.ProcessName = field("ProcessName")
	value.AccessMask = field("AccessMask")
	value.AccessList = field("AccessList")
	value.AccessReason = field("AccessReason")
	value.TransactionID = field("TransactionId")
	value.FileName = field("FileName")
	value.LinkName = field("LinkName")
	value.OldSecurityDescriptor = field("OldSd")
	value.NewSecurityDescriptor = field("NewSd")
	value.SubcategoryGUID = field("SubcategoryGuid")
	value.AuditPolicyChanges = field("AuditPolicyChanges")
}

func auditResult(keywords string, eventID uint32) records.WindowsSecurityAuditResult {
	if eventID == 1102 || eventID == 4719 {
		return records.WindowsSecurityAuditNotApplicable
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(keywords), "0x"), 16, 64)
	if err != nil {
		return records.WindowsSecurityAuditUnknown
	}
	switch parsed {
	case 0x8020000000000000:
		return records.WindowsSecurityAuditSuccess
	case 0x8010000000000000:
		return records.WindowsSecurityAuditFailure
	default:
		return records.WindowsSecurityAuditUnknown
	}
}
