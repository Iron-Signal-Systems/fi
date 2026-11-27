//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Native FreeBSD disposable fixture: four original receiver-signed JSONL
// records exercise Other, Security and Coverage in ONE generation. These
// payloads use FI's actual audited record validators; no direct SQL
// inserts or fabricated SourceParent/typed receipts are involved.
package recordingest

import (
    "encoding/json"
    "fmt"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func c1SignedThreeFamilyRecords(t *testing.T,source string)[]spool.Record{
    t.Helper()
    // FI record timestamps require all NINE fractional digits. RFC3339Nano
    // trims trailing zeros and is intentionally rejected by the validator.
    observed:=time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
    policy:=records.WindowsSecurityAuditPolicyObservation{
        SubcategoryGUID:"{11111111-1111-1111-1111-111111111111}",
        AuditingInformation:"Success and Failure",
        SuccessEnabled:true,FailureEnabled:true,
    }
    coverage:=records.WindowsSecurityCoverageObservation{
        ObservedAt:observed,
        CollectionMethod:records.WindowsSecurityCollectionMethod,
        SecurityLogReadable:false,
        FileSystemPolicy:policy,
        HandleManipulationPolicy:policy,
        DetailedFileSharePolicy:policy,
        AuditPolicyChangePolicy:policy,
        Roots:[]records.WindowsSecurityRootAuditCoverage{{
            ScopeID:"root-a",GovernedRoot:`C:\FI-Coverage`,
            SACLState:"Present",RecommendedChangeAuditPresent:true,
            RecommendedReadAuditPresent:true,
        }},
        Status:records.WindowsSecurityCoveragePartial,
    }
    if err:=records.ValidateWindowsSecurityCoverageObservation(coverage);err!=nil{
        t.Fatalf("C1 signed fixture invalid original coverage record: %v",err)
    }
    event:=records.WindowsSecurityEventObservation{
        ObservedAt:observed,
        CollectionMethod:records.WindowsSecurityCollectionMethod,
        Channel:"Security",Provider:"Microsoft-Windows-Security-Auditing",
        EventID:"4663",EventRecordID:"40123",TimeCreated:observed,
        Computer:source,AuditResult:records.WindowsSecurityAuditSuccess,
        ScopeBasis:records.WindowsSecurityScopePathMatched,
        MatchedScopes:[]records.WindowsSecurityMatchedScope{{
            ScopeID:"root-a",GovernedRoot:`C:\FI-Coverage`,
        }},
        Fields:[]records.WindowsSecurityEventField{
            {Name:"AccessMask",Value:"0x2"},
            {Name:"ObjectName",Value:`C:\FI-Coverage\signed.txt`},
        },
        RawXML:"<Event><EventRecordID>40123</EventRecordID></Event>",
    }
    if err:=records.ValidateWindowsSecurityEventObservation(event);err!=nil{
        t.Fatalf("C1 signed fixture invalid original Security record: %v",err)
    }
    newRecord:=func(kind,scope string,payload any)spool.Record{
        raw,err:=json.Marshal(payload)
        if err!=nil{t.Fatal(err)}
        return spool.Record{
            Version:spool.RecordVersion,RecordKind:kind,
            ScopeID:scope,WrittenAt:observed,Payload:raw,
        }
    }
    original:=[]spool.Record{
        newRecord("SupportingSourceCollectionError","m1-"+source,
            map[string]string{"source":"C1-Mixed-Other","error":"first signed row"}),
        newRecord("WindowsSecurityEvent","root-a",event),
        newRecord("WindowsSecurityCoverage","root-a",coverage),
        newRecord("SupportingSourceCollectionError","m1-"+source,
            map[string]string{"source":"C1-Mixed-Other","error":"fourth signed row"}),
    }
    for i,record:=range original{
        line,e:=json.Marshal(record)
        if e!=nil{t.Fatal(e)}
        line=append(line,'\n')
        if _,e=PrepareSourceRecord(line);e!=nil{
            t.Fatalf("C1 original signed mixed record %d invalid: %v",i,e)
        }
    }
    t.Log(fmt.Sprintf("C1 signed mixed-family fixture validated: 2 Other + 1 Security + 1 Coverage, source=%s",source))
    return original
}
