//go:build freebsd && fi_backlog_typed_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

// Each of the five previously excluded source families is projected through
// the existing strict production projector. Fixtures exercise nested child
// tables and atomic rollback, not merely the parent-kind allowlist.
func backlogRemainingFamiliesFixture(t *testing.T, badLate bool) *PreparedGeneration {
    t.Helper()
    source:="fi-private-all-families.iss.local"
    if badLate {
        source="fi-private-all-families-late.iss.local"
    }
    g:=privateTypedFixture(t,source,false)
    g.Receipt.Descriptor.GenerationID="20261101T130000.000000000Z-all-families"
    receiptDigest:=sha256.Sum256([]byte("fi-private-all-families-test/receipt/"+source))
    transferDigest:=sha256.Sum256([]byte("fi-private-all-families-test/transfer/"+source))
    g.ReceiptSHA256=hex.EncodeToString(receiptDigest[:])
    g.Receipt.TransferSHA256=hex.EncodeToString(transferDigest[:])
    g.Receipt.DataBytes=0

    observed:="2026-11-01T13:00:00.123456789Z"
    sidUser:="S-1-1-0"
    sidUserRaw:=base64.RawURLEncoding.EncodeToString([]byte{
        1,1,0,0,0,0,0,1,0,0,0,0,
    })
    sidGroup:="S-1-5-32-544"
    sidGroupRaw:=base64.RawURLEncoding.EncodeToString([]byte{
        1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0,
    })
    guidRaw:=base64.RawURLEncoding.EncodeToString(make([]byte,16))
    for bi:=range g.Batches {
        b:=&g.Batches[bi]
        var data []byte
        for n:=0;n<b.Manifest.RecordCount;n++{
            var kind string
            var payload any
            switch bi*3+n {
            case 0,5:
                kind="CollectorIdentity"
                collector:=records.ProcessIdentityObservation{
                    ObservedAt:observed,
                    CollectionMethod:records.ProcessIdentityCollectionMethod,
                    Computer:records.ComputerIdentity{NetBIOSName:"FI-TEST"},
                    Token:records.ProcessTokenObservation{
                        User:records.TokenPrincipalObservation{SID:sidUser,AccountName:"Everyone"},
                        TokenTypeRaw:"1",TokenTypeName:"Primary",
                        ElevationTypeRaw:"1",ElevationTypeName:"Default",
                        Groups:[]records.TokenGroupObservation{{
                            Index:"0",Principal:records.TokenPrincipalObservation{SID:sidGroup},
                            AttributesRaw:"7",Mandatory:true,EnabledByDefault:true,Enabled:true,
                        }},
                        Privileges:[]records.TokenPrivilegeObservation{{
                            Index:"0",LUIDLow:"1",LUIDHigh:"0",Name:"SeChangeNotifyPrivilege",
                            AttributesRaw:"2",Enabled:true,
                        }},
                    },
                }
                if badLate && bi==1 {collector.CollectionMethod="InvalidCollectorMethod"}
                if !badLate||bi==0 {
                    if err:=records.ValidateProcessIdentityObservation(collector);err!=nil{t.Fatal(err)}
                }
                payload=collector
            case 1:
                kind="DirectoryPrincipalSnapshot"
                directory:=records.DirectoryPrincipalSnapshot{
                    ObservedAt:observed,
                    CollectionMethod:records.DirectoryPrincipalCollectionMethod,
                    DomainDNSName:"iss.local",
                    ServerDNSName:"dc.iss.local",
                    NamingContext:"DC=iss,DC=local",
                    RequestedSIDs:[]string{sidUser},
                    Principals:[]records.DirectoryPrincipalObservation{{
                        SID:sidUser,SIDRawBase64URL:sidUserRaw,
                        ObjectGUID:"00000000-0000-0000-0000-000000000000",
                        ObjectGUIDRawBase64URL:guidRaw,
                        DistinguishedName:"CN=Everyone,DC=iss,DC=local",
                        ObjectClasses:[]string{"top"},
                    }},
                }
                if err:=records.ValidateDirectoryPrincipalSnapshot(directory);err!=nil{t.Fatal(err)}
                payload=directory
            case 2:
                kind="LocalPrincipalSnapshot"
                local:=records.LocalPrincipalSnapshot{
                    ObservedAt:observed,
                    CollectionMethod:records.LocalPrincipalCollectionMethod,
                    ComputerName:"FI-TEST",
                    Users:[]records.LocalUserObservation{{
                        SID:sidUser,SIDRawBase64URL:sidUserRaw,
                        NameDisplay:"U",NameUTF16LEBase64URL:base64.RawURLEncoding.EncodeToString([]byte{'U',0}),
                        FlagsRaw:"0",
                    }},
                    Groups:[]records.LocalGroupObservation{{
                        SID:sidGroup,SIDRawBase64URL:sidGroupRaw,
                        NameDisplay:"G",NameUTF16LEBase64URL:base64.RawURLEncoding.EncodeToString([]byte{'G',0}),
                        MembershipState:records.LocalMembershipComplete,
                    }},
                    Memberships:[]records.LocalGroupMembershipObservation{{
                        GroupSID:sidGroup,MemberSID:sidUser,MemberSIDRawBase64URL:sidUserRaw,
                        SIDNameUseRaw:"1",SIDNameUseName:"User",
                    }},
                }
                if err:=records.ValidateLocalPrincipalSnapshot(local);err!=nil{t.Fatal(err)}
                payload=local
            case 3:
                kind="SMBShareSnapshot"
                smb:=records.SMBShareSnapshot{
                    ObservedAt:observed,
                    CollectionMethod:records.SMBShareCollectionWindowsNetShareEnum502,
                    Shares:[]records.SMBShareObservation{{
                        NameDisplay:"FI",NameUTF16LEBase64URL:base64.RawURLEncoding.EncodeToString([]byte{'F',0,'I',0}),
                        TypeRaw:"0",TypeName:records.SMBShareTypeDiskTree,
                        LocalPathDisplay:"C:\\FI",
                        LocalPathUTF16LEBase64URL:base64.RawURLEncoding.EncodeToString([]byte{'C',0,':',0,'\\',0,'F',0,'I',0}),
                        PermissionsRaw:"0",MaxUsesRaw:"4294967295",CurrentUses:"0",
                        Security:records.SecurityObservationError("AccessDenied"),
                    }},
                }
                if err:=records.ValidateSMBShareSnapshot(smb);err!=nil{t.Fatal(err)}
                payload=smb
            case 4:
                kind="WindowsSecurityContinuityGap"
                gap:=records.WindowsSecurityContinuityGapObservation{
                    ObservedAt:observed,
                    CollectionMethod:records.WindowsSecurityCollectionMethod,
                    Channel:"Security",ScopeID:"test-scope-1",
                    ReasonCode:"SecurityLogRecordsOverwritten",
                    CheckpointEventRecordID:"42",
                    CurrentOldestEventRecordID:"55",
                    CurrentNewestEventRecordID:"120",
                    CoverageState:records.WindowsSecurityContinuityGapCoverageIncomplete,
                    ReconciliationAction:records.WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
                }
                if err:=records.ValidateWindowsSecurityContinuityGapObservation(gap);err!=nil{t.Fatal(err)}
                payload=gap
            default:
                t.Fatalf("unexpected fixture index %d",bi*3+n)
            }
            raw,err:=json.Marshal(payload);if err!=nil{t.Fatal(err)}
            envelope:=spool.Record{
                Version:SpoolRecordVersion,RecordKind:kind,
                ScopeID:fmt.Sprintf("test-scope-%d",bi),
                WrittenAt:observed,Payload:raw,
            }
            encoded,err:=json.Marshal(envelope);if err!=nil{t.Fatal(err)}
            data=append(data,encoded...)
            data=append(data,'\n')
        }
        path:=filepath.Join(t.TempDir(),"remaining.jsonl")
        if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
        b.DataPath=path
        b.Manifest.DataBytes=int64(len(data))
        hash:=sha256.Sum256(data)
        b.Manifest.DataSHA256=hex.EncodeToString(hash[:])
        manifest,err:=json.Marshal(b.Manifest);if err!=nil{t.Fatal(err)}
        b.ManifestRawBytes=manifest
        b.ManifestBytes=len(manifest)
        mh:=sha256.Sum256(manifest)
        b.ManifestSHA256=hex.EncodeToString(mh[:])
        g.Receipt.DataBytes+=uint64(len(data))
    }
    return g
}

func exerciseBacklogRemainingFamilies(t *testing.T,ctx context.Context,reader,writer *pgx.Conn) {
    t.Helper()
    limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
    good:=backlogRemainingFamiliesFixture(t,false)
    root:=privateBacklogTestRoot(t)
    for i:=0;i<2;i++{
        if _,err:=MaterializeBacklogWindow(ctx,good,limits,i,root);err!=nil{t.Fatal(err)}
        if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,good,limits,i,root);err!=nil{t.Fatal(err)}
        if err:=StageVerifiedBacklogSourceWindow(ctx,writer,good,limits,i,root);err!=nil{t.Fatal(err)}
        if err:=StageBacklogTypedWindow(ctx,reader,writer,good,limits,i,root);err!=nil{
            t.Fatalf("family window %d: %v",i,err)
        }
    }
    if err:=StageBacklogTypedWindow(ctx,reader,writer,good,limits,1,root);err!=nil{
        t.Fatalf("family final window replay: %v",err)
    }
    verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,good,limits)
    if err!=nil{t.Fatalf("complete family generation: %v",err)}
    if verified.Windows!=2 || verified.Records!=6 || verified.DataBytes!=good.Receipt.DataBytes{
        t.Fatalf("wrong family verification: %+v",verified)
    }
    var collector,groups,privs,directory,requested,principal,classes,local,users,localGroups,members,smb,shares,gap,authoritative int64
    err=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.collector_identity),
 (SELECT count(*) FROM fi_recovery_projection.collector_token_group),
 (SELECT count(*) FROM fi_recovery_projection.collector_token_privilege),
 (SELECT count(*) FROM fi_recovery_projection.directory_principal_snapshot),
 (SELECT count(*) FROM fi_recovery_projection.directory_requested_sid),
 (SELECT count(*) FROM fi_recovery_projection.directory_principal),
 (SELECT count(*) FROM fi_recovery_projection.directory_principal_class),
 (SELECT count(*) FROM fi_recovery_projection.local_principal_snapshot),
 (SELECT count(*) FROM fi_recovery_projection.local_user),
 (SELECT count(*) FROM fi_recovery_projection.local_group),
 (SELECT count(*) FROM fi_recovery_projection.local_group_membership),
 (SELECT count(*) FROM fi_recovery_projection.smb_share_snapshot),
 (SELECT count(*) FROM fi_recovery_projection.smb_share),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_continuity_gap),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`,good.Receipt.Descriptor.SourceID).Scan(&collector,&groups,&privs,&directory,&requested,&principal,&classes,
        &local,&users,&localGroups,&members,&smb,&shares,&gap,&authoritative)
    if err!=nil{t.Fatal(err)}
    if collector!=2||groups!=2||privs!=2||directory!=1||requested!=1||principal!=1||classes!=1||
       local!=1||users!=1||localGroups!=1||members!=1||smb!=1||shares!=1||gap!=1||authoritative!=0{
        t.Fatalf("family/child projections incomplete collector=%d groups=%d privs=%d directory=%d requested=%d principal=%d classes=%d local=%d users=%d groups=%d members=%d smb=%d shares=%d gap=%d canonical=%d",
            collector,groups,privs,directory,requested,principal,classes,local,users,localGroups,members,smb,shares,gap,authoritative)
    }

    // The second window's last collector record is deliberately invalid.
    // Even though SMB and continuity-gap parents precede it, none of those
    // second-window rows or its marker may survive the failed transaction.
    bad:=backlogRemainingFamiliesFixture(t,true)
    badRoot:=privateBacklogTestRoot(t)
    for i:=0;i<2;i++{
        if _,err:=MaterializeBacklogWindow(ctx,bad,limits,i,badRoot);err!=nil{t.Fatal(err)}
        if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,bad,limits,i,badRoot);err!=nil{t.Fatal(err)}
        if err:=StageVerifiedBacklogSourceWindow(ctx,writer,bad,limits,i,badRoot);err!=nil{t.Fatal(err)}
    }
    if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,limits,0,badRoot);err!=nil{t.Fatal(err)}
    if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,limits,1,badRoot);err==nil{
        t.Fatal("invalid late collector record committed second private typed window")
    }
    if _,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,bad,limits);err==nil{
        t.Fatal("incomplete all-family generation unexpectedly verified")
    }
    var markerCount,recordCount int64
    err=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery_projection.source_record AS sr
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi_recovery_projection.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
  WHERE rg.source_id=$2)
`,bad.ReceiptSHA256,bad.Receipt.Descriptor.SourceID).Scan(&markerCount,&recordCount)
    if err!=nil{t.Fatal(err)}
    if markerCount!=1||recordCount!=3{
        t.Fatalf("late all-family rollback failed markers=%d sourceRows=%d",markerCount,recordCount)
    }
    t.Log("PASS: all 5 remaining source families and child rows, complete recovery verification, replay, late rollback, zero canonical rows")
}
