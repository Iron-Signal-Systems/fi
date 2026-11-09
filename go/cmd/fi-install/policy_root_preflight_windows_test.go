// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/policyassociation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

func scopeWithRoot(t *testing.T) config.VolumeConfig {
	t.Helper()
	value := validInventoryScope(t)
	value.Policies = []config.RootPolicy{{
		ID: "finance", VolumeID: "data",
		RelativeRoot: `\Shares\Finance`, Depth: config.DepthSecurity,
	}}
	if _, err := config.CanonicalVolumeV2(value); err != nil { t.Fatal(err) }
	return value
}

func fixtureRootID() policyassociation.FileID {
	var result policyassociation.FileID
	result[0], result[15] = 1, 90
	return result
}

func fixtureRootBindings() []policyassociation.RootBinding {
	return []policyassociation.RootBinding{{
		PolicyID: "finance", VolumeID: "data", RootID: fixtureRootID(),
	}}
}

func TestReadOnlyPolicyRootReportDoesNotGrantInstallation(t *testing.T) {
	scope := scopeWithRoot(t)
	calls := 0
	var buf bytes.Buffer
	err := writeVolumeInventoryWithRootInspection(
		context.Background(), &buf, healthyInventory,
		func(_ context.Context, received config.VolumeConfig, enrollmentID string) ([]policyassociation.RootBinding, error) {
			calls++
			if enrollmentID != "data" || received.Version != config.VolumeConfigVersion {
				t.Fatalf("inspector received unexpected scope or enrollment %s", enrollmentID)
			}
			return fixtureRootBindings(), nil
		}, time.Now, &scope, true,
	)
	if err != nil || calls != 1 { t.Fatalf("read-only verified inspection error=%v calls=%d", err, calls) }
	var report volumeInventoryReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil { t.Fatal(err) }
	expectedID := fixtureRootID()
	wantHex := hex.EncodeToString(expectedID[:])
	if report.CollectionAuthorized || !report.PolicyRootsInspected ||
		!report.PolicyRootChecksComplete || report.PreflightBlocked ||
		report.Action != "DiscoveryScopeAndPolicyRootPreflightOnly" ||
		report.RequestedScopeReview == nil || report.RequestedScopeReview.BlocksMutation ||
		len(report.PolicyRootInspections) != 1 ||
		report.PolicyRootInspections[0].Status != "IdentitiesObserved" ||
		len(report.PolicyRootInspections[0].Identities) != 1 ||
		report.PolicyRootInspections[0].Identities[0].PolicyID != "finance" ||
		report.PolicyRootInspections[0].Identities[0].FileID128Hex != wantHex {
		t.Fatalf("misrepresented read-only root report: %+v", report)
	}
}

func TestRootPreflightFailurePreservesEvidenceAndBlocks(t *testing.T) {
	scope := scopeWithRoot(t)
	var buf bytes.Buffer
	err := writeVolumeInventoryWithRootInspection(
		context.Background(), &buf, healthyInventory,
		func(context.Context, config.VolumeConfig, string) ([]policyassociation.RootBinding, error) {
			return fixtureRootBindings(), errors.New("native directory denied")
		}, time.Now, &scope, true,
	)
	if !errors.Is(err, ErrVolumePreflightMismatch) { t.Fatalf("root failure returned %v", err) }
	var report volumeInventoryReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil { t.Fatal(err) }
	if report.CollectionAuthorized || !report.PolicyRootsInspected || report.PolicyRootChecksComplete ||
		!report.PreflightBlocked || len(report.PolicyRootInspections) != 1 ||
		report.PolicyRootInspections[0].Status != "RootAttestationFailed" ||
		!strings.Contains(report.PolicyRootInspections[0].Detail, "native directory denied") ||
		len(report.PolicyRootInspections[0].Identities) != 0 {
		t.Fatalf("partial identity erroneously accepted: %+v", report)
	}
}

func TestRootPreflightRejectsMalformedOrIncompleteNativeBindings(t *testing.T) {
	scope := scopeWithRoot(t)
	cases := []struct{
		name string
		bindings []policyassociation.RootBinding
	}{
		{"missing binding", nil},
		{"zero native object", []policyassociation.RootBinding{{PolicyID:"finance", VolumeID:"data"}}},
		{"foreign volume", []policyassociation.RootBinding{{PolicyID:"finance",VolumeID:"system",RootID:fixtureRootID()}}},
		{"wrong policy", []policyassociation.RootBinding{{PolicyID:"unknown",VolumeID:"data",RootID:fixtureRootID()}}},
		{"duplicate", append(fixtureRootBindings(), fixtureRootBindings()...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeVolumeInventoryWithRootInspection(
				context.Background(), &buf, healthyInventory,
				func(context.Context,config.VolumeConfig,string)([]policyassociation.RootBinding,error){
					return tc.bindings,nil
				}, time.Now, &scope, true,
			)
			if !errors.Is(err, ErrVolumePreflightMismatch) { t.Fatalf("bad native binding accepted: %v", err) }
			var report volumeInventoryReport
			if json.Unmarshal(buf.Bytes(), &report) != nil || !report.PreflightBlocked ||
				report.PolicyRootChecksComplete || len(report.PolicyRootInspections) != 1 ||
				report.PolicyRootInspections[0].Status != "RootAttestationFailed" ||
				len(report.PolicyRootInspections[0].Identities) != 0 {
				t.Fatalf("invalid binding emitted as success: %+v", report)
			}
		})
	}
}

func TestRootPreflightDoesNotInspectUnmatchedVolume(t *testing.T) {
	scope := scopeWithRoot(t)
	calls := 0
	var buf bytes.Buffer
	err := writeVolumeInventoryWithRootInspection(
		context.Background(), &buf,
		func(context.Context)([]volumediscovery.Snapshot,error) {
			return []volumediscovery.Snapshot{{
				GUID: inventoryDataGUID, Serial64: "15172277115761558408",
				FileSystem: "NTFS", Status: volumediscovery.Eligible,
			}}, nil
		},
		func(context.Context, config.VolumeConfig, string) ([]policyassociation.RootBinding,error) {
			calls++
			return fixtureRootBindings(), nil
		}, time.Now, &scope, true,
	)
	if !errors.Is(err, ErrVolumePreflightMismatch) || calls != 0 {
		t.Fatalf("unmatched volume was inspected: error=%v, calls=%d", err,calls)
	}
	var report volumeInventoryReport
	if json.Unmarshal(buf.Bytes(), &report) != nil || !report.PreflightBlocked ||
		report.PolicyRootChecksComplete || len(report.PolicyRootInspections) != 1 ||
		report.PolicyRootInspections[0].Status != "VolumeNotMatched" {
		t.Fatalf("unmatched volume was concealed: %+v", report)
	}
}

func TestRootPreflightZeroGovernedPolicies(t *testing.T) {
	scope := validInventoryScope(t)
	var buf bytes.Buffer
	calls := 0
	err := writeVolumeInventoryWithRootInspection(
		context.Background(), &buf, healthyInventory,
		func(context.Context,config.VolumeConfig,string)([]policyassociation.RootBinding,error) {
			calls++
			return []policyassociation.RootBinding{},nil
		}, time.Now,&scope,true,
	)
	var report volumeInventoryReport
	if err != nil || json.Unmarshal(buf.Bytes(), &report) != nil || calls != 1 ||
		!report.PolicyRootChecksComplete || report.PreflightBlocked ||
		len(report.PolicyRootInspections) != 1 ||
		report.PolicyRootInspections[0].Status != "NoPolicies" {
		t.Fatalf("zero-root volume was not supported: %+v %v", report,err)
	}
}

func TestRootPreflightIndependentEnrolledVolumeResults(t *testing.T) {
	raw := `version_id: 2.0
volume.a.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.a.serial = 15172277115761558407
volume.b.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.b.serial = 14888954410052949637
policy.one.volume = a
policy.one.root = \Finance
policy.one.depth = metadata
policy.two.volume = b
policy.two.root = \Software
policy.two.depth = security
`
	scope,err := config.ParseVolumeV2(strings.NewReader(raw))
	if err != nil { t.Fatal(err) }
	matches := []volumediscovery.Match{
		{EnrollmentID:"a",GUID:scope.Volumes[0].GUID,Status:volumediscovery.IdentityMatched},
		{EnrollmentID:"b",GUID:scope.Volumes[1].GUID,Status:volumediscovery.IdentityMatched},
	}
	calls:=[]string{}
	observations,ok,err:=inspectRequestedPolicyRoots(
		context.Background(),scope,matches,
		func(_ context.Context,_ config.VolumeConfig,id string)([]policyassociation.RootBinding,error){
			calls=append(calls,id)
			if id=="a" {return nil, errors.New("offline root")}
			return []policyassociation.RootBinding{{PolicyID:"two",VolumeID:"b",RootID:fixtureRootID()}},nil
		},
	)
	if err!=nil || ok || len(observations)!=2 || len(calls)!=2 ||
		observations[0].Status!="RootAttestationFailed" ||
		observations[1].Status!="IdentitiesObserved" ||
		len(observations[0].Identities)!=0 || len(observations[1].Identities)!=1 {
		t.Fatalf("one failed volume aborted or authorized another: %+v %v calls=%v",observations,err,calls)
	}
}

func TestRootInspectionRequiresExplicitInputsAndNoMutationFallback(t *testing.T) {
	calls := 0
	inspect:=func(context.Context,config.VolumeConfig,string)([]policyassociation.RootBinding,error){
		calls++; return nil,nil
	}
	for _,tc := range []struct{name string; requested *config.VolumeConfig; observer rootAttestor; enabled bool}{
		{name:"missing scope",observer:inspect,enabled:true},
		{name:"missing observer",requested:ptrInventoryScope(t),enabled:true},
	}{
		t.Run(tc.name,func(t *testing.T){
			var buf bytes.Buffer
			err:=writeVolumeInventoryWithRootInspection(
				context.Background(),&buf,
				func(context.Context)([]volumediscovery.Snapshot,error){
					t.Fatal("invalid root input started native volume discovery")
					return nil,nil
				},
				tc.observer,time.Now,tc.requested,tc.enabled,
			)
			if err==nil||buf.Len()!=0 { t.Fatalf("invalid inspection accepted: %v %q",err,buf.String()) }
		})
	}
	if calls!=0 { t.Fatalf("invalid inspection invoked privileged observer: %d",calls) }
}

func ptrInventoryScope(t *testing.T) *config.VolumeConfig {
	t.Helper()
	v:=validInventoryScope(t)
	return &v
}
