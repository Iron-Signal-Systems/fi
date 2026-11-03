// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use governed by repository LICENSE.
package recordingest

import (
	"errors"
	"fmt"
	"sort"
)

// Canonical and private schemas currently contain exactly these 49 historical
// relational tables. An unexpected DDL change MUST fail promotion preflight.
// A missing or extra table never becomes an implicit silent data-loss path.
var bootstrapSoRTables = []string{
	"recorded_generation", "source_batch", "source_record", "ingest_journal",
	"ntfs_volume", "ntfs_object", "governed_root", "file_observation",
	"file_metadata_observation", "content_hash_observation", "content_prefix_observation",
	"reparse_observation", "stream_inventory", "stream_observation",
	"security_observation", "security_ace", "sacl_observation", "sacl_ace",
	"observation_warning", "collector_identity", "collector_token_group",
	"collector_token_privilege", "smb_share_snapshot", "smb_share", "smb_share_ace",
	"local_principal_snapshot", "local_user", "local_group", "local_group_membership",
	"directory_principal_snapshot", "directory_requested_sid", "directory_principal",
	"directory_principal_class", "directory_membership", "directory_not_found_sid",
	"windows_security_coverage", "windows_security_audit_policy",
	"windows_security_root_coverage", "windows_security_event",
	"windows_security_event_scope", "windows_security_event_field",
	"windows_security_continuity_gap", "ntfs_collection_error",
	"supporting_source_collection_error", "usn_read_boundary",
	"usn_object_observation", "usn_object_change", "usn_object_change_reason",
	"usn_continuity_gap",
}

var bootstrapIdentityColumns = map[string]string{
	"recorded_generation": "recorded_generation_id",
	"source_batch": "source_batch_id",
	"source_record": "source_record_id",
	"ntfs_volume": "ntfs_volume_id",
	"ntfs_object": "ntfs_object_id",
	"governed_root": "governed_root_id",
}

// bootstrapSoRPromotionOrder returns a deterministic FK parent-first order.
// These dependencies come from the actual PostgreSQL catalog at invocation,
// not from guessed table names or hardcoded migration ordering. The one
// canonical ingest_journal table is never copied from private recovery.
func bootstrapSoRPromotionOrder(tables []string, foreignKeys [][2]string) ([]string,error) {
	if len(tables)!=len(bootstrapSoRTables) {return nil,fmt.Errorf("FI SoR bootstrap: schema table count %d != %d",len(tables),len(bootstrapSoRTables))}
	expected:=make(map[string]bool,len(bootstrapSoRTables))
	for _,n:=range bootstrapSoRTables {
		if expected[n]{return nil,errors.New("FI SoR bootstrap: duplicate supported table")}
		expected[n]=true
	}
	remaining:=make(map[string]bool,len(tables))
	for _,n:=range tables {
		if !expected[n] || remaining[n] {return nil,fmt.Errorf("FI SoR bootstrap: unapproved or repeated table %q",n)}
		remaining[n]=true
	}
	deps:=make(map[string]map[string]bool,len(tables))
	for _,pair:=range foreignKeys {
		child,parent:=pair[0],pair[1]
		if !expected[child] || !expected[parent] {return nil,fmt.Errorf("FI SoR bootstrap: unapproved FK %q -> %q",child,parent)}
		if child==parent {return nil,fmt.Errorf("FI SoR bootstrap: self FK requires separate acceptance: %s",child)}
		if deps[child]==nil {deps[child]=make(map[string]bool)}
		deps[child][parent]=true
	}
	delete(remaining,"ingest_journal")
	out:=make([]string,0,len(remaining))
	for len(remaining)>0 {
		var eligible []string
		for child:=range remaining {
			ready:=true
			for parent:=range deps[child] {
				if remaining[parent] {ready=false;break}
			}
			if ready {eligible=append(eligible,child)}
		}
		if len(eligible)==0 {return nil,errors.New("FI SoR bootstrap: cyclic FK dependency graph")}
		sort.Strings(eligible)
		for _,n:=range eligible {out=append(out,n);delete(remaining,n)}
	}
	if len(out)!=48 || out[0]!="recorded_generation" {
		return nil,errors.New("FI SoR bootstrap: invalid parent-first 48-table plan")
	}
	return out,nil
}
