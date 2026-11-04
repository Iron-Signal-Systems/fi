//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import "testing"

func TestValidatedOptfieldK32Profile(t *testing.T) {
	profile, err := selectValidatedK32(nil, true, true, true, false, false, false, true, 3, 0)
	if err != nil { t.Fatal(err) }
	if profile.Name != "optfield-k32-w128-p3-f3" ||
		profile.WindowProfile != "W128" ||
		profile.ProcessingChunkRecords != 32768 ||
		profile.SecurityProfile != "P3" ||
		profile.FileProfile != "F3" {
		t.Fatalf("incorrect K32 profile: %+v", profile)
	}
	_,err = selectValidatedK32(map[string]string{
		"window-profile":"W128", "processing-chunk-records":"32768",
		"security-profile":"P3", "file-profile":"F3",
	}, true, true, true, false, false, false, true, 3, 0)
	if err != nil {t.Fatalf("matching explicit values rejected: %v", err)}
}

func TestValidatedOptfieldK32RejectsUnsafeModes(t *testing.T) {
	cases := []struct{
		name string
		explicit map[string]string
		partitions, writes, continuous, indexed, stream, preflight, cache bool
		start, max int
	}{
		{name:"partition not installed", writes:true, continuous:true, cache:true, start:3},
		{name:"private writes not enabled", partitions:true, continuous:true, cache:true, start:3},
		{name:"not continuous", partitions:true, writes:true, cache:true, start:3},
		{name:"unverified cache", partitions:true, writes:true, continuous:true, start:3},
		{name:"no completed seed", partitions:true, writes:true, continuous:true, cache:true},
		{name:"incorrect max windows", partitions:true, writes:true, continuous:true, cache:true, start:3, max:1},
		{name:"indexed mode", partitions:true, writes:true, continuous:true, indexed:true, cache:true, start:3},
		{name:"stream-loader mode", partitions:true, writes:true, continuous:true, stream:true, cache:true, start:3},
		{name:"preflight mode", partitions:true, writes:true, continuous:true, preflight:true, cache:true, start:3},
		{name:"W64 instead of W128", partitions:true, writes:true, continuous:true, cache:true, start:3, explicit:map[string]string{"window-profile":"W64"}},
		{name:"K64 instead of K32", partitions:true, writes:true, continuous:true, cache:true, start:3, explicit:map[string]string{"processing-chunk-records":"65536"}},
		{name:"P1 instead of P3", partitions:true, writes:true, continuous:true, cache:true, start:3, explicit:map[string]string{"security-profile":"P1"}},
		{name:"F1 instead of F3", partitions:true, writes:true, continuous:true, cache:true, start:3, explicit:map[string]string{"file-profile":"F1"}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			_,err := selectValidatedK32(tc.explicit,tc.partitions,tc.writes,tc.continuous,tc.indexed,tc.stream,tc.preflight,tc.cache,tc.start,tc.max)
			if err==nil {t.Fatal("unsafe profile was accepted")}
		})
	}
}
