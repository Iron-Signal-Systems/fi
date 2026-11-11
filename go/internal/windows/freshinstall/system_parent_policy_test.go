// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"strings"
	"testing"
)

func testSystemEvidence() SystemParentEvidence {
	var root,programData,windowsID [16]byte
	root[0],programData[0],windowsID[0]=1,2,3
	return SystemParentEvidence{
		KnownProgramData: `C:\ProgramData`,
		SystemWindows: `C:\Windows`,
		RootPath: `C:\`,
		RootID:SystemDirectoryID{VolumeSerial:1234567890123,FileID:root},
		ProgramDataID:SystemDirectoryID{VolumeSerial:1234567890123,FileID:programData},
		WindowsID:SystemDirectoryID{VolumeSerial:1234567890123,FileID:windowsID},
	}
}

func TestSystemProgramDataEvidenceRequiresDistinctNativeObjects(t *testing.T) {
	good:=testSystemEvidence()
	if err:=AssessSystemParentEvidence(good);err!=nil{t.Fatal(err)}
	// Case differences are normal Windows path presentation, but they
	// must never be resolved by environment or relative aliases.
	good.KnownProgramData=`c:\PROGRAMDATA`
	good.SystemWindows=`c:\WINDOWS`
	if err:=AssessSystemParentEvidence(good);err!=nil{t.Fatalf("case-only change refused: %v",err)}
}

func TestSystemProgramDataEvidenceFailsClosed(t *testing.T) {
	cases:=[]struct{
		name string
		mutate func(*SystemParentEvidence)
	}{
		{"UNC",func(x *SystemParentEvidence){x.KnownProgramData=`\\server\share\ProgramData`}},
		{"device alias",func(x *SystemParentEvidence){x.KnownProgramData=`\\?\C:\ProgramData`}},
		{"relative",func(x *SystemParentEvidence){x.KnownProgramData=`ProgramData`}},
		{"drive mismatch",func(x *SystemParentEvidence){x.KnownProgramData=`D:\ProgramData`}},
		{"moved subtree",func(x *SystemParentEvidence){x.KnownProgramData=`C:\Users\Public\ProgramData`}},
		{"wrong basename",func(x *SystemParentEvidence){x.KnownProgramData=`C:\NotProgramData`}},
		{"trailing separator",func(x *SystemParentEvidence){x.KnownProgramData=`C:\ProgramData\`}},
		{"parent traversal",func(x *SystemParentEvidence){x.KnownProgramData=`C:\Temp\..\ProgramData`}},
		{"alternate stream",func(x *SystemParentEvidence){x.KnownProgramData=`C:\ProgramData:stream`}},
		{"windows under nested path",func(x *SystemParentEvidence){x.SystemWindows=`C:\Windows\Nested`}},
		{"windows same as programdata",func(x *SystemParentEvidence){x.SystemWindows=x.KnownProgramData}},
		{"root not absolute",func(x *SystemParentEvidence){x.RootPath=`C:`}},
		{"root wrong drive",func(x *SystemParentEvidence){x.RootPath=`D:\`}},
		{"root zero serial",func(x *SystemParentEvidence){x.RootID.VolumeSerial=0}},
		{"programdata cross volume",func(x *SystemParentEvidence){x.ProgramDataID.VolumeSerial++}},
		{"windows cross volume",func(x *SystemParentEvidence){x.WindowsID.VolumeSerial++}},
		{"zero file id",func(x *SystemParentEvidence){x.ProgramDataID.FileID=[16]byte{}}},
		{"same file id root",func(x *SystemParentEvidence){x.ProgramDataID.FileID=x.RootID.FileID}},
		{"same file id windows",func(x *SystemParentEvidence){x.WindowsID.FileID=x.ProgramDataID.FileID}},
		{"oversized path",func(x *SystemParentEvidence){x.KnownProgramData+=strings.Repeat("X",1025)}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			e:=testSystemEvidence();tc.mutate(&e)
			if err:=AssessSystemParentEvidence(e);!errors.Is(err,ErrUnattestedSystemParent){
				t.Fatalf("system parent unsafe evidence accepted: %+v; error=%v",e,err)
			}
		})
	}
}
