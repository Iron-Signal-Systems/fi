// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

func TestValidateProcessIdentityObservation(t *testing.T) {
	observation := ProcessIdentityObservation{
		ObservedAt:       "2026-08-22T09:00:00.000000000Z",
		CollectionMethod: ProcessIdentityCollectionMethod,
		Computer:         ComputerIdentity{NetBIOSName: "ISS-FS-01"},
		Token: ProcessTokenObservation{
			User:              TokenPrincipalObservation{SID: "S-1-5-18"},
			TokenTypeRaw:      "1",
			TokenTypeName:     "Primary",
			ElevationTypeRaw:  "1",
			ElevationTypeName: "Default",
			Groups: []TokenGroupObservation{{
				Index:         "0",
				Principal:     TokenPrincipalObservation{SID: "S-1-5-32-544"},
				AttributesRaw: "7",
			}},
			Privileges: []TokenPrivilegeObservation{{
				Index:         "0",
				LUIDLow:       "20",
				LUIDHigh:      "0",
				AttributesRaw: "3",
			}},
		},
	}
	if err := ValidateProcessIdentityObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProcessIdentityObservationRejectsBadGroupIndex(t *testing.T) {
	observation := ProcessIdentityObservation{
		ObservedAt:       "2026-08-22T09:00:00.000000000Z",
		CollectionMethod: ProcessIdentityCollectionMethod,
		Computer:         ComputerIdentity{NetBIOSName: "ISS-FS-01"},
		Token: ProcessTokenObservation{
			User:              TokenPrincipalObservation{SID: "S-1-5-18"},
			TokenTypeRaw:      "1",
			TokenTypeName:     "Primary",
			ElevationTypeRaw:  "1",
			ElevationTypeName: "Default",
			Groups: []TokenGroupObservation{{
				Index:         "9",
				Principal:     TokenPrincipalObservation{SID: "S-1-5-32-544"},
				AttributesRaw: "7",
			}},
		},
	}
	if err := ValidateProcessIdentityObservation(observation); err == nil {
		t.Fatal("expected validation error")
	}
}
