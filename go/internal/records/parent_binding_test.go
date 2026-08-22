// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

func TestValidateParentObjectBindingPresent(t *testing.T) {
	binding := ParentObjectBindingFor(NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "42",
		SequenceNumber:      "7",
	})
	if err := ValidateParentObjectBinding(binding); err != nil {
		t.Fatal(err)
	}
}

func TestValidateParentObjectBindingGovernedRootRejectsIdentity(t *testing.T) {
	identity := NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "42",
		SequenceNumber:      "7",
	}
	binding := ParentObjectBinding{
		State:          ParentBindingGovernedRoot,
		ObjectIdentity: &identity,
	}
	if err := ValidateParentObjectBinding(binding); err == nil {
		t.Fatal("expected governed-root parent binding to reject object identity")
	}
}

func TestValidateParentObjectBindingErrorRequiresReason(t *testing.T) {
	binding := ParentObjectBinding{State: ParentBindingError}
	if err := ValidateParentObjectBinding(binding); err == nil {
		t.Fatal("expected error parent binding to require reason code")
	}
}
