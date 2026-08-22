// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// ParentBindingState describes FI's knowledge of the directory parent for the
// observed pathname binding. It is a property of the observed path binding, not
// an assertion that an NTFS object can have only one parent; hard-linked files
// can have multiple path bindings in different directories.
type ParentBindingState string

const (
	ParentBindingError        ParentBindingState = "Error"
	ParentBindingGovernedRoot ParentBindingState = "GovernedRoot"
	ParentBindingPresent      ParentBindingState = "Present"
)

// ParentObjectBinding records the NTFS object identity of the directory that
// contained the observed pathname at collection time.
//
// GovernedRoot means the observed object is the governed-root object itself, so
// FI intentionally does not record a parent outside the governed scope.
// Present means ObjectIdentity identifies the observed path's parent directory.
// Error means FI could not prove the parent binding; ReasonCode explains why.
type ParentObjectBinding struct {
	State          ParentBindingState  `json:"state"`
	ObjectIdentity *NTFSObjectIdentity `json:"object_identity,omitempty"`
	ReasonCode     string              `json:"reason_code,omitempty"`
}

// ParentObjectBindingFor creates a successful parent binding while keeping the
// pointer ownership local to the returned record.
func ParentObjectBindingFor(identity NTFSObjectIdentity) ParentObjectBinding {
	copy := identity
	return ParentObjectBinding{
		State:          ParentBindingPresent,
		ObjectIdentity: &copy,
	}
}

// ParentObjectBindingError creates an explicit non-fatal parent-binding failure.
func ParentObjectBindingError(reasonCode string) ParentObjectBinding {
	return ParentObjectBinding{
		State:      ParentBindingError,
		ReasonCode: reasonCode,
	}
}

// ValidateParentObjectBinding validates the shared parent-binding record.
func ValidateParentObjectBinding(binding ParentObjectBinding) error {
	switch binding.State {
	case ParentBindingGovernedRoot:
		if binding.ObjectIdentity != nil || binding.ReasonCode != "" {
			return invalid("Conflict", "parent_binding")
		}
		return nil

	case ParentBindingPresent:
		if binding.ObjectIdentity == nil {
			return invalid("Required", "parent_binding.object_identity")
		}
		if binding.ReasonCode != "" {
			return invalid("Conflict", "parent_binding.reason_code")
		}
		return ValidateNTFSObjectIdentity(*binding.ObjectIdentity)

	case ParentBindingError:
		if binding.ObjectIdentity != nil {
			return invalid("Conflict", "parent_binding.object_identity")
		}
		if binding.ReasonCode == "" {
			return invalid("Required", "parent_binding.reason_code")
		}
		return nil

	default:
		return invalid("UnsupportedValue", "parent_binding.state")
	}
}
