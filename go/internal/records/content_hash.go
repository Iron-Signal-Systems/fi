// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"fmt"
	"strings"
)

// ContentHashState records whether FI collected hashes of the base file's
// unnamed/default $DATA stream. Named ADS content is not hashed by this
// capability.
type ContentHashState string

const (
	ContentHashError         ContentHashState = "Error"
	ContentHashNotApplicable ContentHashState = "NotApplicable"
	ContentHashPresent       ContentHashState = "Present"
)

// ContentHashObservation records compatibility/content fingerprints from one
// local read of a regular file's unnamed/default $DATA stream.
//
// MD5 and SHA-1 are retained as compatibility fingerprints. SHA-256 is the
// primary modern content digest. None of these fields contain source file bytes.
type ContentHashObservation struct {
	State       ContentHashState `json:"state"`
	BytesHashed string           `json:"bytes_hashed,omitempty"`
	MD5         string           `json:"md5,omitempty"`
	SHA1        string           `json:"sha1,omitempty"`
	SHA256      string           `json:"sha256,omitempty"`
	ReasonCode  string           `json:"reason_code,omitempty"`
	Detail      string           `json:"detail,omitempty"`
}

func ValidateContentHashObservation(value ContentHashObservation) error {
	switch value.State {
	case ContentHashNotApplicable:
		if value.BytesHashed != "" || value.MD5 != "" || value.SHA1 != "" ||
			value.SHA256 != "" || value.ReasonCode != "" || value.Detail != "" {
			return invalid("Conflict", "content_hashes")
		}
		return nil

	case ContentHashError:
		if err := require(value.ReasonCode, "content_hashes.reason_code"); err != nil {
			return err
		}
		if value.BytesHashed != "" || value.MD5 != "" || value.SHA1 != "" || value.SHA256 != "" {
			return invalid("Conflict", "content_hashes")
		}
		return nil

	case ContentHashPresent:
		if value.ReasonCode != "" || value.Detail != "" {
			return invalid("Conflict", "content_hashes")
		}
		if _, err := canonicalUnsigned(value.BytesHashed); err != nil {
			return invalid("InvalidDecimal", "content_hashes.bytes_hashed")
		}
		if err := validateLowerHexHash(value.MD5, 32, "content_hashes.md5"); err != nil {
			return err
		}
		if err := validateLowerHexHash(value.SHA1, 40, "content_hashes.sha1"); err != nil {
			return err
		}
		return validateLowerHexHash(value.SHA256, 64, "content_hashes.sha256")

	default:
		return invalid("UnsupportedValue", "content_hashes.state")
	}
}

func validateLowerHexHash(value string, length int, field string) error {
	if len(value) != length || value != strings.ToLower(value) {
		return invalid("InvalidHash", field)
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return invalid("InvalidHash", field)
		}
	}
	if value == "" {
		return fmt.Errorf("empty hash: %s", field)
	}
	return nil
}
