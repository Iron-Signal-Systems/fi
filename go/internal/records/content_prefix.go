// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// ContentPrefixMaxBytes is the maximum number of leading source bytes FI
// preserves from a regular file's unnamed/default $DATA stream.
const ContentPrefixMaxBytes = 16

// ContentPrefixState records whether FI preserved the bounded leading-byte
// sample of the base file's unnamed/default $DATA stream.
type ContentPrefixState string

const (
	ContentPrefixError         ContentPrefixState = "Error"
	ContentPrefixNotApplicable ContentPrefixState = "NotApplicable"
	ContentPrefixPresent       ContentPrefixState = "Present"
)

// ContentPrefixObservation records the exact leading bytes FI observed from a
// regular file's unnamed/default $DATA stream during the same bounded local read
// used for content hashing.
//
// PrefixBase64URL is raw, unpadded Base64URL and therefore preserves the exact
// bytes without interpreting them as a file type. Phase 1 records only the
// source fact. Classification belongs to later enrichment.
type ContentPrefixObservation struct {
	State           ContentPrefixState `json:"state"`
	BytesObserved   string             `json:"bytes_observed,omitempty"`
	PrefixBase64URL string             `json:"prefix_base64url,omitempty"`
	ReasonCode      string             `json:"reason_code,omitempty"`
	Detail          string             `json:"detail,omitempty"`
}

// ValidateContentPrefixObservation validates the bounded source-byte sample.
func ValidateContentPrefixObservation(value ContentPrefixObservation) error {
	switch value.State {
	case ContentPrefixNotApplicable:
		if value.BytesObserved != "" || value.PrefixBase64URL != "" ||
			value.ReasonCode != "" || value.Detail != "" {
			return invalid("Conflict", "content_prefix")
		}
		return nil

	case ContentPrefixError:
		if err := require(value.ReasonCode, "content_prefix.reason_code"); err != nil {
			return err
		}
		if value.BytesObserved != "" || value.PrefixBase64URL != "" {
			return invalid("Conflict", "content_prefix")
		}
		return nil

	case ContentPrefixPresent:
		if value.ReasonCode != "" || value.Detail != "" {
			return invalid("Conflict", "content_prefix")
		}
		count, err := canonicalUnsigned(value.BytesObserved)
		if err != nil || count > ContentPrefixMaxBytes {
			return invalid("InvalidDecimal", "content_prefix.bytes_observed")
		}
		decoded, err := decodeBase64URL(value.PrefixBase64URL, "content_prefix.prefix_base64url")
		if err != nil {
			return err
		}
		if uint64(len(decoded)) != count {
			return invalid("Conflict", "content_prefix")
		}
		return nil

	default:
		return invalid("UnsupportedValue", "content_prefix.state")
	}
}
