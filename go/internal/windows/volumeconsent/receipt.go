// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumeconsent verifies short-lived cryptographic authorization for
// a proposed FI Windows volume-scope installer transaction. It does NOT issue
// trusted keys, collect an administrator's consent, install files, or grant a
// broker any privilege. Public trust keys and expected host/transaction state
// must be obtained from independently protected installer authority.
package volumeconsent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

const (
	ReceiptVersion = "fi-windows-volume-approval/1"
	ApprovedAction = "ApplyVolumeScope"
	maxReceiptSize = 8 * 1024
	maxApprovalAge = 15 * time.Minute
	maxClockSkew = 2 * time.Minute
)

var (
	ErrInvalidReceipt = errors.New("FI volume approval receipt is invalid")
	ErrUnauthorizedReceipt = errors.New("FI volume approval receipt is unauthorized")
	ErrStaleApproval = errors.New("FI volume approval receipt no longer matches current scope")
)

var domain = []byte("FI-WINDOWS-VOLUME-APPROVAL-v1\x00")

// Payload is the exact signed approval intent. MachineSID is supplied by
// native trusted Windows host state; InstallationID and Sequence must match
// independently protected install state, never the receipt's own assertions.
// ApproverSID is audit attribution, NOT proof of an authenticated admin token.
type Payload struct {
	Version string `json:"version"`
	Action string `json:"action"`
	MachineSID string `json:"machine_sid"`
	InstallationID string `json:"installation_id"`
	ApproverSID string `json:"approver_sid"`
	Sequence uint64 `json:"sequence"`
	PreviousConfigSHA256 string `json:"previous_config_sha256,omitempty"`
	RequestedConfigSHA256 string `json:"requested_config_sha256"`
	ReviewFingerprintSHA256 string `json:"review_fingerprint_sha256"`
	IssuedAtUTC string `json:"issued_at_utc"`
	ExpiresAtUTC string `json:"expires_at_utc"`
}

// Receipt uses strict, canonical JSON. ECDSA P-256 with SHA-256 is an offline signature over a
// domain-separated canonical payload, not over a free-form display string.
// No private keys, generated credentials, or self-described trust anchors
// reside in this envelope.
type Receipt struct {
	Payload Payload `json:"payload"`
	SignatureBase64 string `json:"signature_base64"`
}

// Expected is mandatory independently sourced trust context. A caller must
// not fill these from Receipt.Payload; doing so would defeat the host binding
// and sequence anti-replay checks. TrustedPublicKey must be pinned by a
// protected installer trust store whose provisioning is NOT yet implemented.
type Expected struct {
	MachineSID string
	InstallationID string
	Sequence uint64
	PreviousConfigSHA256 string
	TrustedPublicKey *ecdsa.PublicKey
	Now time.Time
}

// Verify requires a trusted signer, correct host/install/sequence binding,
// unexpired short-lived intent, and an unchanged, freshly rediscovered native
// volume review. A successful result is only a VERIFIED INSTALLER INTENT;
// it does not write an installed grant or enable privileged broker access.
func Verify(
	encoded []byte,
	expected Expected,
	existing *config.VolumeConfig,
	requested config.VolumeConfig,
	previousReview volumereview.Review,
	freshNative []volumediscovery.Snapshot,
) error {
	if len(encoded) == 0 || len(encoded) > maxReceiptSize {
		return fmt.Errorf("%w: size exceeds bounded envelope", ErrInvalidReceipt)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return fmt.Errorf("%w: parse: %v", ErrInvalidReceipt, err)
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON data", ErrInvalidReceipt)
	}
	// Canonical byte equality rejects duplicate JSON keys, unknown whitespace
	// encodings, alternate field order and aliases rather than accepting a
	// partially interpreted signed approval.
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return fmt.Errorf("%w: noncanonical JSON", ErrInvalidReceipt)
	}
	if err := validatePayload(receipt.Payload); err != nil {
		return err
	}
	if err := validateExpected(expected); err != nil {
		return err
	}
	rawSignature, err := base64.StdEncoding.Strict().DecodeString(receipt.SignatureBase64)
	if err != nil || len(rawSignature) == 0 || len(rawSignature) > 80 ||
		base64.StdEncoding.EncodeToString(rawSignature) != receipt.SignatureBase64 {
		return fmt.Errorf("%w: malformed ECDSA P-256 DER signature encoding", ErrInvalidReceipt)
	}
	signable, err := message(receipt.Payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(signable)
	if !ecdsa.VerifyASN1(expected.TrustedPublicKey, digest[:], rawSignature) {
		return ErrUnauthorizedReceipt
	}
	// Authenticate the payload first, then compare to independently observed
	// host/installer state. A valid receipt issued for another host or a prior
	// generation cannot be replayed on this installation.
	p := receipt.Payload
	if p.MachineSID != expected.MachineSID || p.InstallationID != expected.InstallationID ||
		p.Sequence != expected.Sequence ||
		!digestEqual(p.PreviousConfigSHA256, expected.PreviousConfigSHA256) {
		return ErrStaleApproval
	}
	issued, _ := time.Parse(time.RFC3339Nano, p.IssuedAtUTC)
	expires, _ := time.Parse(time.RFC3339Nano, p.ExpiresAtUTC)
	if issued.After(expected.Now.Add(maxClockSkew)) ||
		expires.Before(expected.Now) ||
		!expires.After(issued) || expires.Sub(issued) > maxApprovalAge {
		return ErrStaleApproval
	}
	if p.ReviewFingerprintSHA256 != previousReview.ReviewFingerprintSHA256 ||
		p.RequestedConfigSHA256 != previousReview.RequestedConfigSHA256 ||
		!digestEqual(p.PreviousConfigSHA256, previousReview.CurrentConfigSHA256) {
		return ErrStaleApproval
	}
	if err := volumereview.Revalidate(previousReview, existing, requested, freshNative); err != nil {
		return fmt.Errorf("%w: %v", ErrStaleApproval, err)
	}
	return nil
}

// Test fixtures sign canonical receipts using test-only in-memory keys.
// Production signing must use a protected Windows CNG ECDSA P-256 signer and
// authenticated administrator consent. CNG's raw signature output must be
// converted into a strict ASN.1 DER ECDSA signature at the issuing boundary.
func message(payload Payload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode payload: %v", ErrInvalidReceipt, err)
	}
	result := make([]byte, 0, len(domain)+len(encoded))
	result = append(result, domain...)
	result = append(result, encoded...)
	return result, nil
}

func validatePayload(p Payload) error {
	if p.Version != ReceiptVersion || p.Action != ApprovedAction || p.Sequence == 0 ||
		!validSID(p.MachineSID) || !validSID(p.ApproverSID) || !validInstallationID(p.InstallationID) ||
		!validDigest(p.RequestedConfigSHA256, false) ||
		!validDigest(p.ReviewFingerprintSHA256, false) ||
		!validDigest(p.PreviousConfigSHA256, true) {
		return fmt.Errorf("%w: invalid version, action, scope or principal fields", ErrInvalidReceipt)
	}
	issued, err := time.Parse(time.RFC3339Nano, p.IssuedAtUTC)
	if err != nil || issued.Location() != time.UTC ||
		p.IssuedAtUTC != issued.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("%w: issued_at_utc must be canonical UTC", ErrInvalidReceipt)
	}
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAtUTC)
	if err != nil || expires.Location() != time.UTC ||
		p.ExpiresAtUTC != expires.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("%w: expires_at_utc must be canonical UTC", ErrInvalidReceipt)
	}
	if !expires.After(issued) || expires.Sub(issued) > maxApprovalAge {
		return fmt.Errorf("%w: approval lifetime is invalid", ErrInvalidReceipt)
	}
	return nil
}

func validateExpected(e Expected) error {
	if !validSID(e.MachineSID) || !validInstallationID(e.InstallationID) ||
		e.Sequence == 0 || !validDigest(e.PreviousConfigSHA256, true) ||
		!validTrustedP256Key(e.TrustedPublicKey) || e.Now.IsZero() {
		return fmt.Errorf("%w: trusted host, sequence, key, clock or baseline missing", ErrUnauthorizedReceipt)
	}
	return nil
}

// Reject nil, malformed and alternative-curve keys even when a caller
// mistakenly supplies an untrusted key from the receipt itself. Keys must
// originate in independently protected installer trust.
// CNGP256SignatureToDER converts Windows CNG's fixed-width P1363 ECDSA
// signature output (32-byte R || 32-byte S) into the canonical ASN.1 DER
// representation required by Receipt.SignatureBase64. It neither signs nor
// authorizes anything. The future native CNG signer must first authenticate
// operator consent and isolate the non-exportable private key.
func CNGP256SignatureToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("%w: CNG ECDSA P-256 signature must contain exactly 64 bytes", ErrInvalidReceipt)
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	order := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 ||
		r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return nil, fmt.Errorf("%w: CNG ECDSA P-256 signature scalar out of range", ErrInvalidReceipt)
	}
	der, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("%w: encode CNG ECDSA P-256 signature: %v", ErrInvalidReceipt, err)
	}
	return der, nil
}

func validTrustedP256Key(key *ecdsa.PublicKey) bool {
	return key != nil &&
		key.Curve == elliptic.P256() &&
		key.X != nil && key.Y != nil &&
		key.Curve.IsOnCurve(key.X, key.Y)
}

func validInstallationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id &&
		id != strings.Repeat("0", 32)
}

func validDigest(value string, optional bool) bool {
	if optional && value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func digestEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// A SID is canonical ASCII: S-1-<48-bit authority>-<one to 15 32-bit
// subauthorities>. This validates presentation only; the native installer
// must obtain and verify the actual Windows operator token and local host.
func validSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return false
	}
	for index, part := range parts[2:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		limit := 32
		if index == 0 {
			limit = 48
		}
		if _, err := strconv.ParseUint(part, 10, limit); err != nil {
			return false
		}
	}
	return true
}
