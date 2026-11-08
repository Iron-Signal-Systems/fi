// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumegrant verifies a durable signed *installed scope declaration*.
//
// It deliberately does not load files, select trust roots, persist counters,
// grant Windows privileges, or start FICollector/FIUSNReader. In particular,
// a valid signature is insufficient unless an independently protected local
// commitment pins the exact signed grant bytes, generation and installation.
// This package contains no production signer and cannot install itself.
package volumegrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const (
	Version = "fi-windows-installed-volume-grant/1"
	Mode = "VolumeFirst"
	maxGrantBytes = 8 * 1024
	maxOperationalConfigBytes = 1024 * 1024 // bounded until complete v2 schema exists
	maxFutureSkew = 2 * time.Minute
)

var (
	ErrInvalidGrant = errors.New("FI installed volume grant is malformed")
	ErrUntrustedGrant = errors.New("FI installed volume grant lacks trusted authority")
	ErrGrantDrift = errors.New("FI installed volume grant does not match committed state")
)

var signatureDomain = []byte("FI-WINDOWS-INSTALLED-VOLUME-GRANT-v1\x00")

// Manifest records the *installed* volume-scope commitment, not an
// administrator's short-lived transaction request.
//
// OperationalConfigSHA256 must be the hash of the future complete installed
// v2 operational configuration, not merely the scope-only v2 declaration.
// ApprovalReceiptSHA256 provides a forensic reference to a separately verified
// installer approval; its presence does not prove that verification occurred.
// All identifiers and hashes must be canonical lower-case strings.
type Manifest struct {
	Version string `json:"version"`
	Mode string `json:"mode"`
	MachineSID string `json:"machine_sid"`
	InstallationID string `json:"installation_id"`
	Generation uint64 `json:"generation"`
	CommitID string `json:"commit_id"`
	ScopeConfigSHA256 string `json:"scope_config_sha256"`
	OperationalConfigSHA256 string `json:"operational_config_sha256"`
	ApprovalReceiptSHA256 string `json:"approval_receipt_sha256"`
	PreviousGrantSHA256 string `json:"previous_grant_sha256,omitempty"`
	CommittedAtUTC string `json:"committed_at_utc"`
}

type SignedGrant struct {
	Manifest Manifest `json:"manifest"`
	SignatureBase64 string `json:"signature_base64"`
}

// TrustedState is mandatory independently protected installer state. The
// caller MUST NOT construct these values from the grant being checked.
//
// GrantSHA256 is a pinned hash of the entire canonical signed-grant envelope;
// this closes the gap where an older correctly signed grant could otherwise be
// accepted after a local rollback. Generation/PreviousGrantSHA256 are an
// additional explicit anti-replay chain, not alternatives to the pinned hash.
// Native code must prove ACL/provenance/host identity and ensure atomic durable
// updates; this package makes no such claim.
type TrustedState struct {
	MachineSID string
	InstallationID string
	Generation uint64
	GrantSHA256 string
	PreviousGrantSHA256 string
	ScopeConfigSHA256 string
	OperationalConfigSHA256 string
	TrustedPublicKey *ecdsa.PublicKey
	Now time.Time
}

// Verify validates the signed durable declaration against independently
// trusted state, exact current normalized scope, and the actual installed
// operational config bytes (not merely a caller-asserted hash).
// It returns only an error, never a capability or authorization token.
// A future service must additionally validate native volume identity,
// authorized object policies and the installed *operational* configuration.
func Verify(encoded []byte, state TrustedState, scope config.VolumeConfig, installedOperationalConfig []byte) error {
	if len(encoded) == 0 || len(encoded) > maxGrantBytes {
		return fmt.Errorf("%w: signed envelope size outside limits", ErrInvalidGrant)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var grant SignedGrant
	if err := decoder.Decode(&grant); err != nil {
		return fmt.Errorf("%w: JSON: %v", ErrInvalidGrant, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: trailing or duplicate JSON data", ErrInvalidGrant)
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(canonical, encoded) {
		// This also denies duplicate keys, alternate key casing/order, extra
		// whitespace, and equivalent noncanonical JSON spellings.
		return fmt.Errorf("%w: noncanonical JSON envelope", ErrInvalidGrant)
	}
	if err := validateManifest(grant.Manifest); err != nil {
		return err
	}
	if err := validateTrust(state); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(grant.SignatureBase64)
	if err != nil || len(signature) < 8 || len(signature) > 80 ||
		base64.StdEncoding.EncodeToString(signature) != grant.SignatureBase64 {
		return fmt.Errorf("%w: invalid DER signature encoding", ErrInvalidGrant)
	}
	packed, err := signatureMessage(grant.Manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(packed)
	if !ecdsa.VerifyASN1(state.TrustedPublicKey, digest[:], signature) {
		return ErrUntrustedGrant
	}

	manifest := grant.Manifest
	// An independently protected exact-envelope digest is required even
	// when this manifest was signed by a still-trusted issuer. Otherwise a
	// previously valid grant could be replayed after later policy changes.
	envelopeDigest := sha256.Sum256(encoded)
	if !hashEqual(state.GrantSHA256, hex.EncodeToString(envelopeDigest[:])) ||
		manifest.MachineSID != state.MachineSID ||
		manifest.InstallationID != state.InstallationID ||
		manifest.Generation != state.Generation ||
		!hashEqual(manifest.PreviousGrantSHA256, state.PreviousGrantSHA256) ||
		!hashEqual(manifest.ScopeConfigSHA256, state.ScopeConfigSHA256) ||
		!hashEqual(manifest.OperationalConfigSHA256, state.OperationalConfigSHA256) {
		return ErrGrantDrift
	}

	normalized, err := config.CanonicalVolumeV2(scope)
	if err != nil {
		return fmt.Errorf("%w: installed volume configuration: %v", ErrGrantDrift, err)
	}
	observed := sha256.Sum256(normalized)
	if !hashEqual(manifest.ScopeConfigSHA256, hex.EncodeToString(observed[:])) {
		return ErrGrantDrift
	}
	// Compare against the ACTUAL installed operational bytes as well as the
	// independently protected expected digest. Comparing only two hashes
	// supplied by the caller would not detect edited operational files.
	// Future source integration must separately parse/validate the complete
	// v2 operational schema; byte equality is necessary, not sufficient.
	if len(installedOperationalConfig) == 0 ||
		len(installedOperationalConfig) > maxOperationalConfigBytes {
		return fmt.Errorf("%w: operational configuration is empty or exceeds size limit", ErrGrantDrift)
	}
	operationalDigest := sha256.Sum256(installedOperationalConfig)
	if !hashEqual(manifest.OperationalConfigSHA256, hex.EncodeToString(operationalDigest[:])) {
		return ErrGrantDrift
	}
	committed, _ := time.Parse(time.RFC3339Nano, manifest.CommittedAtUTC)
	if committed.After(state.Now.Add(maxFutureSkew)) {
		return ErrGrantDrift
	}
	return nil
}

// signatureMessage is kept unexported: installation signing, issuer trust and
// operator consent are separate future Windows components. Tests may sign this
// payload with disposable, strictly in-memory test-only P-256 keys.
func signatureMessage(value Manifest) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: serialize manifest: %v", ErrInvalidGrant, err)
	}
	out := make([]byte, 0, len(signatureDomain)+len(payload))
	out = append(out, signatureDomain...)
	out = append(out, payload...)
	return out, nil
}

func validateManifest(m Manifest) error {
	if m.Version != Version || m.Mode != Mode ||
		!validSID(m.MachineSID) || !validInstallID(m.InstallationID) ||
		m.Generation == 0 || !validInstallID(m.CommitID) ||
		!validHash(m.ScopeConfigSHA256, false) ||
		!validHash(m.OperationalConfigSHA256, false) ||
		!validHash(m.ApprovalReceiptSHA256, false) ||
		!validHash(m.PreviousGrantSHA256, true) {
		return fmt.Errorf("%w: incorrect version, identity, generation or digest", ErrInvalidGrant)
	}
	if (m.Generation == 1) != (m.PreviousGrantSHA256 == "") {
		return fmt.Errorf("%w: grant predecessor must be absent only for generation 1", ErrInvalidGrant)
	}
	if !canonicalUTC(m.CommittedAtUTC) {
		return fmt.Errorf("%w: invalid committed UTC time", ErrInvalidGrant)
	}
	return nil
}

func validateTrust(s TrustedState) error {
	if !validSID(s.MachineSID) || !validInstallID(s.InstallationID) ||
		s.Generation == 0 || !validHash(s.GrantSHA256, false) ||
		!validHash(s.PreviousGrantSHA256, true) ||
		!validHash(s.ScopeConfigSHA256, false) ||
		!validHash(s.OperationalConfigSHA256, false) ||
		!validP256Key(s.TrustedPublicKey) || s.Now.IsZero() {
		return fmt.Errorf("%w: missing independent host, commit, signer or time authority", ErrUntrustedGrant)
	}
	if (s.Generation == 1) != (s.PreviousGrantSHA256 == "") {
		return fmt.Errorf("%w: invalid protected generation/previous-hash chain", ErrUntrustedGrant)
	}
	return nil
}

func validP256Key(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() &&
		key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

func validInstallID(value string) bool {
	if len(value) != 32 || value == strings.Repeat("0", 32) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == value
}

func validHash(value string, optional bool) bool {
	if optional && value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func hashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func canonicalUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC &&
		value == parsed.UTC().Format(time.RFC3339Nano)
}

// This validates only the canonical SID representation, not Windows identity.
// The caller must supply the actual host SID from native protected state.
func validSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return false
	}
	for index, part := range parts[2:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		bits := 32
		if index == 0 {
			bits = 48
		}
		if _, err := strconv.ParseUint(part, 10, bits); err != nil {
			return false
		}
	}
	return true
}
