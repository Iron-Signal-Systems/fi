// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: one-pass decoding for the canonical collector Security envelope.
// The active ingestion path is unchanged until equivalence and speed are proven.
package recordingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5/pgtype"
)

// The canonical collector emits fields in spool.Record declaration order.
// Noncanonical signed JSON is still valid input for the established decoder;
// this candidate declines it rather than guessing where payload bytes end.
var (
	securityEnvelopePrefix = []byte(`{"version":"fi-spool-record/0.1","record_kind":"WindowsSecurityEvent","scope_id":`)
	securityWrittenAtKey = []byte(`,"written_at":`)
	securityPayloadKey = []byte(`,"payload":`)
)

type singlePassSecurityEnvelope struct {
	Version    string                                 `json:"version"`
	RecordKind string                                 `json:"record_kind"`
	ScopeID    string                                 `json:"scope_id"`
	WrittenAt  string                                 `json:"written_at"`
	Payload    records.WindowsSecurityEventObservation `json:"payload"`
}

// tryPrepareSinglePassSecurity returns selected=false for any noncanonical
// envelope, allowing the exact existing general-purpose decoder to handle it.
// All selected records are still decoded strictly, validated, and hashed from
// the identical LF-terminated source bytes. Payload is an immutable view of
// the owned source slice, not another heap copy.
func tryPrepareSinglePassSecurity(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
	var emptySource SourceRecord
	var emptySecurity securityBulkRecord
	if len(raw) < len(securityEnvelopePrefix)+len(securityPayloadKey)+2 ||
		!bytes.HasPrefix(raw, securityEnvelopePrefix) ||
		raw[len(raw)-1] != '\n' || raw[len(raw)-2] != '}' {
		return emptySource, emptySecurity, false, nil
	}
	body := raw[:len(raw)-1]
	if bytes.Contains(body, []byte{'\n'}) {
		return emptySource, emptySecurity, false, nil
	}
	// Only select the exact canonical layout. A repeated or reordered
	// member goes through the original strict decoder, preserving its
	// legacy JSON v1 acceptance/rejection and error behavior.
	written, payload, canonical := findCanonicalSecurityEnvelopeKeys(body)
	if !canonical ||
		written <= len(securityEnvelopePrefix) ||
		payload <= written+len(securityWrittenAtKey) {
		return emptySource, emptySecurity, false, nil
	}
	// The two intervening values must be exactly one JSON string each;
	// otherwise an inserted or reordered envelope member could be mistaken
	// for the canonical layout.
	scopeValue := body[len(securityEnvelopePrefix):written]
	writtenAtValue := body[written+len(securityWrittenAtKey):payload]
	if len(scopeValue) < 2 || scopeValue[0] != '"' || scopeValue[len(scopeValue)-1] != '"' ||
		!json.Valid(scopeValue) ||
		len(writtenAtValue) < 2 || writtenAtValue[0] != '"' || writtenAtValue[len(writtenAtValue)-1] != '"' ||
		!json.Valid(writtenAtValue) {
		return emptySource, emptySecurity, false, nil
	}
	rawPayload := body[payload+len(securityPayloadKey):len(body)-1]
	// Canonical Security spool payloads are JSON objects and the LAST
	// envelope member. Their exact byte span starts and ends with braces.
	// The existing strict decoder below validates all nested JSON once.
	// Unlike the old json.Valid check, this does not rescan the large payload.
	if len(rawPayload) < 2 || rawPayload[0] != '{' || rawPayload[len(rawPayload)-1] != '}' {
		return emptySource, emptySecurity, false, nil
	}

	var parsed singlePassSecurityEnvelope
	if err := decodeStrictPayload(json.RawMessage(body), &parsed); err != nil {
		// Preserve legacy selection for invalid payload syntax. This full
		// payload check is paid only on a strict decoder failure, never for
		// an authenticated canonical Security event.
		if !json.Valid(rawPayload) {
			return emptySource, emptySecurity, false, nil
		}
		return emptySource, emptySecurity, true, fmt.Errorf("decode FI ingest source record: %w", err)
	}
	if parsed.Version != SpoolRecordVersion || parsed.RecordKind != "WindowsSecurityEvent" {
		return emptySource, emptySecurity, true, errors.New("FI single-pass Security envelope identity changed")
	}
	if parsed.ScopeID == "" || parsed.WrittenAt == "" {
		return emptySource, emptySecurity, true, errors.New("FI ingest source record scope ID and written_at are required")
	}
	writtenAt, err := time.Parse(time.RFC3339Nano, parsed.WrittenAt)
	if err != nil {
		return emptySource, emptySecurity, true, fmt.Errorf("parse FI ingest source record written_at: %w", err)
	}
	value := parsed.Payload
	if err := records.ValidateWindowsSecurityEventObservation(value); err != nil {
		return emptySource, emptySecurity, true, projectionValidationError("WindowsSecurityEvent", err)
	}
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_event.observed_at")
	if err != nil {
		return emptySource, emptySecurity, true, err
	}
	timeCreated, err := parseRFC3339(value.TimeCreated, "windows_security_event.time_created")
	if err != nil {
		return emptySource, emptySecurity, true, err
	}
	eventID, err := parseUint(value.EventID, 63, "windows_security_event.event_id")
	if err != nil {
		return emptySource, emptySecurity, true, err
	}
	bigEventRecordID, ok := new(big.Int).SetString(value.EventRecordID, 10)
	if !ok || bigEventRecordID.Sign() < 0 {
		return emptySource, emptySecurity, true, errors.New("FI Windows Security event record ID is not an unsigned decimal")
	}
	digest := sha256.Sum256(raw)
	source := SourceRecord{
		Record: spool.Record{
			Version: parsed.Version, RecordKind: parsed.RecordKind, ScopeID: parsed.ScopeID,
			WrittenAt: parsed.WrittenAt, Payload: json.RawMessage(rawPayload),
		},
		RawRecordBytes: raw, RecordBytes: len(raw),
		RecordSHA256: hex.EncodeToString(digest[:]), RecordDigest: digest,
		WrittenAtUTC: writtenAt.UTC(),
	}
	security := securityBulkRecord{
		prepared: source, digest: source.RecordDigest[:], value: value,
		observedAt: observedAt, timeCreated: timeCreated, eventID: int64(eventID),
		eventRecordID: pgtype.Numeric{Int: bigEventRecordID, Exp: 0, Valid: true},
	}
	return source, security, true, nil
}


// findCanonicalSecurityEnvelopeKeys locates the two exact outer-envelope
// markers in one pass over commas. The collector emits canonical keys with
// no extra spaces, casing changes, or JSON escape sequences. If a signed
// record instead contains another plausible envelope member after payload,
// decline the fast path so the general strict decoder owns it.
//
// We do not validate or decode JSON here. The strict JSONv2 decoder above is
// the sole full-payload validation. This scanner already replaces the old
// two Index + two Count traversals, so its suffix checks require NO additional
// full record pass.
func findCanonicalSecurityEnvelopeKeys(body []byte) (written, payload int, canonical bool) {
	written, payload = -1, -1
	for offset := 0; offset < len(body); {
		rel := bytes.IndexByte(body[offset:], ',')
		if rel < 0 {
			break
		}
		offset += rel
		if bytes.HasPrefix(body[offset:], securityWrittenAtKey) {
			if written >= 0 {
				return -1, -1, false
			}
			written = offset
		}
		if bytes.HasPrefix(body[offset:], securityPayloadKey) {
			if payload >= 0 {
				return -1, -1, false
			}
			payload = offset
		} else if payload >= 0 {
			// A second envelope member can otherwise be case-folded by v1
			// JSON or use escaped key characters. It may even have a JSON
			// object value, making a suffix-brace check insufficient.
			//
			// This check examines only key-shaped commas as the existing
			// scan passes them, and conservatively falls back for unusual
			// keys rather than emitting an invalid raw payload slice.
			next := offset + 1
			for next < len(body) && (body[next] == ' ' || body[next] == '\t') {
				next++
			}
			if next < len(body) && body[next] == '"' {
				if next != offset+1 {
					return -1, -1, false
				}
				key := body[next+1:]
				for i := 0; i < len(key) && i < 40; i++ {
					if key[i] == '\\' {
						return -1, -1, false
					}
					if key[i] == '"' {
						// Recognized envelope fields following payload
						// are never canonical. Match only a short key.
						switch {
						case bytes.EqualFold(key[:i], []byte("payload")),
							bytes.EqualFold(key[:i], []byte("version")),
							bytes.EqualFold(key[:i], []byte("record_kind")),
							bytes.EqualFold(key[:i], []byte("scope_id")),
							bytes.EqualFold(key[:i], []byte("written_at")):
							return -1, -1, false
						}
						break
					}
				}
			}
		}
		offset++
	}
	return written, payload, written >= 0 && payload >= 0
}

// findSinglePassSecurityEnvelopeKeys preserves the historical strict-equivalent
// marker scan used by the signed source acceptance tests and the established
// legacy/canonical-selection contract. The JSON-once candidate uses the
// conservative canonical variant but keeps this reference implementation.
func findSinglePassSecurityEnvelopeKeys(body []byte) (writtenAt, payload int, unique bool) {
	writtenAt, payload = -1, -1
	for offset := 0; offset < len(body); {
		comma := bytes.IndexByte(body[offset:], ',')
		if comma < 0 { break }
		offset += comma
		if bytes.HasPrefix(body[offset:], securityWrittenAtKey) {
			if writtenAt >= 0 { return -1, -1, false }
			writtenAt = offset
		}
		if bytes.HasPrefix(body[offset:], securityPayloadKey) {
			if payload >= 0 { return -1, -1, false }
			payload = offset
		}
		offset++
	}
	return writtenAt, payload, writtenAt >= 0 && payload >= 0
}

// usePrivateSinglePassSecurity restricts this CPU optimization to the
// experimental detached Security-field W128/P3 path. Production P1 and
// ordinary P3 keep the established two-step strict decoder.
func usePrivateSinglePassSecurity(ctx context.Context) bool {
	return ctx != nil && privateSecurityFieldPartitionsEnabled(ctx) &&
		securityBulkLimitsFromContext(ctx).Name == "P3"
}
