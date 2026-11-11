// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Private development overlay: remove the redundant full-payload json.Valid
// traversal from the authenticated canonical Security fast path.
// The existing strict JSONv2 typed decoder remains mandatory.
// Patch applies ONLY to the disposable pinned H16 source archive.
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func exactlyOne(src, old, replacement string) string {
    if count:=strings.Count(src,old);count!=1 {
        panic(fmt.Sprintf("FI JSON ONCE PATCH STOP: expected one historical source anchor; found %d",count))
    }
    return strings.Replace(src,old,replacement,1)
}

func main() {
    if len(os.Args)!=2 {panic("FI JSON ONCE PATCH STOP: one disposable optimized-source directory required")}
    root:=os.Args[1]
    if !filepath.IsAbs(root)||!strings.Contains(root,"/fi-window-bench-")||
        !strings.HasSuffix(root,"/optimized-source") {
        panic("FI JSON ONCE PATCH STOP: target is not disposable pinned source")
    }
    p:=filepath.Join(root,"go/internal/recordingest/security_single_pass_candidate.go")
    raw,err:=os.ReadFile(p)
    if err!=nil {panic(err)}
    src:=string(raw)

    // Normal Windows Security payloads are JSON objects written at the end
    // of the canonical spool envelope. A constant-time '}}' tail check
    // rejects an extra top-level string member after the payload. The
    // existing comma/key-marker loop identifies duplicate payload members.
    // Do NOT substitute another O(n) structural scan.
    oldPayload:=`// A payload followed by another top-level envelope member is valid
	// legacy JSON, but not canonical spool layout: decline this fast path.
	// json.Valid also confirms that the exact zero-copy RawMessage is
	// independently well-formed, as required by the source-record contract.
	if len(rawPayload) == 0 || !json.Valid(rawPayload) {
		return emptySource, emptySecurity, false, nil
	}`
    newPayload:=`// The canonical Windows emitter writes its object payload as the LAST
	// envelope member. Its final two bytes are therefore the payload's
	// closing brace and the envelope's closing brace. Check that shape in
	// constant time; the strict typed JSON decoder below validates all
	// nested JSON grammar, schema, and unknown fields in a single pass.
	// Unexpected suffixes return to the legacy decoder, not to an unsafe
	// success path. No extra whole-payload scan on canonical records.
	if len(rawPayload) == 0 || body[len(body)-2] != '}' {
		return emptySource, emptySecurity, false, nil
	}`
    src=exactlyOne(src,oldPayload,newPayload)

    // On the rare malformed input, the original JSON-validity gate selected
    // the legacy fallback. Pay the json.Valid cost ONLY on decoder errors.
    oldDecoder:=`if err := decodeStrictPayload(json.RawMessage(body), &parsed); err != nil {
		return emptySource, emptySecurity, true, fmt.Errorf("decode FI ingest source record: %w", err)
	}`
    newDecoder:=`if err := decodeStrictPayload(json.RawMessage(body), &parsed); err != nil {
		if !json.Valid(rawPayload) {
			return emptySource, emptySecurity, false, nil
		}
		return emptySource, emptySecurity, true, fmt.Errorf("decode FI ingest source record: %w", err)
	}`
    src=exactlyOne(src,oldDecoder,newDecoder)

    // json/v1 semantics can accept an alternate-case duplicate payload key.
    // Reject such a post-payload key in the EXISTING comma scanning loop
    // rather than revalidating the entire payload. The existing key scanner
    // remains the only O(n) delimiter scan performed before strict decode.
    oldScanner:=`if bytes.HasPrefix(body[offset:], securityPayloadKey) {
			if payload >= 0 {
				return -1, -1, false
			}
			payload = offset
		}`
    newScanner:=`if bytes.HasPrefix(body[offset:], securityPayloadKey) {
			if payload >= 0 {
				return -1, -1, false
			}
			payload = offset
		} else if payload >= 0 {
			// A duplicate payload member with changed capitalization or
			// whitespace is not canonical (v1 accepts case-folded keys).
			const key = ",\"payload\""
			if len(body)-offset >= len(key) &&
				bytes.EqualFold(body[offset:offset+len(key)], []byte(key)) {
				end := offset + len(key)
				for end < len(body) && (body[end] == ' ' || body[end] == '\t') {
					end++
				}
				if end < len(body) && body[end] == ':' {
					return -1, -1, false
				}
			}
		}`
    src=exactlyOne(src,oldScanner,newScanner)

    if err:=os.WriteFile(p,[]byte(src),0600);err!=nil {panic(err)}
    fmt.Println("FI JSON ONCE PATCH PASS canonical_extra_payload_scans=0 strict_json_decoder=unchanged SHA_once=retained")
}
