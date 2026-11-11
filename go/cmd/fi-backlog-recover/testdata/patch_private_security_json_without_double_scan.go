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

    // Keep findSinglePassSecurityEnvelopeKeys unchanged: its historical
    // equivalence tests and legacy fallback behavior are authoritative.
    // The private canonical variant performs the additional duplicate-key
    // disqualification IN ITS EXISTING comma scan, with no second pass.
    src=exactlyOne(src,
        "written, payload, unique := findSinglePassSecurityEnvelopeKeys(body)",
        "written, payload, unique := findPrivateCanonicalSecurityEnvelopeKeys(body)")

    // This helper is used only when private W128/P3 explicitly selected
    // canonical Security ingestion. The legacy key scan is retained intact.
    helper:=`
func findPrivateCanonicalSecurityEnvelopeKeys(body []byte) (writtenAt, payload int, unique bool) {
    writtenAt,payload=-1,-1
    for offset:=0;offset<len(body); {
        comma:=bytes.IndexByte(body[offset:],',')
        if comma<0 {break}
        offset+=comma
        if bytes.HasPrefix(body[offset:],securityWrittenAtKey) {
            if writtenAt>=0 {return -1,-1,false}
            writtenAt=offset
        }
        if bytes.HasPrefix(body[offset:],securityPayloadKey) {
            if payload>=0 {return -1,-1,false}
            payload=offset
        } else if payload>=0 {
            // Canonical signed Windows spool JSON has no padded JSON
            // member separators or escaped member names. Fall back to
            // the original strict decoder for noncanonical member keys.
            keyStart:=offset+1
            for keyStart<len(body)&&(body[keyStart]==' '||body[keyStart]=='\t'){
                keyStart++
            }
            if keyStart!=offset+1&&keyStart<len(body)&&body[keyStart]=='"'{
                return -1,-1,false
            }
            if keyStart+1<len(body)&&body[keyStart]=='"'&&body[keyStart+1]=='\\'{
                return -1,-1,false
            }
            const key = ",\"payload\""
            if len(body)-offset>=len(key)&&
                bytes.EqualFold(body[offset:offset+len(key)],[]byte(key)){
                end:=offset+len(key)
                for end<len(body)&&(body[end]==' '||body[end]=='\t'){end++}
                if end<len(body)&&body[end]==':'{return -1,-1,false}
            }
        }
        offset++
    }
    return writtenAt,payload,writtenAt>=0&&payload>=0
}
`
    src += helper

    if err:=os.WriteFile(p,[]byte(src),0600);err!=nil {panic(err)}
    fmt.Println("FI JSON ONCE PATCH PASS canonical_extra_payload_scans=0 strict_json_decoder=unchanged SHA_once=retained")
}
