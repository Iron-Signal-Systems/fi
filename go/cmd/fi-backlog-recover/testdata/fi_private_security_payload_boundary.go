// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// EXPERIMENTAL, PRIVATE ONLY. A structural boundary check replaces a second
// complete JSON syntax validation on canonical Security event envelopes.
// Strict payload decoding is STILL the acceptance authority. Any malformed
// structural candidate is handed back to the legacy decoder unchanged.
package recordingest

// privateSingleJSONObjectBoundary confirms that a JSON object occupies the
// entire payload byte span, with no trailing envelope member. It recognizes
// nested arrays/objects, quoted text, and escaped delimiters. It intentionally
// does NOT validate JSON grammar: decodeStrictPayload does that independently.
// If strict decoding fails, the caller uses json.Valid to decide whether the
// original fast path would have declined the malformed candidate.
func privateSingleJSONObjectBoundary(value []byte) bool {
    if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
        return false
    }
    // Separate object/array stack ensures a malformed nesting sequence is
    // never mistaken for a complete canonical object.
    var stack [64]byte // bounded, allocation-free for canonical Security JSON
    depth := 0
    var inString, escaped bool
    for i, b := range value {
        if inString {
            if escaped {
                escaped = false
            } else if b == '\\' {
                escaped = true
            } else if b == '"' {
                inString = false
            }
            continue
        }
        switch b {
        case '"':
            inString = true
        case '{', '[':
            if depth == len(stack) {
                return false // uncommon deep input takes original decoder path
            }
            stack[depth] = b
            depth++
        case '}', ']':
            if depth == 0 {
                return false
            }
            expected := byte('{')
            if b == ']' {
                expected = '['
            }
            if stack[depth-1] != expected {
                return false
            }
            depth--
            if depth == 0 && i != len(value)-1 {
                return false
            }
        }
    }
    return !inString && !escaped && depth == 0
}
