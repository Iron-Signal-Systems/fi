// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

// ObjectWork is a lightweight NTFS correlation candidate. The complete USN
// change history is retained separately in Segment.Batch. Parent references
// are historical facts, never a substitute for hard-link or move resolution.
type ObjectWork struct {
	FileIdentity     records.NTFSObjectIdentity   `json:"file_identity"`
	ParentIdentities []records.NTFSObjectIdentity `json:"parent_identities"`
	TriggerUSNs      []string                     `json:"trigger_usns"`
	// ScopeUnknown is intentional until ancestry, moves, and historical
	// bindings are resolved. No candidate is discarded on a quick path test.
	Scope string `json:"scope"`
}

const ScopeUnknown = "Unresolved"

// DistinctWork preserves first-seen order and every triggering USN. It
// deduplicates expensive object lookups, NOT individual journal events.
func DistinctWork(batch records.USNReadBatch) []ObjectWork {
	indexed := make(map[records.NTFSObjectIdentity]int)
	result := make([]ObjectWork, 0)
	for _, change := range batch.Records {
		pos, exists := indexed[change.FileIdentity]
		if !exists {
			pos = len(result)
			indexed[change.FileIdentity] = pos
			result = append(result, ObjectWork{FileIdentity: change.FileIdentity, Scope: ScopeUnknown})
		}
		object := &result[pos]
		object.TriggerUSNs = append(object.TriggerUSNs, change.USN)
		found := false
		for _, parent := range object.ParentIdentities {
			if parent == change.ParentIdentity {
				found = true
				break
			}
		}
		if !found {
			object.ParentIdentities = append(object.ParentIdentities, change.ParentIdentity)
		}
	}
	return result
}
