// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

// DirectRootScopeResolver proves only the one safe, source-native membership
// fact requiring no File-ID reopen and no pathname reconstruction: at the
// original event USN, the journal itself names the governed root's exact
// NTFS object identity as the event's parent.
//
// This is NOT an outside-scope filter. Nested ancestry, hard links, moves and
// deletes with a different parent remain unresolved until a trusted historical
// index can establish membership; no event is silently discarded.
func DirectRootScopeResolver(governedScopeID, journalID string,
    root records.NTFSObjectIdentity) ScopeResolver {
    return func(change records.USNChangeObservation)(ScopeEvidence,error){
        evidence:=ScopeEvidence{
            Class:ScopeUnresolved,
            ScopeID:governedScopeID,
            JournalID:journalID,
            RootIdentity:root,
            FileIdentity:change.FileIdentity,
            ParentIdentity:change.ParentIdentity,
            EventUSN:change.USN,
        }
        if change.ParentIdentity==root {
            evidence.Class=ScopeGoverned
            evidence.HistoricalAncestry=true
            evidence.Reason="JournalRecordedImmediateGovernedRootParent"
        }
        return evidence,nil
    }
}
