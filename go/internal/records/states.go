// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// Used by Windows Systems and Backend Recorder.

// CollectionMethod identifies the source-side mechanism that produced an
// observation.
//
// Only mechanisms that actually exist belong here.
type CollectionMethod string

const (
	CollectionDirectWindowsNTFS CollectionMethod = "DirectWindowsNTFS"
)

// ObservationState describes a sub-observation that can fail without making the
// entire source observation unusable.
//
// Add new states only when a real collector or record path emits them.
type ObservationState string

const (
	ObservationStateError   ObservationState = "Error"
	ObservationStatePresent ObservationState = "Present"
)

// ObservationStatus describes the overall result of the current direct NTFS
// collection.
//
// Complete means all current collection work succeeded. Partial means useful
// facts were returned but a non-fatal sub-collection failed. The Changed and
// Replaced states record consistency problems observed while the collector was
// running.
type ObservationStatus string

const (
	ObservationChangedDuringCollection  ObservationStatus = "ChangedDuringCollection"
	ObservationComplete                 ObservationStatus = "Complete"
	ObservationPartial                  ObservationStatus = "Partial"
	ObservationReplacedDuringCollection ObservationStatus = "ReplacedDuringCollection"
)

// ReparseState records whether Windows reported a reparse point for the object.
type ReparseState string

const (
	ReparseStateNotPresent ReparseState = "NotPresent"
	ReparseStatePresent    ReparseState = "Present"
)

// ReparseTagNameNotKnown means FI preserved an exact reparse tag value but does
// not have an exact documented name for that value.
const ReparseTagNameNotKnown = "NotKnown"

// StreamKind identifies how an NTFS stream relates to its parent object.
type StreamKind string

const (
	StreamDefaultData StreamKind = "DefaultData"
	StreamNamedData   StreamKind = "NamedData"
	StreamOther       StreamKind = "Other"
)

// SubjectKind identifies the base NTFS object kind observed by Windows.
// Reparse state and tag identity are recorded separately.
type SubjectKind string

const (
	SubjectDirectory SubjectKind = "Directory"
	SubjectFile      SubjectKind = "File"
)

// END Used by Windows Systems and Backend Recorder.
