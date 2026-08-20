// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// Used by Windows Systems and Backend Recorder.

// SubjectKind identifies the NTFS object kind observed by Windows.
type SubjectKind string

const (
	SubjectFile          SubjectKind = "File"
	SubjectDirectory     SubjectKind = "Directory"
	SubjectReparseObject SubjectKind = "ReparseObject"
)

// ObservationState describes a sub-observation that can fail without making the
// entire source observation unusable.
//
// Add new states only when a real collector or record path emits them.
type ObservationState string

const (
	ObservationStatePresent ObservationState = "Present"
	ObservationStateError   ObservationState = "Error"
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
	ObservationComplete                 ObservationStatus = "Complete"
	ObservationPartial                  ObservationStatus = "Partial"
	ObservationChangedDuringCollection  ObservationStatus = "ChangedDuringCollection"
	ObservationReplacedDuringCollection ObservationStatus = "ReplacedDuringCollection"
)

// CollectionMethod identifies the source-side mechanism that produced an
// observation.
//
// Only mechanisms that actually exist belong here.
type CollectionMethod string

const (
	CollectionDirectWindowsNTFS CollectionMethod = "DirectWindowsNTFS"
)

// StreamKind identifies how an NTFS stream relates to its parent object.
type StreamKind string

const (
	StreamDefaultData StreamKind = "DefaultData"
	StreamNamedData   StreamKind = "NamedData"
	StreamOther       StreamKind = "Other"
)

// END Used by Windows Systems and Backend Recorder.
