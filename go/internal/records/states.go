package records

// SubjectKind identifies the primary NTFS object kind observed by FI.
type SubjectKind string

const (
	SubjectFile          SubjectKind = "File"
	SubjectDirectory     SubjectKind = "Directory"
	SubjectReparseObject SubjectKind = "ReparseObject"
)

// IdentityConfidence describes how authoritative an object identity is.
type IdentityConfidence string

const (
	IdentityAuthoritative IdentityConfidence = "Authoritative"
	IdentityCorroborated  IdentityConfidence = "Corroborated"
	IdentityAmbiguous     IdentityConfidence = "Ambiguous"
	IdentityUnavailable   IdentityConfidence = "Unavailable"
	IdentityUnsupported   IdentityConfidence = "Unsupported"
	IdentityInvalid       IdentityConfidence = "Invalid"
)

// ObservationState describes the result of one attempted field or field-group observation.
type ObservationState string

const (
	ObservationStatePresent       ObservationState = "Present"
	ObservationStateNotApplicable ObservationState = "NotApplicable"
	ObservationStateNotObserved   ObservationState = "NotObserved"
	ObservationStateUnavailable   ObservationState = "Unavailable"
	ObservationStateUnsupported   ObservationState = "Unsupported"
	ObservationStateAccessDenied  ObservationState = "AccessDenied"
	ObservationStateAmbiguous     ObservationState = "Ambiguous"
	ObservationStateInvalid       ObservationState = "Invalid"
	ObservationStateError         ObservationState = "Error"
)

// ObservationStatus describes the overall result of one source observation.
type ObservationStatus string

const (
	ObservationComplete                 ObservationStatus = "Complete"
	ObservationPartial                  ObservationStatus = "Partial"
	ObservationChangedDuringCollection  ObservationStatus = "ChangedDuringCollection"
	ObservationReplacedDuringCollection ObservationStatus = "ReplacedDuringCollection"
	ObservationSubjectNotFound          ObservationStatus = "SubjectNotFound"
	ObservationSourceUnavailable        ObservationStatus = "SourceUnavailable"
	ObservationContinuityLost           ObservationStatus = "ContinuityLost"
	ObservationInvalid                  ObservationStatus = "Invalid"
	ObservationCancelled                ObservationStatus = "Cancelled"
)

// CollectionMethod identifies the source-side mechanism that produced an observation.
type CollectionMethod string

const (
	CollectionDirectWindowsNTFS CollectionMethod = "DirectWindowsNTFS"
	CollectionProtectedRead     CollectionMethod = "ProtectedReadBroker"
)

// StreamKind identifies the relationship of an NTFS stream to its parent object.
type StreamKind string

const (
	StreamDefaultData StreamKind = "DefaultData"
	StreamNamedData   StreamKind = "NamedData"
	StreamOther       StreamKind = "Other"
)

// JournalContinuityState describes whether incremental source coverage can continue safely.
type JournalContinuityState string

const (
	JournalContinuous            JournalContinuityState = "Continuous"
	JournalBaselineReplayPending JournalContinuityState = "BaselineReplayPending"
	JournalReconciliationPending JournalContinuityState = "ReconciliationPending"
	JournalDiscontinuous         JournalContinuityState = "Discontinuous"
	JournalUnavailable           JournalContinuityState = "JournalUnavailable"
	JournalRecreated             JournalContinuityState = "JournalRecreated"
	JournalCursorExpired         JournalContinuityState = "CursorExpired"
	JournalVolumeIdentityChanged JournalContinuityState = "VolumeIdentityChanged"
	JournalInvalid               JournalContinuityState = "Invalid"
	JournalUnknown               JournalContinuityState = "Unknown"
)
