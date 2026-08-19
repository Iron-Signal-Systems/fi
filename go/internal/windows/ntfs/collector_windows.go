//go:build windows

package ntfs

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func CollectPath(ctx context.Context, scopeID string, governedRoot string, targetPath string) (Observation, error) {
	rootUnits, err := syscall.UTF16FromString(governedRoot)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(GovernedRoot)", Err: err}
	}
	targetUnits, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(Target)", Err: err}
	}
	return CollectUTF16(ctx, scopeID, rootUnits[:len(rootUnits)-1], targetUnits[:len(targetUnits)-1])
}

func CollectUTF16(ctx context.Context, scopeID string, governedRoot []uint16, targetPath []uint16) (Observation, error) {
	if scopeID == "" {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "ValidateScope", Err: ErrGovernedRootRequired}
	}
	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}
	if err := validateLocalAbsolutePath(governedRoot); err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "ValidatePath", Err: err}
	}
	if err := validateLocalAbsolutePath(targetPath); err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "ValidatePath", Err: err}
	}

	rootHandle, err := openPath(nulTerminate(governedRoot))
	if err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "CreateFileW", Err: err}
	}
	defer syscall.CloseHandle(rootHandle)

	rootFileSystem, err := queryVolume(rootHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "GetVolumeInformationByHandleW", Err: err}
	}
	if !strings.EqualFold(rootFileSystem, "NTFS") {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "VerifyNTFS", Err: ErrNotNTFS}
	}
	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		return Observation{}, err
	}
	if rootState.Basic.FileAttributes&fileAttributeReparse != 0 {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "RejectReparseRoot", Err: ErrGovernedRootReparse}
	}
	rootFinalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "GetFinalPathNameByHandleW", Err: err}
	}
	rootVolumeGUID, err := volumeGUIDFromFinalPath(rootFinalPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "ParseVolumeGUID", Err: err}
	}
	rootVolumeIdentity, rootObjectIdentity, err := buildObjectIdentity(rootState.ID.VolumeSerialNumber, rootState.ID.FileID)
	if err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "DecodeNTFSFileID", Err: err}
	}
	rootVolumeIdentity.VolumeGUID = rootVolumeGUID

	targetHandle, err := openPath(nulTerminate(targetPath))
	if err != nil {
		return Observation{}, &Error{Stage: StageOpen, Op: "CreateFileW", Err: err}
	}
	defer syscall.CloseHandle(targetHandle)

	targetFileSystem, err := queryVolume(targetHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageVolume, Op: "GetVolumeInformationByHandleW", Err: err}
	}
	if !strings.EqualFold(targetFileSystem, "NTFS") {
		return Observation{}, &Error{Stage: StageVolume, Op: "VerifyNTFS", Err: ErrNotNTFS}
	}
	targetFinalPath, err := finalVolumePath(targetHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageContainment, Op: "GetFinalPathNameByHandleW", Err: err}
	}
	targetVolumeGUID, err := volumeGUIDFromFinalPath(targetFinalPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageContainment, Op: "ParseVolumeGUID", Err: err}
	}
	if targetVolumeGUID != rootVolumeGUID || !pathContainedBy(rootFinalPath, targetFinalPath) {
		return Observation{}, &Error{Stage: StageContainment, Op: "HandleDerivedContainment", Err: ErrOutsideGovernedRoot}
	}

	pre, err := queryNativeState(targetHandle)
	if err != nil {
		return Observation{}, err
	}

	streamInventory := records.StreamInventory{State: records.ObservationStatePresent, Streams: []records.StreamObservation{}}
	warnings := []records.ObservationWarning{}
	status := records.ObservationComplete
	nativeStreams, streamErr := queryStreams(targetHandle)
	if streamErr != nil {
		streamInventory = records.StreamInventory{State: records.ObservationStateError, Streams: []records.StreamObservation{}, ReasonCode: "StreamEnumerationFailed"}
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{Code: "StreamEnumerationFailed", Detail: streamErr.Error()})
	} else {
		streamInventory.Streams, err = streamObservations(nativeStreams)
		if err != nil {
			return Observation{}, &Error{Stage: StageStreams, Op: "Convert", Err: err}
		}
	}

	post, err := queryNativeState(targetHandle)
	if err != nil {
		return Observation{}, err
	}
	if pre.ID != post.ID {
		return Observation{}, &Error{Stage: StageConsistency, Op: "SameHandleIdentity", Err: ErrIdentityChanged}
	}
	volumeIdentity, objectIdentity, err := buildObjectIdentity(post.ID.VolumeSerialNumber, post.ID.FileID)
	if err != nil {
		return Observation{}, &Error{Stage: StageIdentity, Op: "DecodeNTFSFileID", Err: err}
	}
	volumeIdentity.VolumeGUID = targetVolumeGUID

	metadata, subjectKind, err := metadataFromState(post)
	if err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "Convert", Err: err}
	}
	if pre.Basic != post.Basic || pre.Standard != post.Standard {
		if status == records.ObservationComplete {
			status = records.ObservationChangedDuringCollection
		} else {
			status = records.ObservationPartial
		}
		warnings = append(warnings, records.ObservationWarning{Code: "MetadataChangedDuringCollection"})
	}

	reopened, reopenErr := openPath(nulTerminate(targetPath))
	if reopenErr != nil {
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{Code: "PathConsistencyNotVerified"})
	} else {
		reopenedFinalPath, finalErr := finalVolumePath(reopened)
		reopenedState, stateErr := queryNativeState(reopened)
		syscall.CloseHandle(reopened)
		if finalErr != nil || stateErr != nil {
			status = records.ObservationPartial
			warnings = append(warnings, records.ObservationWarning{Code: "PathConsistencyNotVerified"})
		} else if !pathContainedBy(rootFinalPath, reopenedFinalPath) {
			return Observation{}, &Error{Stage: StageContainment, Op: "ReopenContainment", Err: ErrOutsideGovernedRoot}
		} else if reopenedState.ID != post.ID {
			status = records.ObservationReplacedDuringCollection
			warnings = append(warnings, records.ObservationWarning{Code: "PathNowReferencesDifferentObject"})
		}
	}

	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].Code < warnings[j].Code })

	rootVolumeCopy := rootVolumeIdentity
	rootObjectCopy := rootObjectIdentity
	observation := Observation{
		GovernedRoot: records.GovernedRootIdentity{
			ScopeID:                       scopeID,
			RequestedPathUTF16LEBase64URL: utf16LEBase64URL(governedRoot),
			ResolvedPathUTF16LEBase64URL:  utf16LEBase64URL(rootFinalPath),
			State:                         records.ObservationStatePresent,
			MethodVersion:                 ContainmentMethodVersion,
			VolumeIdentity:                &rootVolumeCopy,
			ObjectIdentity:                &rootObjectCopy,
		},
		Containment:       records.PathContainment{State: records.ObservationStatePresent, MethodVersion: ContainmentMethodVersion},
		VolumeIdentity:    volumeIdentity,
		ObjectIdentity:    objectIdentity,
		SubjectKind:       subjectKind,
		PathBinding:       records.PathBinding{PathUTF16LEBase64URL: utf16LEBase64URL(targetPath), State: records.ObservationStatePresent},
		Metadata:          metadata,
		StreamInventory:   streamInventory,
		CollectionMethod:  records.CollectionDirectWindowsNTFS,
		ObservationStatus: status,
		Warnings:          warnings,
	}
	if err := ValidateObservation(observation); err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "ValidateObservation", Err: err}
	}
	return observation, nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func nulTerminate(path []uint16) []uint16 { return append(append([]uint16(nil), path...), 0) }

func metadataFromState(state nativeState) (records.MetadataObservation, records.SubjectKind, error) {
	if state.Standard.EndOfFile < 0 || state.Standard.AllocationSize < 0 {
		return records.MetadataObservation{}, "", fmt.Errorf("negative file size")
	}
	creationTime, err := filetimeToCanonical(state.Basic.CreationTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	lastAccessTime, err := filetimeToCanonical(state.Basic.LastAccessTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	lastWriteTime, err := filetimeToCanonical(state.Basic.LastWriteTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	changeTime, err := filetimeToCanonical(state.Basic.ChangeTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}

	subjectKind := records.SubjectFile
	objectKind := "RegularFile"
	if state.Basic.FileAttributes&fileAttributeReparse != 0 {
		subjectKind = records.SubjectReparseObject
		objectKind = "ReparseObject"
	} else if state.Standard.Directory != 0 || state.Basic.FileAttributes&fileAttributeDirectory != 0 {
		subjectKind = records.SubjectDirectory
		objectKind = "Directory"
	}
	return records.MetadataObservation{
		State:          records.ObservationStatePresent,
		ObjectKind:     objectKind,
		LogicalSize:    strconv.FormatUint(uint64(state.Standard.EndOfFile), 10),
		AllocatedSize:  strconv.FormatUint(uint64(state.Standard.AllocationSize), 10),
		CreationTime:   creationTime,
		LastWriteTime:  lastWriteTime,
		ChangeTime:     changeTime,
		LastAccessTime: lastAccessTime,
		RawAttributes:  strconv.FormatUint(uint64(state.Basic.FileAttributes), 10),
		LinkCount:      strconv.FormatUint(uint64(state.Standard.NumberOfLinks), 10),
	}, subjectKind, nil
}

func streamObservations(native []nativeStream) ([]records.StreamObservation, error) {
	observations := make([]records.StreamObservation, 0, len(native))
	for _, stream := range native {
		if stream.Size < 0 || stream.AllocationSize < 0 {
			return nil, fmt.Errorf("negative stream size")
		}
		observations = append(observations, records.StreamObservation{
			Identity:      streamIdentityFromWindowsName(stream.Name),
			State:         records.ObservationStatePresent,
			LogicalSize:   strconv.FormatUint(uint64(stream.Size), 10),
			AllocatedSize: strconv.FormatUint(uint64(stream.AllocationSize), 10),
		})
	}
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Identity.RawNameUTF16LEBase64URL < observations[j].Identity.RawNameUTF16LEBase64URL
	})
	return observations, nil
}
