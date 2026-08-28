// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const (
	CollectionMethod = "WindowsNTFSUSNJournalV0"

	fsctlQueryUSNJournal = 0x000900F4
	fsctlReadUSNJournal  = 0x000900BB

	readBufferSize             = 1024 * 1024
	usnV2HeaderSize            = 60
	maximumFinalPathUTF16Units = 64 * 1024
)

var (
	ErrInvalidGovernedRoot  = errors.New("governed root must use a local drive-absolute path")
	ErrMalformedUSNBuffer   = errors.New("Windows returned a malformed USN journal buffer")
	ErrUnsupportedUSNRecord = errors.New("unsupported USN record version")
)

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procDeviceIoControl               = kernel32.NewProc("DeviceIoControl")
	procGetFileInformationByHandleEx  = kernel32.NewProc("GetFileInformationByHandleEx")
	procGetFinalPathNameByHandleW     = kernel32.NewProc("GetFinalPathNameByHandleW")
	procGetVolumeInformationByHandleW = kernel32.NewProc("GetVolumeInformationByHandleW")
)

type journalDataV0 struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type readJournalDataV0 struct {
	StartUSN          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	JournalID         uint64
}

var (
	_ [24 - unsafe.Sizeof(fileIDInfo{})]byte
	_ [unsafe.Sizeof(fileIDInfo{}) - 24]byte
	_ [56 - unsafe.Sizeof(journalDataV0{})]byte
	_ [unsafe.Sizeof(journalDataV0{}) - 56]byte
	_ [40 - unsafe.Sizeof(readJournalDataV0{})]byte
	_ [unsafe.Sizeof(readJournalDataV0{}) - 40]byte
)

// QueryJournal records the current NTFS change-journal state for the volume
// containing governedRoot. It never creates, resizes, deletes, or otherwise
// modifies the journal.
func QueryJournal(ctx context.Context, scopeID, governedRoot string) (records.USNJournalState, error) {
	if err := validateContext(ctx); err != nil {
		return records.USNJournalState{}, err
	}
	if scopeID == "" {
		return records.USNJournalState{}, errors.New("scope ID is required")
	}

	volume, err := openVolumeForRoot(governedRoot)
	if err != nil {
		return records.USNJournalState{}, err
	}
	defer syscall.CloseHandle(volume.handle)

	journal, err := queryJournalNative(volume.handle)
	if err != nil {
		return records.USNJournalState{}, err
	}
	if journal.FirstUSN < 0 || journal.NextUSN < 0 || journal.LowestValidUSN < 0 || journal.MaxUSN < 0 {
		return records.USNJournalState{}, ErrMalformedUSNBuffer
	}

	state := records.USNJournalState{
		ObservedAt:       canonicalNow(),
		CollectionMethod: CollectionMethod,
		ScopeID:          scopeID,
		VolumeIdentity:   volume.identity,
		JournalID:        strconv.FormatUint(journal.JournalID, 10),
		FirstUSN:         strconv.FormatUint(uint64(journal.FirstUSN), 10),
		NextUSN:          strconv.FormatUint(uint64(journal.NextUSN), 10),
		LowestValidUSN:   strconv.FormatUint(uint64(journal.LowestValidUSN), 10),
		MaxUSN:           strconv.FormatUint(uint64(journal.MaxUSN), 10),
		MaximumSize:      strconv.FormatUint(journal.MaximumSize, 10),
		AllocationDelta:  strconv.FormatUint(journal.AllocationDelta, 10),
	}
	if err := records.ValidateUSNJournalState(state); err != nil {
		return records.USNJournalState{}, err
	}
	return state, nil
}

// ReadJournal reads one bounded batch beginning at startUSN. The result is
// volume-wide source data. Governed-root filtering is intentionally deferred to
// the later File-ID re-observation step, where containment can be proved from an
// open handle instead of guessed from the USN leaf name.
func ReadJournal(ctx context.Context, scopeID, governedRoot, startUSN string) (records.USNReadBatch, error) {
	if err := validateContext(ctx); err != nil {
		return records.USNReadBatch{}, err
	}
	start, err := parseUSN(startUSN)
	if err != nil {
		return records.USNReadBatch{}, err
	}

	volume, err := openVolumeForRoot(governedRoot)
	if err != nil {
		return records.USNReadBatch{}, err
	}
	defer syscall.CloseHandle(volume.handle)

	journal, err := queryJournalNative(volume.handle)
	if err != nil {
		return records.USNReadBatch{}, err
	}
	if journal.FirstUSN < 0 || journal.NextUSN < 0 || journal.LowestValidUSN < 0 || journal.MaxUSN < 0 {
		return records.USNReadBatch{}, ErrMalformedUSNBuffer
	}

	buffer, err := readJournalNative(volume.handle, start, journal.JournalID)
	if err != nil {
		return records.USNReadBatch{}, err
	}
	next, changes, err := parseReadBuffer(buffer)
	if err != nil {
		return records.USNReadBatch{}, err
	}

	batch := records.USNReadBatch{
		ObservedAt:       canonicalNow(),
		CollectionMethod: CollectionMethod,
		ScopeID:          scopeID,
		VolumeIdentity:   volume.identity,
		JournalID:        strconv.FormatUint(journal.JournalID, 10),
		StartUSN:         strconv.FormatUint(uint64(start), 10),
		NextUSN:          strconv.FormatUint(uint64(next), 10),
		Records:          changes,
	}
	if err := records.ValidateUSNReadBatch(batch); err != nil {
		return records.USNReadBatch{}, err
	}
	return batch, nil
}

type openedVolume struct {
	handle   syscall.Handle
	identity records.VolumeIdentity
}

func openVolumeForRoot(governedRoot string) (openedVolume, error) {
	drive, err := governedRootDrive(governedRoot)
	if err != nil {
		return openedVolume{}, err
	}

	devicePath := `\\.\` + strings.ToUpper(drive) + `:`
	deviceUnits, err := syscall.UTF16PtrFromString(devicePath)
	if err != nil {
		return openedVolume{}, err
	}
	handle, err := syscall.CreateFile(
		deviceUnits,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return openedVolume{}, err
	}

	identity, err := queryVolumeIdentity(governedRoot)
	if err != nil {
		syscall.CloseHandle(handle)
		return openedVolume{}, err
	}
	return openedVolume{handle: handle, identity: identity}, nil
}

func governedRootDrive(path string) (string, error) {
	switch {
	case len(path) >= 3 && isASCIILetter(path[0]) && path[1] == ':' && path[2] == '\\':
		return string(path[0]), nil
	case len(path) >= 7 && strings.HasPrefix(path, `\\?\`) && isASCIILetter(path[4]) && path[5] == ':' && path[6] == '\\':
		return string(path[4]), nil
	default:
		return "", ErrInvalidGovernedRoot
	}
}

func isASCIILetter(value byte) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

func queryVolumeIdentity(governedRoot string) (records.VolumeIdentity, error) {
	rootUnits, err := syscall.UTF16PtrFromString(governedRoot)
	if err != nil {
		return records.VolumeIdentity{}, err
	}
	rootHandle, err := syscall.CreateFile(
		rootUnits,
		0x0080, // FILE_READ_ATTRIBUTES
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return records.VolumeIdentity{}, err
	}
	defer syscall.CloseHandle(rootHandle)

	var fsName [32]uint16
	r1, _, callErr := procGetVolumeInformationByHandleW.Call(
		uintptr(rootHandle),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if r1 == 0 {
		return records.VolumeIdentity{}, callErr
	}
	if !strings.EqualFold(syscall.UTF16ToString(fsName[:]), "NTFS") {
		return records.VolumeIdentity{}, ntfs.ErrNotNTFS
	}

	var id fileIDInfo
	r1, _, callErr = procGetFileInformationByHandleEx.Call(
		uintptr(rootHandle),
		18, // FileIdInfo
		uintptr(unsafe.Pointer(&id)),
		unsafe.Sizeof(id),
	)
	if r1 == 0 {
		return records.VolumeIdentity{}, callErr
	}

	finalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		return records.VolumeIdentity{}, err
	}
	volumeGUID, err := volumeGUIDFromFinalPath(finalPath)
	if err != nil {
		return records.VolumeIdentity{}, err
	}

	identity := records.VolumeIdentity{
		MethodVersion: ntfs.IdentityMethodVersion,
		VolumeGUID:    volumeGUID,
		VolumeSerial:  strconv.FormatUint(id.VolumeSerialNumber, 10),
	}
	if err := records.ValidateVolumeIdentity(identity); err != nil {
		return records.VolumeIdentity{}, err
	}
	return identity, nil
}

func finalVolumePath(handle syscall.Handle) ([]uint16, error) {
	buffer := make([]uint16, 512)
	for attempts := 0; attempts < 3; attempts++ {
		length, _, callErr := procGetFinalPathNameByHandleW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			0x0001, // VOLUME_NAME_GUID | FILE_NAME_NORMALIZED
		)
		if length == 0 {
			return nil, callErr
		}
		if length < uintptr(len(buffer)) {
			return append([]uint16(nil), buffer[:length]...), nil
		}
		nextSize, err := finalPathBufferLength(length)
		if err != nil {
			return nil, err
		}
		buffer = make([]uint16, nextSize)
	}
	return nil, errors.New("final path exceeded retry bound")
}

func finalPathBufferLength(required uintptr) (int, error) {
	if required >= uintptr(maximumFinalPathUTF16Units) {
		return 0, fmt.Errorf(
			"final path exceeds bounded UTF-16 limit: %d >= %d",
			required,
			maximumFinalPathUTF16Units,
		)
	}
	return int(required) + 1, nil
}

func volumeGUIDFromFinalPath(path []uint16) (string, error) {
	prefix := []uint16{'\\', '\\', '?', '\\', 'V', 'o', 'l', 'u', 'm', 'e', '{'}
	if len(path) < len(prefix) {
		return "", errors.New("final path is not a volume-GUID path")
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return "", errors.New("final path is not a volume-GUID path")
		}
	}
	for i := len(prefix); i+1 < len(path); i++ {
		if path[i] == '}' && path[i+1] == '\\' {
			return syscall.UTF16ToString(path[:i+2]), nil
		}
	}
	return "", errors.New("volume GUID terminator missing")
}

func queryJournalNative(handle syscall.Handle) (journalDataV0, error) {
	var journal journalDataV0
	var returned uint32
	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		fsctlQueryUSNJournal,
		0,
		0,
		uintptr(unsafe.Pointer(&journal)),
		unsafe.Sizeof(journal),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r1 == 0 {
		return journalDataV0{}, callErr
	}
	if returned < uint32(unsafe.Sizeof(journal)) {
		return journalDataV0{}, ErrMalformedUSNBuffer
	}
	return journal, nil
}

func readJournalNative(handle syscall.Handle, startUSN int64, journalID uint64) ([]byte, error) {
	request := readJournalDataV0{
		StartUSN:          startUSN,
		ReasonMask:        0xFFFFFFFF,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		JournalID:         journalID,
	}
	buffer := make([]byte, readBufferSize)
	var returned uint32
	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		fsctlReadUSNJournal,
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r1 == 0 {
		return nil, callErr
	}
	if returned < 8 || returned > uint32(len(buffer)) {
		return nil, ErrMalformedUSNBuffer
	}
	return append([]byte(nil), buffer[:returned]...), nil
}

func parseReadBuffer(buffer []byte) (int64, []records.USNChangeObservation, error) {
	if len(buffer) < 8 {
		return 0, nil, ErrMalformedUSNBuffer
	}
	nextUSN := int64(binary.LittleEndian.Uint64(buffer[:8]))
	if nextUSN < 0 {
		return 0, nil, ErrMalformedUSNBuffer
	}

	changes := make([]records.USNChangeObservation, 0, 64)
	for offset := 8; offset < len(buffer); {
		if len(buffer)-offset < 8 {
			return 0, nil, ErrMalformedUSNBuffer
		}
		recordLength := int(binary.LittleEndian.Uint32(buffer[offset : offset+4]))
		major := binary.LittleEndian.Uint16(buffer[offset+4 : offset+6])
		minor := binary.LittleEndian.Uint16(buffer[offset+6 : offset+8])
		if recordLength < usnV2HeaderSize || offset+recordLength > len(buffer) {
			return 0, nil, ErrMalformedUSNBuffer
		}
		if major != 2 {
			return 0, nil, fmt.Errorf("%w: %d.%d", ErrUnsupportedUSNRecord, major, minor)
		}

		record, err := parseV2Record(buffer[offset:offset+recordLength], major, minor)
		if err != nil {
			return 0, nil, err
		}
		changes = append(changes, record)
		offset += recordLength
	}
	return nextUSN, changes, nil
}

func parseV2Record(raw []byte, major, minor uint16) (records.USNChangeObservation, error) {
	if len(raw) < usnV2HeaderSize {
		return records.USNChangeObservation{}, ErrMalformedUSNBuffer
	}

	fileRef := binary.LittleEndian.Uint64(raw[8:16])
	parentRef := binary.LittleEndian.Uint64(raw[16:24])
	usnValue := int64(binary.LittleEndian.Uint64(raw[24:32]))
	timestamp := int64(binary.LittleEndian.Uint64(raw[32:40]))
	reason := binary.LittleEndian.Uint32(raw[40:44])
	sourceInfo := binary.LittleEndian.Uint32(raw[44:48])
	securityID := binary.LittleEndian.Uint32(raw[48:52])
	attributes := binary.LittleEndian.Uint32(raw[52:56])
	nameLength := int(binary.LittleEndian.Uint16(raw[56:58]))
	nameOffset := int(binary.LittleEndian.Uint16(raw[58:60]))

	if usnValue < 0 || nameLength < 0 || nameLength%2 != 0 || nameOffset < usnV2HeaderSize || nameOffset+nameLength > len(raw) {
		return records.USNChangeObservation{}, ErrMalformedUSNBuffer
	}

	fileIdentity := identityFromReference(fileRef)
	parentIdentity := identityFromReference(parentRef)
	fileName := append([]byte(nil), raw[nameOffset:nameOffset+nameLength]...)
	canonicalTimestamp, err := filetimeToCanonical(timestamp)
	if err != nil {
		return records.USNChangeObservation{}, err
	}

	return records.USNChangeObservation{
		MajorVersion:             strconv.FormatUint(uint64(major), 10),
		MinorVersion:             strconv.FormatUint(uint64(minor), 10),
		FileIdentity:             fileIdentity,
		ParentIdentity:           parentIdentity,
		USN:                      strconv.FormatUint(uint64(usnValue), 10),
		Timestamp:                canonicalTimestamp,
		ReasonRaw:                strconv.FormatUint(uint64(reason), 10),
		ReasonNames:              reasonNames(reason),
		SourceInfoRaw:            strconv.FormatUint(uint64(sourceInfo), 10),
		SecurityID:               strconv.FormatUint(uint64(securityID), 10),
		FileAttributesRaw:        strconv.FormatUint(uint64(attributes), 10),
		FileNameUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString(fileName),
	}, nil
}

func identityFromReference(reference uint64) records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: strconv.FormatUint(reference&0x0000FFFFFFFFFFFF, 10),
		SequenceNumber:      strconv.FormatUint(reference>>48, 10),
	}
}

func reasonNames(reason uint32) []string {
	known := []struct {
		mask uint32
		name string
	}{
		{0x00000001, "DataOverwrite"},
		{0x00000002, "DataExtend"},
		{0x00000004, "DataTruncation"},
		{0x00000010, "NamedDataOverwrite"},
		{0x00000020, "NamedDataExtend"},
		{0x00000040, "NamedDataTruncation"},
		{0x00000100, "FileCreate"},
		{0x00000200, "FileDelete"},
		{0x00000400, "EAChange"},
		{0x00000800, "SecurityChange"},
		{0x00001000, "RenameOldName"},
		{0x00002000, "RenameNewName"},
		{0x00004000, "IndexableChange"},
		{0x00008000, "BasicInfoChange"},
		{0x00010000, "HardLinkChange"},
		{0x00020000, "CompressionChange"},
		{0x00040000, "EncryptionChange"},
		{0x00080000, "ObjectIDChange"},
		{0x00100000, "ReparsePointChange"},
		{0x00200000, "StreamChange"},
		{0x00400000, "TransactedChange"},
		{0x00800000, "IntegrityChange"},
		{0x80000000, "Close"},
	}

	names := make([]string, 0, 4)
	for _, item := range known {
		if reason&item.mask != 0 {
			names = append(names, item.name)
		}
	}
	sort.Strings(names)
	return names
}

func parseUSN(value string) (int64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("USN must be canonical unsigned decimal")
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("USN: %w", err)
	}
	return int64(parsed), nil
}

func filetimeToCanonical(value int64) (string, error) {
	if value < 0 {
		return "", errors.New("negative Windows file time")
	}
	const windowsUnixEpochOffsetSeconds int64 = 11644473600
	seconds := value/10_000_000 - windowsUnixEpochOffsetSeconds
	nanoseconds := (value % 10_000_000) * 100
	return time.Unix(seconds, nanoseconds).UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
}

func canonicalNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
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
