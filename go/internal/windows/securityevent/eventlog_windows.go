// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	securityChannel          = "Security"
	evtOpenChannelPath       = 0x00000001
	evtQueryChannelPath      = 0x00000001
	evtQueryForwardDirection = 0x00000100
	evtRenderEventXML        = 1
	evtLogNumberOfLogRecords = 5
	evtLogOldestRecordNumber = 6
	errorInsufficientBuffer  = syscall.Errno(122)
	errorNoMoreItems         = syscall.Errno(259)

	// MaxReadRecordIDSpan bounds one Windows Security query by EventRecordID
	// distance. Configured catch-up advances through repeated verified windows so
	// a large backlog cannot require one unbounded in-memory event slice.
	MaxReadRecordIDSpan uint64 = 10000
)

var (
	wevtapi           = syscall.NewLazyDLL("wevtapi.dll")
	procEvtOpenLog    = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo = wevtapi.NewProc("EvtGetLogInfo")
	procEvtQuery      = wevtapi.NewProc("EvtQuery")
	procEvtNext       = wevtapi.NewProc("EvtNext")
	procEvtRender     = wevtapi.NewProc("EvtRender")
	procEvtClose      = wevtapi.NewProc("EvtClose")
)

type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

var (
	_ [16 - unsafe.Sizeof(evtVariant{})]byte
	_ [unsafe.Sizeof(evtVariant{}) - 16]byte
)

type LogState struct {
	ObservedAt          string `json:"observed_at"`
	Channel             string `json:"channel"`
	NumberOfRecords     string `json:"number_of_records"`
	OldestEventRecordID string `json:"oldest_event_record_id"`
	NewestEventRecordID string `json:"newest_event_record_id"`
}

func QueryLogState() (LogState, error) {
	channel, err := syscall.UTF16PtrFromString(securityChannel)
	if err != nil {
		return LogState{}, err
	}
	handle, _, callErr := procEvtOpenLog.Call(0, uintptr(unsafe.Pointer(channel)), evtOpenChannelPath)
	if handle == 0 {
		return LogState{}, windowsCallError("EvtOpenLog(Security)", callErr)
	}
	defer procEvtClose.Call(handle)

	count, err := evtLogUInt64(handle, evtLogNumberOfLogRecords)
	if err != nil {
		return LogState{}, err
	}
	oldest, err := evtLogUInt64(handle, evtLogOldestRecordNumber)
	if err != nil {
		return LogState{}, err
	}
	newest := uint64(0)
	if count > 0 {
		newest = oldest + count - 1
	}
	return LogState{
		ObservedAt:          formatCanonicalTime(time.Now()),
		Channel:             securityChannel,
		NumberOfRecords:     strconv.FormatUint(count, 10),
		OldestEventRecordID: strconv.FormatUint(oldest, 10),
		NewestEventRecordID: strconv.FormatUint(newest, 10),
	}, nil
}

func evtLogUInt64(handle uintptr, property uintptr) (uint64, error) {
	var value evtVariant
	var used uint32
	r1, _, callErr := procEvtGetLogInfo.Call(
		handle,
		property,
		unsafe.Sizeof(value),
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Pointer(&used)),
	)
	if r1 == 0 {
		return 0, windowsCallError("EvtGetLogInfo", callErr)
	}
	return value.Value, nil
}

func ReadSelectedEvents(startAfterRecordID, throughRecordID uint64) ([]records.WindowsSecurityEventObservation, error) {
	if startAfterRecordID >= throughRecordID {
		return []records.WindowsSecurityEventObservation{}, nil
	}
	span := throughRecordID - startAfterRecordID
	if span > MaxReadRecordIDSpan {
		return nil, fmt.Errorf(
			"Windows Security read range exceeds bounded EventRecordID span: %d > %d",
			span,
			MaxReadRecordIDSpan,
		)
	}

	channel, err := syscall.UTF16PtrFromString(securityChannel)
	if err != nil {
		return nil, err
	}
	queryText := fmt.Sprintf(
		"*[System[(EventRecordID > %d and EventRecordID <= %d) and (EventID=4656 or EventID=4663 or EventID=4660 or EventID=4664 or EventID=4670 or EventID=4907 or EventID=5145 or EventID=1102 or EventID=4719)]]",
		startAfterRecordID,
		throughRecordID,
	)
	query, err := syscall.UTF16PtrFromString(queryText)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		evtQueryChannelPath|evtQueryForwardDirection,
	)
	if handle == 0 {
		return nil, windowsCallError("EvtQuery(Security)", callErr)
	}
	defer procEvtClose.Call(handle)

	result := []records.WindowsSecurityEventObservation{}
	for {
		var events [16]uintptr
		var returned uint32
		r1, _, nextErr := procEvtNext.Call(
			handle,
			uintptr(len(events)),
			uintptr(unsafe.Pointer(&events[0])),
			0,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r1 == 0 {
			if errors.Is(nextErr, errorNoMoreItems) {
				break
			}
			return nil, windowsCallError("EvtNext", nextErr)
		}
		for index := uint32(0); index < returned; index++ {
			eventHandle := events[index]
			rawXML, err := renderEventXML(eventHandle)
			procEvtClose.Call(eventHandle)
			if err != nil {
				return nil, err
			}
			value, err := ParseEvent(rawXML, time.Now())
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
	}
	return result, nil
}

func renderEventXML(handle uintptr) (string, error) {
	var used uint32
	var properties uint32
	r1, _, callErr := procEvtRender.Call(0, handle, evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if r1 != 0 || !errors.Is(callErr, errorInsufficientBuffer) {
		if r1 == 0 {
			return "", windowsCallError("EvtRender(size)", callErr)
		}
	}
	if used < 2 {
		return "", errors.New("EvtRender returned empty XML size")
	}
	buffer := make([]uint16, (used+1)/2)
	r1, _, callErr = procEvtRender.Call(
		0,
		handle,
		evtRenderEventXML,
		uintptr(len(buffer)*2),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&properties)),
	)
	if r1 == 0 {
		return "", windowsCallError("EvtRender(XML)", callErr)
	}
	return strings.TrimSuffix(syscall.UTF16ToString(buffer), "\x00"), nil
}

func windowsCallError(operation string, callErr error) error {
	if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
		return fmt.Errorf("%s: %w", operation, callErr)
	}
	return fmt.Errorf("%s failed", operation)
}
