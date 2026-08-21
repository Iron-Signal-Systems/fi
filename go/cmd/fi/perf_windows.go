// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	winprocess "github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
)

const performanceReportVersion = "fi-performance/0.1"

type performanceReport struct {
	ReportVersion         string                 `json:"report_version"`
	RunState              string                 `json:"run_state"`
	ResourceObservation   string                 `json:"resource_observation"`
	PerformanceThresholds string                 `json:"performance_thresholds"`
	Root                  performanceRoot        `json:"root"`
	Environment           performanceEnvironment `json:"environment"`
	Timing                performanceTiming      `json:"timing"`
	Collection            performanceCollection  `json:"collection"`
	Process               performanceProcess     `json:"process"`
	GoRuntime             performanceGoRuntime   `json:"go_runtime"`
	ResourceErrors        []string               `json:"resource_errors,omitempty"`
	FatalError            string                 `json:"fatal_error,omitempty"`
}

type performanceRoot struct {
	PathDisplay          string `json:"path_display"`
	PathUTF16LEBase64URL string `json:"path_utf16le_base64url"`
	VolumeGUID           string `json:"volume_guid,omitempty"`
	VolumeSerial         string `json:"volume_serial,omitempty"`
	FileReferenceNumber  string `json:"file_reference_number,omitempty"`
	SequenceNumber       string `json:"sequence_number,omitempty"`
}

type performanceEnvironment struct {
	Hostname    string `json:"hostname,omitempty"`
	Windows     string `json:"windows_version,omitempty"`
	GoVersion   string `json:"go_version"`
	GOARCH      string `json:"goarch"`
	LogicalCPUs int    `json:"logical_cpus"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSTime     string `json:"vcs_time,omitempty"`
	VCSModified string `json:"vcs_modified,omitempty"`
}

type performanceTiming struct {
	StartedAt        string  `json:"started_at"`
	CompletedAt      string  `json:"completed_at"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	ObjectsPerSecond float64 `json:"objects_per_second"`
	FilesPerSecond   float64 `json:"files_per_second"`
}

type performanceCollection struct {
	Observations             uint64            `json:"observations"`
	Files                    uint64            `json:"files"`
	Directories              uint64            `json:"directories"`
	ReparseObjects           uint64            `json:"reparse_objects"`
	DefaultDataStreams       uint64            `json:"default_data_streams"`
	NamedDataStreams         uint64            `json:"named_data_streams"`
	OtherStreams             uint64            `json:"other_streams"`
	Warnings                 uint64            `json:"warnings"`
	ObjectErrors             uint64            `json:"object_errors"`
	Complete                 uint64            `json:"complete"`
	Partial                  uint64            `json:"partial"`
	ChangedDuringCollection  uint64            `json:"changed_during_collection"`
	ReplacedDuringCollection uint64            `json:"replaced_during_collection"`
	WarningCodes             map[string]uint64 `json:"warning_codes,omitempty"`
	ErrorStages              map[string]uint64 `json:"error_stages,omitempty"`
}

type performanceProcess struct {
	CPUSeconds          float64 `json:"cpu_seconds"`
	WorkingSetBytes     uint64  `json:"working_set_bytes"`
	PeakWorkingSetBytes uint64  `json:"peak_working_set_bytes"`
	PrivateBytes        uint64  `json:"private_bytes"`
}

type performanceGoRuntime struct {
	HeapAllocStartBytes  uint64 `json:"heap_alloc_start_bytes"`
	HeapAllocEndBytes    uint64 `json:"heap_alloc_end_bytes"`
	HeapInUseEndBytes    uint64 `json:"heap_in_use_end_bytes"`
	TotalAllocDeltaBytes uint64 `json:"total_alloc_delta_bytes"`
	MallocsDelta         uint64 `json:"mallocs_delta"`
	FreesDelta           uint64 `json:"frees_delta"`
	NumGCDelta           uint32 `json:"num_gc_delta"`
	GoroutinesStart      int    `json:"goroutines_start"`
	GoroutinesEnd        int    `json:"goroutines_end"`
}

func runPerformance(governedRoot string) {
	report, runErr := measurePerformance(context.Background(), governedRoot)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	if runErr != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", runErr)
		os.Exit(1)
	}
}

func measurePerformance(ctx context.Context, governedRoot string) (performanceReport, error) {
	exactRoot, err := pathUTF16LEBase64URL(governedRoot)
	if err != nil {
		return performanceReport{}, err
	}

	report := performanceReport{
		ReportVersion:         performanceReportVersion,
		RunState:              "COMPLETE",
		ResourceObservation:   "RECORDED",
		PerformanceThresholds: "NOT_EVALUATED",
		Root: performanceRoot{
			PathDisplay:          governedRoot,
			PathUTF16LEBase64URL: exactRoot,
		},
		Environment: performanceEnvironment{
			GoVersion:   runtime.Version(),
			GOARCH:      runtime.GOARCH,
			LogicalCPUs: runtime.NumCPU(),
		},
		Collection: performanceCollection{
			WarningCodes: map[string]uint64{},
			ErrorStages:  map[string]uint64{},
		},
		ResourceErrors: []string{},
	}

	if hostname, hostnameErr := os.Hostname(); hostnameErr == nil {
		report.Environment.Hostname = hostname
	} else {
		report.ResourceErrors = append(report.ResourceErrors, "hostname: "+hostnameErr.Error())
	}
	if version, versionErr := winprocess.WindowsVersion(); versionErr == nil {
		report.Environment.Windows = version
	} else {
		report.ResourceErrors = append(report.ResourceErrors, "windows version: "+versionErr.Error())
	}
	readBuildEnvironment(&report.Environment)

	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)
	report.GoRuntime.HeapAllocStartBytes = memStart.HeapAlloc
	report.GoRuntime.GoroutinesStart = runtime.NumGoroutine()

	processStart, processStartErr := winprocess.Current()
	if processStartErr != nil {
		report.ResourceErrors = append(report.ResourceErrors, "process start: "+processStartErr.Error())
	}

	started := time.Now()
	report.Timing.StartedAt = started.UTC().Format("2006-01-02T15:04:05.000000000Z")

	walkErr := ntfs.WalkGovernedRoot(
		ctx,
		"performance-measurement",
		governedRoot,
		func(_ string, observation ntfs.Observation, objectErr error) error {
			if objectErr != nil {
				report.Collection.ObjectErrors++
				addErrorStage(report.Collection.ErrorStages, objectErr)
				return nil
			}
			if observation.ObservedAt == "" {
				return nil
			}
			addPerformanceObservation(&report, observation)
			return nil
		},
	)

	completed := time.Now()
	report.Timing.CompletedAt = completed.UTC().Format("2006-01-02T15:04:05.000000000Z")
	elapsed := completed.Sub(started)
	report.Timing.ElapsedSeconds = elapsed.Seconds()
	if elapsed > 0 {
		report.Timing.ObjectsPerSecond = float64(report.Collection.Observations) / elapsed.Seconds()
		report.Timing.FilesPerSecond = float64(report.Collection.Files) / elapsed.Seconds()
	}

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)
	report.GoRuntime.HeapAllocEndBytes = memEnd.HeapAlloc
	report.GoRuntime.HeapInUseEndBytes = memEnd.HeapInuse
	report.GoRuntime.TotalAllocDeltaBytes = unsignedDelta(memEnd.TotalAlloc, memStart.TotalAlloc)
	report.GoRuntime.MallocsDelta = unsignedDelta(memEnd.Mallocs, memStart.Mallocs)
	report.GoRuntime.FreesDelta = unsignedDelta(memEnd.Frees, memStart.Frees)
	if memEnd.NumGC >= memStart.NumGC {
		report.GoRuntime.NumGCDelta = memEnd.NumGC - memStart.NumGC
	}
	report.GoRuntime.GoroutinesEnd = runtime.NumGoroutine()

	processEnd, processEndErr := winprocess.Current()
	if processEndErr != nil {
		report.ResourceErrors = append(report.ResourceErrors, "process end: "+processEndErr.Error())
	} else {
		report.Process.WorkingSetBytes = processEnd.WorkingSetBytes
		report.Process.PeakWorkingSetBytes = processEnd.PeakWorkingSetBytes
		report.Process.PrivateBytes = processEnd.PrivateBytes
		if processStartErr == nil && processEnd.CPU100Nanoseconds >= processStart.CPU100Nanoseconds {
			report.Process.CPUSeconds = float64(processEnd.CPU100Nanoseconds-processStart.CPU100Nanoseconds) / 10_000_000
		}
	}

	if len(report.ResourceErrors) != 0 {
		report.ResourceObservation = "PARTIAL"
	}
	if walkErr != nil {
		report.RunState = "FAILED"
		report.FatalError = walkErr.Error()
		addErrorStage(report.Collection.ErrorStages, walkErr)
	}

	return report, walkErr
}

func addPerformanceObservation(report *performanceReport, observation ntfs.Observation) {
	collection := &report.Collection
	collection.Observations++

	if report.Root.VolumeGUID == "" {
		report.Root.VolumeGUID = observation.GovernedRoot.VolumeIdentity.VolumeGUID
		report.Root.VolumeSerial = observation.GovernedRoot.VolumeIdentity.VolumeSerial
		report.Root.FileReferenceNumber = observation.GovernedRoot.ObjectIdentity.FileReferenceNumber
		report.Root.SequenceNumber = observation.GovernedRoot.ObjectIdentity.SequenceNumber
	}

	switch observation.SubjectKind {
	case records.SubjectFile:
		collection.Files++
	case records.SubjectDirectory:
		collection.Directories++
	}

	if observation.Reparse.State == records.ReparseStatePresent {
		collection.ReparseObjects++
	}

	for _, stream := range observation.StreamInventory.Streams {
		switch stream.Identity.Kind {
		case records.StreamDefaultData:
			collection.DefaultDataStreams++
		case records.StreamNamedData:
			collection.NamedDataStreams++
		case records.StreamOther:
			collection.OtherStreams++
		}
	}

	switch observation.ObservationStatus {
	case records.ObservationComplete:
		collection.Complete++
	case records.ObservationPartial:
		collection.Partial++
	case records.ObservationChangedDuringCollection:
		collection.ChangedDuringCollection++
	case records.ObservationReplacedDuringCollection:
		collection.ReplacedDuringCollection++
	}

	collection.Warnings += uint64(len(observation.Warnings))
	for _, warning := range observation.Warnings {
		collection.WarningCodes[warning.Code]++
	}
}

func addErrorStage(stages map[string]uint64, err error) {
	var collectionErr *ntfs.Error
	if errors.As(err, &collectionErr) {
		stages[string(collectionErr.Stage)]++
		return
	}
	stages["Walk"]++
}

func readBuildEnvironment(environment *performanceEnvironment) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			environment.VCSRevision = setting.Value
		case "vcs.time":
			environment.VCSTime = setting.Value
		case "vcs.modified":
			environment.VCSModified = setting.Value
		}
	}
}

func unsignedDelta(end, start uint64) uint64 {
	if end < start {
		return 0
	}
	return end - start
}
