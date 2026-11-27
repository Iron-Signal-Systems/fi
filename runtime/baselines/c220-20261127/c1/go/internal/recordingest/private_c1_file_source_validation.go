//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// Only fully validated source observations can receive this proof. The
// regular ingest path never fabricates a reuse marker from a row counter.
func validateSourceFileObservation(value ntfs.Observation) (*validatedSourceFileObservation,error) {
    if err:=ntfs.ValidateObservation(value);err!=nil{
        return nil,fmt.Errorf("C1 original source validation: %w",err)
    }
    return &validatedSourceFileObservation{observation:value},nil
}

// Bind one original source validation proof to its exact signed SQL identity.
// The normal File bulk projector consumes the same validated observation.
func fileBulkRecordFromValidatedSource(
    sourceID string,sourceRecordID,ordinal int64,
    proof *validatedSourceFileObservation,
    hashes *records.ContentHashObservation,recordBytes int64,
)(fileObservationBulkRecord,error){
    if sourceID==""||sourceRecordID<=0||ordinal<=0||proof==nil||recordBytes<=0 {
        return fileObservationBulkRecord{},errors.New("FI C1 File: original signed identity and validated source required")
    }
    return fileObservationBulkRecord{
        sourceID:sourceID,sourceRecordID:sourceRecordID,ordinal:ordinal,
        value:proof.observation,hashes:hashes,bytes:recordBytes,
        validatedSource:proof,
    },nil
}
