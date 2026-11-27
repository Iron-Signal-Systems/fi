// Copyright (c) 2026 John Joseph Wood. All rights reserved.
//go:build freebsd

package transportreceiver

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// recordedStartupCustody verifies the exact immutable FIGT bytes against an
// existing immutable recorder receipt. It never creates a READY hint, cache,
// SQL record, or a new recorded receipt. Missing receipts take the normal full
// trust/semantic recovery path. This fast path avoids decompressing and
// re-materializing historical already-recorded generation caches at startup.
// Historical cache reconstruction remains an explicit, separately verified
// BackfillRecordedGenerationCache operation, never a listener prerequisite.
func recordedStartupCustody(config Config, discovered transportgeneration.DiscoveredCustody,
    offer transportgeneration.Offer) (bool, error) {
    root := config.GenerationRecordedRoot
    if config.GenerationSourceNamespaces {
        sourceRoot, err := generationrecorder.RecordedSourceDirectory(root, offer.Descriptor.SourceID)
        if err != nil { return false, err }
        resolved, err := filepath.EvalSymlinks(sourceRoot)
        if err != nil { return false, fmt.Errorf("FI startup recorded namespace: %w", err) }
        if resolved != sourceRoot { return false, errors.New("FI startup recorded namespace symlink") }
        root = sourceRoot
    }
    receiptPath := filepath.Join(root,
        generationrecorder.RecordedReceiptObjectName(offer.Descriptor.SourceID,
            offer.Descriptor.GenerationID))
    before, err := os.Lstat(receiptPath)
    if errors.Is(err, os.ErrNotExist) { return false, nil }
    if err != nil { return false, fmt.Errorf("inspect startup recorded receipt: %w", err) }
    if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
        before.Mode().Perm() != 0400 || before.Size() <= 0 || before.Size() > 256<<10 {
        return false, errors.New("FI startup recorded receipt has unsafe type/mode/size")
    }
    file, err := os.Open(receiptPath)
    if err != nil { return false, err }
    opened, statErr := file.Stat()
    if statErr != nil || !os.SameFile(before, opened) {
        _ = file.Close()
        return false, errors.New("FI startup recorded receipt changed while opening")
    }
    raw, readErr := io.ReadAll(io.LimitReader(file, 256<<10+1))
    closeErr := file.Close()
    after, afterErr := os.Lstat(receiptPath)
    if readErr != nil || closeErr != nil || afterErr != nil ||
        !os.SameFile(before, after) || int64(len(raw)) != before.Size() {
        return false, errors.New("FI startup recorded receipt changed during read")
    }
    receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
    if err != nil { return false, fmt.Errorf("invalid existing startup recorded receipt: %w", err) }
    if receipt.Descriptor != offer.Descriptor ||
        receipt.MetadataBytes != offer.MetadataBytes ||
        receipt.MetadataSHA256 != offer.MetadataSHA256 ||
        receipt.TransferBytes != discovered.Bytes ||
        filepath.Base(discovered.Path) != transportgeneration.DurableCustodyObjectName(
            offer.Descriptor.SourceID, offer.Descriptor.GenerationID) {
        return false, errors.New("FI startup recorded receipt conflicts with signed custody identity")
    }
    custodyBefore, err := os.Lstat(discovered.Path)
    if err != nil || !custodyBefore.Mode().IsRegular() ||
        custodyBefore.Mode().Perm() != 0400 || custodyBefore.Size() != int64(discovered.Bytes) {
        return false, errors.New("FI startup original signed custody changed or is unsafe")
    }
    custody, err := os.Open(discovered.Path)
    if err != nil { return false, err }
    openedCustody, err := custody.Stat()
    if err != nil || !os.SameFile(custodyBefore, openedCustody) {
        _ = custody.Close()
        return false, errors.New("FI startup custody changed while opening")
    }
    hash := sha256.New()
    count, readErr := io.Copy(hash, custody)
    closeErr = custody.Close()
    custodyAfter, afterErr := os.Lstat(discovered.Path)
    if readErr != nil || closeErr != nil || afterErr != nil ||
        !os.SameFile(custodyBefore, custodyAfter) ||
        custodyAfter.Size() != custodyBefore.Size() || uint64(count) != discovered.Bytes {
        return false, errors.New("FI startup signed custody changed during verification")
    }
    if hex.EncodeToString(hash.Sum(nil)) != receipt.TransferSHA256 {
        return false, errors.New("FI startup signed custody SHA-256 conflicts with durable recorded receipt")
    }
    return true, nil
}
