// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

const (
	generationSourceCustodyDirectory          = ".fi-generation-source-custody"
	generationSourceCustodyVersion            = "fi-generation-source-custody/1"
	maximumGenerationSourceCustodyBytes int64 = 32 << 20
)

var ErrGenerationSourceCustodyConflict = errors.New(
	"FI generation source custody receipt conflicts with recorded identity",
)

// GenerationSourceCustodyReceipt records one independently verified
// source-to-sealed-generation relationship.
//
// Its SHA-256 detects local damage. It is not a signature, PKI authorization,
// receiver acknowledgement, or permission to delete original source bytes.
//
// The source and ledger hashes are sorted sets, as in the verified preflight.
type GenerationSourceCustodyReceipt struct {
	Version              string   `json:"version"`
	GenerationID         string   `json:"generation_id"`
	SourceID             string   `json:"source_id"`
	SignedMetadataSHA256 string   `json:"signed_metadata_sha256"`
	CanonicalSHA256      string   `json:"canonical_sha256"`
	EncodedSHA256        string   `json:"encoded_sha256"`
	SourceBatchSHA256    []string `json:"source_batch_sha256"`
	SourceLedgerSHA256   []string `json:"source_ledger_sha256"`
	SHA256               string   `json:"sha256"`
}

// generationSourceCustodyPath maps private and promoted sealed generations
// onto the same sender-side custody receipt. It never infers collector state
// from the spool directory.
func generationSourceCustodyPath(
	sealedDir, generationID string,
) (string, error) {
	if !filepath.IsAbs(sealedDir) ||
		generationID == "" ||
		len(generationID) > 128 ||
		strings.ContainsAny(generationID, `\/:`) ||
		filepath.Base(filepath.Clean(sealedDir)) !=
			generationDirectoryPrefix+generationID {
		return "", fmt.Errorf(
			"%w: invalid FI generation source custody path",
			ErrGenerationSourceCustodyConflict,
		)
	}

	info, err := os.Lstat(sealedDir)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New(
			"FI sealed generation custody path is not a real directory",
		)
	}

	parent := filepath.Dir(filepath.Clean(sealedDir))
	stageRoot := parent

	if filepath.Base(parent) == generationTransportBuildRootDirectoryName {
		parentInfo, err := os.Lstat(parent)
		if err != nil {
			return "", err
		}
		if parentInfo.Mode()&os.ModeSymlink != 0 ||
			!parentInfo.IsDir() {
			return "", errors.New(
				"FI private generation build root is not a real directory",
			)
		}
		stageRoot = filepath.Dir(parent)
	}

	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return "", err
	}

	return filepath.Join(
		stageRoot,
		generationSourceCustodyDirectory,
		generationDirectoryPrefix+generationID+".json",
	), nil
}

// readSourceCustodyReceipt checks a bounded, regular, identity-stable file.
//
// An absent receipt permits only a first publication. Malformed, oversized,
// changed, or noncanonical receipts are never treated as absent.
func readSourceCustodyReceipt(
	path string,
) (GenerationSourceCustodyReceipt, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return GenerationSourceCustodyReceipt{}, false, nil
	}
	if err != nil {
		return GenerationSourceCustodyReceipt{}, false, err
	}

	if !before.Mode().IsRegular() ||
		before.Size() <= 0 ||
		before.Size() > maximumGenerationSourceCustodyBytes {
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: invalid custody receipt file",
			ErrGenerationSourceCustodyConflict,
		)
	}

	file, err := os.Open(path)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, false, err
	}

	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: custody receipt changed while opening: %v",
			ErrGenerationSourceCustodyConflict,
			err,
		)
	}

	bytesRead, readErr := io.ReadAll(
		io.LimitReader(file, maximumGenerationSourceCustodyBytes+1),
	)
	closeErr := file.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return GenerationSourceCustodyReceipt{}, false, err
	}

	after, err := os.Lstat(path)
	if err != nil ||
		!os.SameFile(opened, after) ||
		opened.Size() != after.Size() ||
		int64(len(bytesRead)) != before.Size() {
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: custody receipt changed while reading: %v",
			ErrGenerationSourceCustodyConflict,
			err,
		)
	}

	var value GenerationSourceCustodyReceipt

	decoder := json.NewDecoder(bytes.NewReader(bytesRead))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&value); err != nil {
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: malformed custody receipt: %v",
			ErrGenerationSourceCustodyConflict,
			err,
		)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: trailing custody receipt data",
			ErrGenerationSourceCustodyConflict,
		)
	}

	if err := validateSourceCustodyReceipt(value); err != nil {
		return GenerationSourceCustodyReceipt{}, false, err
	}

	canonical, err := json.Marshal(value)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, false, err
	}
	if !bytes.Equal(bytesRead, canonical) {
		return GenerationSourceCustodyReceipt{}, false, fmt.Errorf(
			"%w: noncanonical custody receipt encoding",
			ErrGenerationSourceCustodyConflict,
		)
	}

	return value, true, nil
}

// recordVerifiedGenerationCustody persists one fully verified source-to-sealed
// relationship in the sender's private stage namespace.
//
// Only the successful committed-generation preflight may call this function.
// File publication is atomic. Identical replay is accepted; conflicting replay
// fails closed. The original frozen source is never deleted here.
func recordVerifiedGenerationCustody(
	sealedDir string,
	proof usncapture.CommittedGenerationPreflight,
) (GenerationSourceCustodyReceipt, error) {
	path, err := generationSourceCustodyPath(
		sealedDir,
		proof.GenerationID,
	)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}

	value := GenerationSourceCustodyReceipt{
		Version:              generationSourceCustodyVersion,
		GenerationID:         proof.GenerationID,
		SourceID:             proof.SourceID,
		SignedMetadataSHA256: proof.SignedMetadataSHA256,
		CanonicalSHA256:      proof.CanonicalSHA256,
		EncodedSHA256:        proof.EncodedSHA256,
		SourceBatchSHA256:    append([]string(nil), proof.SourceBatchSHA256...),
		SourceLedgerSHA256:   append([]string(nil), proof.SourceLedgerSHA256...),
	}

	value.SHA256, err = sourceCustodyReceiptHash(value)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}
	if err := validateSourceCustodyReceipt(value); err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}
	if len(encoded) > int(maximumGenerationSourceCustodyBytes) {
		return GenerationSourceCustodyReceipt{}, fmt.Errorf(
			"%w: FI source custody receipt exceeds byte ceiling",
			ErrGenerationSourceCustodyConflict,
		)
	}

	root := filepath.Dir(path)

	if err := os.Mkdir(root, 0o700); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return GenerationSourceCustodyReceipt{}, err
	}

	info, err := os.Lstat(root)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return GenerationSourceCustodyReceipt{}, fmt.Errorf(
			"%w: custody receipt directory is not a real directory",
			ErrGenerationSourceCustodyConflict,
		)
	}

	prior, found, err := readSourceCustodyReceipt(path)
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}
	if found {
		if !reflect.DeepEqual(prior, value) {
			return GenerationSourceCustodyReceipt{},
				ErrGenerationSourceCustodyConflict
		}
		return prior, nil
	}

	file, err := os.CreateTemp(root, ".fi-custody-*.tmp")
	if err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}
	defer func() {
		_ = os.Remove(file.Name())
	}()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return GenerationSourceCustodyReceipt{}, err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return GenerationSourceCustodyReceipt{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return GenerationSourceCustodyReceipt{}, err
	}
	if err := file.Close(); err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}

	if _, exists, err := readSourceCustodyReceipt(path); err != nil ||
		exists {
		return GenerationSourceCustodyReceipt{}, fmt.Errorf(
			"%w: custody receipt was created concurrently: %v",
			ErrGenerationSourceCustodyConflict,
			err,
		)
	}

	if err := publishGenerationDirectory(file.Name(), path); err != nil {
		return GenerationSourceCustodyReceipt{}, err
	}

	stored, found, err := readSourceCustodyReceipt(path)
	if err != nil || !found || !reflect.DeepEqual(stored, value) {
		return GenerationSourceCustodyReceipt{}, fmt.Errorf(
			"%w: published custody receipt did not verify: %v",
			ErrGenerationSourceCustodyConflict,
			err,
		)
	}

	return stored, nil
}

// sourceCustodyReceiptHash hashes every field except the self-check digest.
func sourceCustodyReceiptHash(
	value GenerationSourceCustodyReceipt,
) (string, error) {
	value.SHA256 = ""

	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validSourceCustodyDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		hex.EncodeToString(decoded) == value
}

func validSourceCustodySet(values []string) bool {
	if len(values) == 0 || len(values) > 131072 {
		return false
	}

	previous := ""
	for _, value := range values {
		if !validSourceCustodyDigest(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validateSourceCustodyReceipt(
	value GenerationSourceCustodyReceipt,
) error {
	if value.Version != generationSourceCustodyVersion ||
		value.GenerationID == "" ||
		len(value.GenerationID) > 128 ||
		strings.ContainsAny(value.GenerationID, `\/:`) ||
		strings.TrimSpace(value.SourceID) == "" ||
		strings.ContainsAny(value.SourceID, `\/`) ||
		!validSourceCustodyDigest(value.SignedMetadataSHA256) ||
		!validSourceCustodyDigest(value.CanonicalSHA256) ||
		!validSourceCustodyDigest(value.EncodedSHA256) ||
		!validSourceCustodySet(value.SourceBatchSHA256) ||
		!validSourceCustodySet(value.SourceLedgerSHA256) ||
		len(value.SourceBatchSHA256) != len(value.SourceLedgerSHA256) {
		return fmt.Errorf(
			"%w: invalid committed-generation receipt fields",
			ErrGenerationSourceCustodyConflict,
		)
	}

	hash, err := sourceCustodyReceiptHash(value)
	if err != nil {
		return err
	}
	if value.SHA256 != hash {
		return fmt.Errorf(
			"%w: committed-generation receipt digest differs",
			ErrGenerationSourceCustodyConflict,
		)
	}

	return nil
}
