// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

const (
	MemberIndexVersion      = "fi-recovery-index/0.1"
	maxRecoveryIndexBytes   = uint64(256 << 20)
	maxRecoveryMembers      = uint64(1_000_000)
	maxMemberManifestBytes  = uint64(4 << 20)
	maxSignedStreamingBytes = uint64(1<<63 - 1)
)

// Member binds one original published Phase 1 batch to its exact local source
// artifacts. Path fields are local-only and are not encoded into the wire index.
type Member struct {
	BatchID        string
	RecordCount    uint64
	ManifestBytes  uint64
	ManifestSHA256 string
	DataBytes      uint64
	DataSHA256     string
	ManifestPath   string
	DataPath       string
}

// Index is the exact ordered member set carried in a recovery transaction.
type Index struct {
	Version string
	Members []Member
}

func MemberFromPublishedManifest(manifestPath string) (Member, error) {
	if manifestPath == "" || !filepath.IsAbs(manifestPath) {
		return Member{}, errors.New("published FI manifest path must be absolute")
	}
	initial, err := os.Lstat(manifestPath)
	if err != nil {
		return Member{}, fmt.Errorf("inspect published FI manifest: %w", err)
	}
	if !initial.Mode().IsRegular() || initial.Size() <= 0 || uint64(initial.Size()) > maxMemberManifestBytes {
		return Member{}, errors.New("published FI manifest must be a bounded regular file")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Member{}, fmt.Errorf("read published FI manifest: %w", err)
	}
	after, err := os.Lstat(manifestPath)
	if err != nil || !os.SameFile(initial, after) || after.Size() != initial.Size() {
		return Member{}, errors.New("published FI manifest changed while being read for recovery")
	}
	manifest, err := decodePublishedManifest(raw)
	if err != nil {
		return Member{}, err
	}
	if filepath.Base(manifestPath) != "batch-"+manifest.BatchID+".manifest.json" {
		return Member{}, errors.New("published FI manifest filename does not match batch ID")
	}

	dataPath := filepath.Join(filepath.Dir(manifestPath), manifest.DataFile)
	dataInfo, err := os.Lstat(dataPath)
	if err != nil {
		return Member{}, fmt.Errorf("inspect published FI data for recovery: %w", err)
	}
	if !dataInfo.Mode().IsRegular() || dataInfo.Size() <= 0 || uint64(dataInfo.Size()) != uint64(manifest.DataBytes) {
		return Member{}, errors.New("published FI data size does not match manifest")
	}

	manifestDigest := sha256.Sum256(raw)
	member := Member{
		BatchID:        manifest.BatchID,
		RecordCount:    uint64(manifest.RecordCount),
		ManifestBytes:  uint64(len(raw)),
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		DataBytes:      uint64(manifest.DataBytes),
		DataSHA256:     manifest.DataSHA256,
		ManifestPath:   filepath.Clean(manifestPath),
		DataPath:       filepath.Clean(dataPath),
	}
	if err := member.ValidateWire(); err != nil {
		return Member{}, err
	}
	return member, nil
}

func (member Member) ValidateWire() error {
	if strings.TrimSpace(member.BatchID) == "" || !utf8.ValidString(member.BatchID) || len(member.BatchID) > 4096 || strings.ContainsAny(member.BatchID, "/\\\x00\r\n") {
		return errors.New("recovery member batch ID is invalid")
	}
	if member.RecordCount == 0 {
		return errors.New("recovery member record count must be greater than zero")
	}
	if member.ManifestBytes == 0 || member.ManifestBytes > maxMemberManifestBytes {
		return errors.New("recovery member manifest byte count is outside bounds")
	}
	if member.DataBytes == 0 || member.DataBytes > maxSignedStreamingBytes {
		return errors.New("recovery member data byte count is outside bounds")
	}
	if err := validateSHA256("recovery member manifest SHA-256", member.ManifestSHA256); err != nil {
		return err
	}
	if err := validateSHA256("recovery member data SHA-256", member.DataSHA256); err != nil {
		return err
	}
	return nil
}

func (index Index) Validate() error {
	if index.Version != MemberIndexVersion {
		return fmt.Errorf("recovery index version must be %q", MemberIndexVersion)
	}
	if len(index.Members) == 0 {
		return errors.New("recovery index must contain at least one member")
	}
	if uint64(len(index.Members)) > maxRecoveryMembers {
		return fmt.Errorf("recovery index member count exceeds %d", maxRecoveryMembers)
	}
	last := ""
	seen := make(map[string]struct{}, len(index.Members))
	for position, member := range index.Members {
		if err := member.ValidateWire(); err != nil {
			return fmt.Errorf("validate recovery member %d: %w", position, err)
		}
		if _, exists := seen[member.BatchID]; exists {
			return fmt.Errorf("recovery index contains duplicate batch ID %q", member.BatchID)
		}
		seen[member.BatchID] = struct{}{}
		if last != "" && member.BatchID <= last {
			return errors.New("recovery index members must be strictly oldest-first by batch ID")
		}
		last = member.BatchID
	}
	return nil
}

func (index Index) CanonicalBytes() (uint64, error) {
	if err := index.Validate(); err != nil {
		return 0, err
	}
	var total uint64
	for _, member := range index.Members {
		if member.ManifestBytes > maxSignedStreamingBytes-total {
			return 0, errors.New("recovery canonical byte count overflow")
		}
		total += member.ManifestBytes
		if member.DataBytes > maxSignedStreamingBytes-total {
			return 0, errors.New("recovery canonical byte count overflow")
		}
		total += member.DataBytes
	}
	return total, nil
}

func (index Index) RecordCount() (uint64, error) {
	if err := index.Validate(); err != nil {
		return 0, err
	}
	var total uint64
	for _, member := range index.Members {
		if member.RecordCount > ^uint64(0)-total {
			return 0, errors.New("recovery record count overflow")
		}
		total += member.RecordCount
	}
	return total, nil
}

// MarshalIndex encodes the recovery member set in a deterministic binary form.
// Local paths are intentionally omitted.
func MarshalIndex(index Index) ([]byte, error) {
	if err := index.Validate(); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := writeLPString(&buffer, index.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, uint64(len(index.Members))); err != nil {
		return nil, err
	}
	for _, member := range index.Members {
		if err := writeLPString(&buffer, member.BatchID); err != nil {
			return nil, err
		}
		for _, value := range []uint64{member.RecordCount, member.ManifestBytes, member.DataBytes} {
			if err := binary.Write(&buffer, binary.BigEndian, value); err != nil {
				return nil, err
			}
		}
		manifestDigest, _ := hex.DecodeString(member.ManifestSHA256)
		dataDigest, _ := hex.DecodeString(member.DataSHA256)
		if _, err := buffer.Write(manifestDigest); err != nil {
			return nil, err
		}
		if _, err := buffer.Write(dataDigest); err != nil {
			return nil, err
		}
		if uint64(buffer.Len()) > maxRecoveryIndexBytes {
			return nil, errors.New("recovery member index exceeds maximum encoded size")
		}
	}
	return buffer.Bytes(), nil
}

func UnmarshalIndex(value []byte) (Index, error) {
	if len(value) == 0 || uint64(len(value)) > maxRecoveryIndexBytes {
		return Index{}, errors.New("recovery member index byte count is outside bounds")
	}
	reader := bytes.NewReader(value)
	version, err := readLPString(reader, 256)
	if err != nil {
		return Index{}, fmt.Errorf("read recovery index version: %w", err)
	}
	var count uint64
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return Index{}, fmt.Errorf("read recovery member count: %w", err)
	}
	if count == 0 || count > maxRecoveryMembers {
		return Index{}, errors.New("recovery member count is outside bounds")
	}
	members := make([]Member, 0, int(count))
	for position := uint64(0); position < count; position++ {
		batchID, err := readLPString(reader, 4096)
		if err != nil {
			return Index{}, fmt.Errorf("read recovery member %d batch ID: %w", position, err)
		}
		member := Member{BatchID: batchID}
		for _, destination := range []*uint64{&member.RecordCount, &member.ManifestBytes, &member.DataBytes} {
			if err := binary.Read(reader, binary.BigEndian, destination); err != nil {
				return Index{}, fmt.Errorf("read recovery member %d numeric facts: %w", position, err)
			}
		}
		var manifestDigest [32]byte
		var dataDigest [32]byte
		if _, err := io.ReadFull(reader, manifestDigest[:]); err != nil {
			return Index{}, fmt.Errorf("read recovery member %d manifest digest: %w", position, err)
		}
		if _, err := io.ReadFull(reader, dataDigest[:]); err != nil {
			return Index{}, fmt.Errorf("read recovery member %d data digest: %w", position, err)
		}
		member.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
		member.DataSHA256 = hex.EncodeToString(dataDigest[:])
		members = append(members, member)
	}
	if reader.Len() != 0 {
		return Index{}, errors.New("recovery member index contains trailing bytes")
	}
	index := Index{Version: version, Members: members}
	if err := index.Validate(); err != nil {
		return Index{}, err
	}
	return index, nil
}

func IndexSHA256(indexBytes []byte) (string, error) {
	if len(indexBytes) == 0 || uint64(len(indexBytes)) > maxRecoveryIndexBytes {
		return "", errors.New("recovery member index byte count is outside bounds")
	}
	digest := sha256.Sum256(indexBytes)
	return hex.EncodeToString(digest[:]), nil
}

func MemberFromFrozenManifest(manifestPath string) (Member, error) {
	if manifestPath == "" || !filepath.IsAbs(manifestPath) {
		return Member{}, errors.New(
			"frozen FI manifest path must be absolute",
		)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Member{}, fmt.Errorf(
			"read frozen FI manifest: %w",
			err,
		)
	}

	if len(raw) == 0 || uint64(len(raw)) > maxMemberManifestBytes {
		return Member{}, errors.New(
			"frozen FI manifest size is outside recovery bounds",
		)
	}

	manifest, err := decodePublishedManifest(raw)
	if err != nil {
		return Member{}, err
	}

	if filepath.Base(manifestPath) !=
		"batch-"+manifest.BatchID+".manifest.json" {
		return Member{}, errors.New(
			"frozen FI manifest filename does not match batch ID",
		)
	}

	dataPath := filepath.Join(
		filepath.Dir(manifestPath),
		manifest.DataFile,
	)

	manifestDigest := sha256.Sum256(raw)

	member := Member{
		BatchID:        manifest.BatchID,
		RecordCount:    uint64(manifest.RecordCount),
		ManifestBytes:  uint64(len(raw)),
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		DataBytes:      uint64(manifest.DataBytes),
		DataSHA256:     manifest.DataSHA256,
		ManifestPath:   filepath.Clean(manifestPath),
		DataPath:       filepath.Clean(dataPath),
	}

	if err := member.ValidateWire(); err != nil {
		return Member{}, err
	}

	return member, nil
}

func BuildFrozenIndex(manifestPaths []string) (Index, []byte, error) {
	if len(manifestPaths) == 0 {
		return Index{}, nil, errors.New(
			"at least one frozen manifest is required for FI generation aggregation",
		)
	}

	paths := append(
		[]string(nil),
		manifestPaths...,
	)

	sort.Strings(paths)

	members := make(
		[]Member,
		0,
		len(paths),
	)

	for _, path := range paths {
		member, err := MemberFromFrozenManifest(path)
		if err != nil {
			return Index{}, nil, err
		}

		members = append(
			members,
			member,
		)
	}

	index := Index{
		Version: MemberIndexVersion,
		Members: members,
	}

	encoded, err := MarshalIndex(index)
	if err != nil {
		return Index{}, nil, err
	}

	return index, encoded, nil
}
func BuildIndex(manifestPaths []string) (Index, []byte, error) {
	if len(manifestPaths) == 0 {
		return Index{}, nil, errors.New("at least one published manifest is required for FI transport aggregation")
	}
	paths := append([]string(nil), manifestPaths...)
	sort.Strings(paths)
	members := make([]Member, 0, len(paths))
	for _, path := range paths {
		member, err := MemberFromPublishedManifest(path)
		if err != nil {
			return Index{}, nil, err
		}
		members = append(members, member)
	}
	index := Index{Version: MemberIndexVersion, Members: members}
	encoded, err := MarshalIndex(index)
	if err != nil {
		return Index{}, nil, err
	}
	return index, encoded, nil
}

// ValidateManifestBytes performs receiver-side structural checks against the
// exact manifest bytes carried inside a recovery bundle. The exact byte hash is
// already bound by the signed recovery index; this function verifies the
// semantic fields needed to bind the following JSONL payload.
func ValidateManifestBytes(raw []byte, member Member) (spool.Manifest, error) {
	if uint64(len(raw)) != member.ManifestBytes {
		return spool.Manifest{}, errors.New("recovery manifest byte count mismatch")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != member.ManifestSHA256 {
		return spool.Manifest{}, errors.New("recovery manifest SHA-256 mismatch")
	}
	manifest, err := decodePublishedManifest(raw)
	if err != nil {
		return spool.Manifest{}, err
	}
	if manifest.BatchID != member.BatchID || uint64(manifest.RecordCount) != member.RecordCount || uint64(manifest.DataBytes) != member.DataBytes || manifest.DataSHA256 != member.DataSHA256 {
		return spool.Manifest{}, errors.New("recovery member manifest facts do not match signed index")
	}
	return manifest, nil
}

func decodePublishedManifest(raw []byte) (spool.Manifest, error) {
	if len(raw) == 0 || uint64(len(raw)) > maxMemberManifestBytes {
		return spool.Manifest{}, errors.New("published FI manifest size is outside recovery bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest spool.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return spool.Manifest{}, fmt.Errorf("decode FI published manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return spool.Manifest{}, errors.New("FI published manifest contains trailing JSON")
	}
	if manifest.Version != spool.ManifestVersion || strings.TrimSpace(manifest.BatchID) == "" || strings.ContainsAny(manifest.BatchID, "/\\\x00\r\n") {
		return spool.Manifest{}, errors.New("FI published manifest identity is invalid")
	}
	if manifest.TargetBatchSize <= 0 || manifest.RecordCount <= 0 || manifest.RecordCount > manifest.TargetBatchSize {
		return spool.Manifest{}, errors.New("FI published manifest record counts are invalid")
	}
	if manifest.DataBytes <= 0 || uint64(manifest.DataBytes) > maxSignedStreamingBytes || !isSHA256(manifest.DataSHA256) {
		return spool.Manifest{}, errors.New("FI published manifest data facts are invalid")
	}
	if manifest.DataFile != "batch-"+manifest.BatchID+".jsonl" || filepath.Base(manifest.DataFile) != manifest.DataFile || strings.ContainsAny(manifest.DataFile, `/\\`) {
		return spool.Manifest{}, errors.New("FI published manifest data filename is invalid")
	}
	if manifest.Collector.ExecutablePath == "" || !isSHA256(manifest.Collector.ExecutableSHA256) || manifest.CreatedAt == "" || manifest.CompletedAt == "" {
		return spool.Manifest{}, errors.New("FI published manifest metadata is invalid")
	}
	return manifest, nil
}

func isSHA256(value string) bool {
	return validateSHA256("SHA-256", value) == nil
}

func writeLPString(writer io.Writer, value string) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("length-prefixed string exceeds uint32")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	_, err := io.WriteString(writer, value)
	return err
}

func readLPString(reader io.Reader, maximum uint32) (string, error) {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return "", err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maximum {
		return "", errors.New("length-prefixed string size is outside bounds")
	}
	value := make([]byte, int(size))
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", errors.New("length-prefixed string is not valid UTF-8")
	}
	if strings.ContainsRune(string(value), '\x00') {
		return "", errors.New("length-prefixed string contains NUL")
	}
	return string(value), nil
}
