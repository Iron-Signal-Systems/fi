// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
)

// RecoveryPlan is untrusted planning state used only to negotiate receiver
// limits. Exact custody facts are constructed later from fully verified members.
type RecoveryPlan struct {
	PendingCanonicalBytes uint64
	PendingMembers        uint64
	OldestBatchID         string
	NewestBatchID         string
	ProposedMembers       uint64
	ManifestPaths         []string
}

type RecoveryAuthorization struct {
	acknowledgement transportrecovery.Acknowledgement
}

type RecoveryRetirementResult struct {
	Members          uint64
	ManifestsRemoved uint64
	DataRemoved      uint64
}

func PlanRecovery(queue *PublishedBatchQueue) (RecoveryPlan, error) {
	if queue == nil {
		return RecoveryPlan{}, errors.New("FI published-batch queue is required")
	}
	if err := validateRecoverySpoolDir(queue.spoolDir); err != nil {
		return RecoveryPlan{}, err
	}
	if len(queue.manifestPaths) == 0 {
		paths, err := scanPublishedBatchManifests(queue.spoolDir)
		if err != nil {
			return RecoveryPlan{}, err
		}
		queue.manifestPaths = paths
	}
	if len(queue.manifestPaths) < 2 {
		return RecoveryPlan{}, nil
	}

	paths := append([]string(nil), queue.manifestPaths...)
	var total uint64
	var oldest string
	var newest string
	for position, path := range paths {
		batchID, canonicalBytes, err := inspectPlanningManifest(path)
		if err != nil {
			return RecoveryPlan{}, fmt.Errorf("inspect FI recovery planning manifest %q: %w", path, err)
		}
		if canonicalBytes > ^uint64(0)-total {
			return RecoveryPlan{}, errors.New("FI recovery planning byte count overflow")
		}
		total += canonicalBytes
		if position == 0 {
			oldest = batchID
		}
		newest = batchID
	}
	proposed := uint64(len(paths)) / 2
	if proposed < 2 {
		return RecoveryPlan{}, nil
	}
	return RecoveryPlan{
		PendingCanonicalBytes: total,
		PendingMembers:        uint64(len(paths)),
		OldestBatchID:         oldest,
		NewestBatchID:         newest,
		ProposedMembers:       proposed,
		ManifestPaths:         paths,
	}, nil
}

func SelectRecoveryIndex(plan RecoveryPlan, maxMembers, maxCanonicalBytes uint64) (transportrecovery.Index, error) {
	if plan.PendingMembers < 2 || plan.ProposedMembers < 2 || len(plan.ManifestPaths) < 2 {
		return transportrecovery.Index{}, errors.New("FI recovery plan does not contain enough members")
	}
	if maxMembers < 2 || maxCanonicalBytes == 0 {
		return transportrecovery.Index{}, errors.New("FI recovery receiver limits do not permit aggregation")
	}
	target := plan.ProposedMembers
	if target > maxMembers {
		target = maxMembers
	}
	if target > uint64(len(plan.ManifestPaths)) {
		target = uint64(len(plan.ManifestPaths))
	}

	members := make([]transportrecovery.Member, 0, int(target))
	var canonical uint64
	for _, path := range plan.ManifestPaths[:int(target)] {
		member, err := transportrecovery.MemberFromPublishedManifest(path)
		if err != nil {
			return transportrecovery.Index{}, err
		}
		memberBytes := member.ManifestBytes + member.DataBytes
		if memberBytes > maxCanonicalBytes-canonical {
			break
		}
		canonical += memberBytes
		members = append(members, member)
	}
	if len(members) < 2 {
		return transportrecovery.Index{}, errors.New("FI recovery negotiated limits fit fewer than two oldest members")
	}
	index := transportrecovery.Index{Version: transportrecovery.MemberIndexVersion, Members: members}
	if err := index.Validate(); err != nil {
		return transportrecovery.Index{}, err
	}
	return index, nil
}

func HalveRecoveryIndex(index transportrecovery.Index) (transportrecovery.Index, bool) {
	if len(index.Members) <= 2 {
		return transportrecovery.Index{}, false
	}
	next := len(index.Members) / 2
	if next < 2 {
		next = 2
	}
	members := append([]transportrecovery.Member(nil), index.Members[:next]...)
	return transportrecovery.Index{Version: transportrecovery.MemberIndexVersion, Members: members}, true
}

func VerifyRecoveryAcknowledgement(reader io.Reader, prepared transportrecovery.PreparedFrame) (RecoveryAuthorization, error) {
	ack, err := transportrecovery.ReadAcknowledgement(reader)
	if err != nil {
		return RecoveryAuthorization{}, fmt.Errorf("read FI durable recovery acknowledgement: %w", err)
	}
	if err := transportrecovery.AcknowledgementMatches(ack, prepared.Descriptor, prepared.FrameBytes, prepared.FrameSHA256); err != nil {
		return RecoveryAuthorization{}, err
	}
	return RecoveryAuthorization{acknowledgement: ack}, nil
}

func (authorization RecoveryAuthorization) Acknowledgement() (transportrecovery.Acknowledgement, error) {
	if err := authorization.acknowledgement.Validate(); err != nil {
		return transportrecovery.Acknowledgement{}, errors.New("invalid FI recovery retirement authorization")
	}
	return authorization.acknowledgement, nil
}

func RetireRecoveryMembers(spoolDir string, prepared transportrecovery.PreparedFrame, authorization RecoveryAuthorization) (RecoveryRetirementResult, error) {
	ack, err := authorization.Acknowledgement()
	if err != nil {
		return RecoveryRetirementResult{}, err
	}
	if err := transportrecovery.AcknowledgementMatches(ack, prepared.Descriptor, prepared.FrameBytes, prepared.FrameSHA256); err != nil {
		return RecoveryRetirementResult{}, fmt.Errorf("match FI recovery retirement authorization: %w", err)
	}
	if err := validateRecoverySpoolDir(spoolDir); err != nil {
		return RecoveryRetirementResult{}, err
	}

	indexBytes, err := transportrecovery.MarshalIndex(prepared.Index)
	if err != nil {
		return RecoveryRetirementResult{}, err
	}
	indexSHA, _ := transportrecovery.IndexSHA256(indexBytes)
	if indexSHA != ack.IndexSHA256 || uint64(len(prepared.Index.Members)) != ack.MemberCount {
		return RecoveryRetirementResult{}, errors.New("FI recovery in-memory member index does not match acknowledged index")
	}

	type state struct {
		member       transportrecovery.Member
		manifestPath string
		dataPath     string
		manifest     bool
		data         bool
	}
	states := make([]state, 0, len(prepared.Index.Members))
	for _, member := range prepared.Index.Members {
		manifestPath := filepath.Join(spoolDir, "batch-"+member.BatchID+".manifest.json")
		dataPath := filepath.Join(spoolDir, "batch-"+member.BatchID+".jsonl")
		manifestExists, err := verifyRecoveryRetirementManifest(manifestPath, member)
		if err != nil {
			return RecoveryRetirementResult{}, err
		}
		dataExists, err := verifyRecoveryRetirementData(dataPath, member)
		if err != nil {
			return RecoveryRetirementResult{}, err
		}
		if manifestExists && !dataExists {
			return RecoveryRetirementResult{}, errors.New("FI recovery retirement found manifest without corresponding data")
		}
		states = append(states, state{member: member, manifestPath: manifestPath, dataPath: dataPath, manifest: manifestExists, data: dataExists})
	}

	result := RecoveryRetirementResult{Members: uint64(len(states))}
	for _, current := range states {
		if current.manifest {
			if err := os.Remove(current.manifestPath); err != nil {
				return result, fmt.Errorf("remove acknowledged FI recovery member manifest: %w", err)
			}
			result.ManifestsRemoved++
		}
	}
	for _, current := range states {
		if current.data {
			if err := os.Remove(current.dataPath); err != nil {
				return result, fmt.Errorf("remove acknowledged FI recovery member data: %w", err)
			}
			result.DataRemoved++
		}
	}
	return result, nil
}

func AdvanceRecoveryQueue(queue *PublishedBatchQueue, prepared transportrecovery.PreparedFrame) error {
	if queue == nil {
		return errors.New("FI published-batch queue is required")
	}
	if len(prepared.Index.Members) == 0 {
		return errors.New("FI recovery member set is empty")
	}

	// Recovery retirement can span process restarts and can remove a large prefix
	// of the queue in one operation. Re-snapshot the directory after retirement
	// rather than trying to mutate a possibly stale in-memory filename snapshot.
	paths, err := scanPublishedBatchManifests(queue.spoolDir)
	if err != nil {
		return fmt.Errorf("rescan FI published-batch queue after recovery: %w", err)
	}
	selected := make(map[string]struct{}, len(prepared.Index.Members))
	for _, member := range prepared.Index.Members {
		selected["batch-"+member.BatchID+".manifest.json"] = struct{}{}
	}
	for _, path := range paths {
		name := filepath.Base(path)
		if _, exists := selected[name]; exists {
			return errors.New("FI recovery queue rescan found a supposedly retired member manifest")
		}
	}
	queue.manifestPaths = paths
	return nil
}

func inspectPlanningManifest(path string) (string, uint64, error) {
	member, err := transportrecovery.MemberFromPublishedManifest(path)
	if err != nil {
		return "", 0, err
	}
	if member.ManifestBytes > ^uint64(0)-member.DataBytes {
		return "", 0, errors.New("FI recovery planning member byte count overflow")
	}
	return member.BatchID, member.ManifestBytes + member.DataBytes, nil
}

func verifyRecoveryRetirementManifest(path string, member transportrecovery.Member) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != member.ManifestBytes {
		return false, errors.New("FI recovery retirement manifest size changed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != member.ManifestSHA256 {
		return false, errors.New("FI recovery retirement manifest SHA-256 changed")
	}
	if _, err := transportrecovery.ValidateManifestBytes(raw, member); err != nil {
		return false, err
	}
	return true, nil
}

func verifyRecoveryRetirementData(path string, member transportrecovery.Member) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != member.DataBytes {
		return false, errors.New("FI recovery retirement data size changed")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return false, copyErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if uint64(written) != member.DataBytes || hex.EncodeToString(hasher.Sum(nil)) != member.DataSHA256 {
		return false, errors.New("FI recovery retirement data changed")
	}
	return true, nil
}

func RecoveryOfferFromPlan(sourceID string, plan RecoveryPlan) (transportrecovery.Offer, error) {
	offer := transportrecovery.Offer{
		Version:               "fi-recovery-offer/0.1",
		SourceID:              sourceID,
		PendingMembers:        plan.PendingMembers,
		PendingCanonicalBytes: plan.PendingCanonicalBytes,
		OldestBatchID:         plan.OldestBatchID,
		NewestBatchID:         plan.NewestBatchID,
		ProposedMembers:       plan.ProposedMembers,
	}
	if err := offer.Validate(); err != nil {
		return transportrecovery.Offer{}, err
	}
	return offer, nil
}

func validateRecoverySpoolDir(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("FI recovery spool directory must be absolute")
	}
	clean := filepath.Clean(path)
	if err := validateOutboundStageDirectoryPath(clean); err != nil {
		return fmt.Errorf("validate FI recovery spool directory path: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect FI recovery spool directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI recovery spool path must name a real directory")
	}
	return nil
}

func RecoveryStageMatchesSpool(prepared transportrecovery.PreparedFrame, spoolDir string) error {
	if prepared.Descriptor.SourceID == "" {
		return errors.New("FI staged recovery source identity is incomplete")
	}
	if err := validateRecoverySpoolDir(spoolDir); err != nil {
		return err
	}
	for _, member := range prepared.Index.Members {
		if strings.ContainsAny(member.BatchID, `/\\`) {
			return errors.New("FI staged recovery contains invalid batch ID")
		}
		manifestPath := filepath.Join(spoolDir, "batch-"+member.BatchID+".manifest.json")
		dataPath := filepath.Join(spoolDir, "batch-"+member.BatchID+".jsonl")
		manifestExists, err := verifyRecoveryRetirementManifest(manifestPath, member)
		if err != nil {
			return err
		}
		dataExists, err := verifyRecoveryRetirementData(dataPath, member)
		if err != nil {
			return err
		}
		if !manifestExists && !dataExists {
			continue
		}
		if manifestExists && !dataExists {
			return errors.New("FI staged recovery spool state contains manifest without data")
		}
	}
	return nil
}
