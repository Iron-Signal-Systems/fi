// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// A bounded chunk limits PostgreSQL array arguments, transaction memory and
// the time spent resolving new NTFS identities. The parent and child projector
// keeps its existing generation transaction and validation/rollback behavior.
const ntfsIdentityPrefetchBatchRows = 512

type ntfsIdentityPrefetchKey struct {
	volumeID int64
	frn      string
	sequence string
}

type ntfsIdentityPrefetchRequest struct {
	key       ntfsIdentityPrefetchKey
	method    string
	originals []records.NTFSObjectIdentity
}

type ntfsIdentityPrefetchResult struct {
	id     int64
	method string
}

func canonicalNTFSIdentityNumber(value string) (string, error) {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 {
		return "", fmt.Errorf("invalid nonnegative NTFS identity numeric %q", value)
	}
	return n.String(), nil
}

// prefetchNTFSObjectIdentities primes the *generation-scoped* cache before
// prepareFileObservationBulk does its existing FK-safe parent/metadata COPY.
// No state survives a failed or rolled-back generation transaction.
func prefetchNTFSObjectIdentities(ctx context.Context, tx pgx.Tx, pending []fileObservationBulkRecord) error {
	cache, _ := ctx.Value(ntfsObjectCacheContextKey{}).(*ntfsObjectCache)
	if cache == nil || len(pending) == 0 {
		return nil // Legacy direct projectors and isolated table tests are unchanged.
	}
	if tx == nil {
		return errors.New("FI NTFS identity prefetch requires a transaction")
	}

	requests := make([]*ntfsIdentityPrefetchRequest, 0, len(pending)*2)
	byKey := make(map[ntfsIdentityPrefetchKey]*ntfsIdentityPrefetchRequest, len(pending)*2)
	for _, p := range pending {
		volumeID, err := ensureNTFSVolume(ctx, tx, p.sourceID, p.value.VolumeIdentity)
		if err != nil {
			return fmt.Errorf("FI NTFS identity prefetch source record %d volume: %w", p.sourceRecordID, err)
		}
		objects := []records.NTFSObjectIdentity{p.value.ObjectIdentity, p.value.GovernedRoot.ObjectIdentity}
		if p.value.ParentBinding.ObjectIdentity != nil {
			objects = append(objects, *p.value.ParentBinding.ObjectIdentity)
		}
		for _, object := range objects {
			rawKey := ntfsObjectCacheKey{volumeID: volumeID, fileReferenceNumber: object.FileReferenceNumber, sequenceNumber: object.SequenceNumber}
			if entry, hit := cache.objects[rawKey]; hit {
				if entry.methodVersion != object.MethodVersion {
					return errors.New("FI NTFS object identity method conflicts with existing relational identity")
				}
				continue
			}
			// Prefetch every uncached identity. The bounded FIFO cache evicts
			// older entries when full; saturation must never force this path
			// back into one SQL round trip per source-record identity.
			frn, err := canonicalNTFSIdentityNumber(object.FileReferenceNumber)
			if err != nil {
				return fmt.Errorf("FI NTFS identity prefetch source record %d FRN: %w", p.sourceRecordID, err)
			}
			sequence, err := canonicalNTFSIdentityNumber(object.SequenceNumber)
			if err != nil {
				return fmt.Errorf("FI NTFS identity prefetch source record %d sequence: %w", p.sourceRecordID, err)
			}
			key := ntfsIdentityPrefetchKey{volumeID: volumeID, frn: frn, sequence: sequence}
			request, found := byKey[key]
			if !found {
				request = &ntfsIdentityPrefetchRequest{key: key, method: object.MethodVersion}
				byKey[key] = request
				requests = append(requests, request)
			} else if request.method != object.MethodVersion {
				return errors.New("FI NTFS object identity method conflicts with existing relational identity")
			}
			request.originals = append(request.originals, object)
		}
	}
	// A deterministic order prevents two otherwise independent transactions
	// from locking the same set of new identities in opposite orders.
	sort.Slice(requests, func(i, j int) bool {
		a, b := requests[i].key, requests[j].key
		if a.volumeID != b.volumeID {
			return a.volumeID < b.volumeID
		}
		if len(a.frn) != len(b.frn) {
			return len(a.frn) < len(b.frn)
		}
		if a.frn != b.frn {
			return a.frn < b.frn
		}
		if len(a.sequence) != len(b.sequence) {
			return len(a.sequence) < len(b.sequence)
		}
		return a.sequence < b.sequence
	})
	for start := 0; start < len(requests); start += ntfsIdentityPrefetchBatchRows {
		end := start + ntfsIdentityPrefetchBatchRows
		if end > len(requests) {
			end = len(requests)
		}
		if err := prefetchNTFSObjectBatch(ctx, tx, cache, requests[start:end]); err != nil {
			return fmt.Errorf("FI NTFS identity prefetch rows %d-%d: %w", start+1, end, err)
		}
	}
	return nil
}

func prefetchNTFSObjectBatch(ctx context.Context, tx pgx.Tx, cache *ntfsObjectCache, requests []*ntfsIdentityPrefetchRequest) error {
	if len(requests) == 0 {
		return nil
	}
	if ctx == nil || tx == nil || cache == nil || len(requests) > ntfsIdentityPrefetchBatchRows {
		return errors.New("FI NTFS identity prefetch batch has invalid bounds")
	}
	existing, err := selectNTFSObjectBatch(ctx, tx, requests)
	if err != nil {
		return err
	}
	missing := make([]*ntfsIdentityPrefetchRequest, 0, len(requests))
	for _, request := range requests {
		if result, found := existing[request.key]; found {
			if result.method != request.method {
				return errors.New("FI NTFS object identity method conflicts with existing relational identity")
			}
		} else {
			missing = append(missing, request)
		}
	}
	if len(missing) > 0 {
		volumes, frns, sequences, methods := ntfsIdentityPrefetchArrays(missing)
		_, err := tx.Exec(ctx, `
INSERT INTO fi.ntfs_object (
    ntfs_volume_id, identity_method_version, file_reference_number, sequence_number
)
SELECT requested.volume_id, requested.method, requested.frn::numeric, requested.sequence::numeric
FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[])
    AS requested(volume_id, frn, sequence, method)
ON CONFLICT (ntfs_volume_id, file_reference_number, sequence_number) DO NOTHING
`, volumes, frns, sequences, methods)
		if err != nil {
			return fmt.Errorf("insert FI batched NTFS identities: %w", err)
		}
		// Re-select rather than relying on generated sequence IDs or RETURNING
		// order. Also sees a concurrently inserted identity after ON CONFLICT.
		inserted, err := selectNTFSObjectBatch(ctx, tx, missing)
		if err != nil {
			return err
		}
		for key, result := range inserted {
			existing[key] = result
		}
	}
	if len(existing) != len(requests) {
		return fmt.Errorf("FI NTFS identity prefetch resolved %d of %d identities", len(existing), len(requests))
	}
	for _, request := range requests {
		result, found := existing[request.key]
		if !found || result.id <= 0 {
			return errors.New("FI NTFS identity prefetch returned incomplete identity")
		}
		if result.method != request.method {
			return errors.New("FI NTFS object identity method conflicts with existing relational identity")
		}
		for _, original := range request.originals {
			cache.remember(request.key.volumeID, original, result.id)
		}
	}
	return nil
}

func ntfsIdentityPrefetchArrays(requests []*ntfsIdentityPrefetchRequest) ([]int64, []string, []string, []string) {
	volumes := make([]int64, 0, len(requests))
	frns := make([]string, 0, len(requests))
	sequences := make([]string, 0, len(requests))
	methods := make([]string, 0, len(requests))
	for _, request := range requests {
		volumes = append(volumes, request.key.volumeID)
		frns = append(frns, request.key.frn)
		sequences = append(sequences, request.key.sequence)
		methods = append(methods, request.method)
	}
	return volumes, frns, sequences, methods
}

func selectNTFSObjectBatch(ctx context.Context, tx pgx.Tx, requests []*ntfsIdentityPrefetchRequest) (map[ntfsIdentityPrefetchKey]ntfsIdentityPrefetchResult, error) {
	volumes, frns, sequences, _ := ntfsIdentityPrefetchArrays(requests)
	rows, err := tx.Query(ctx, `
SELECT requested.volume_id, requested.frn, requested.sequence,
       obj.ntfs_object_id, obj.identity_method_version
FROM unnest($1::bigint[], $2::text[], $3::text[])
     AS requested(volume_id, frn, sequence)
JOIN fi.ntfs_object AS obj
  ON obj.ntfs_volume_id = requested.volume_id
 AND obj.file_reference_number = requested.frn::numeric
 AND obj.sequence_number = requested.sequence::numeric
`, volumes, frns, sequences)
	if err != nil {
		return nil, fmt.Errorf("read FI batched NTFS identities: %w", err)
	}
	defer rows.Close()
	results := make(map[ntfsIdentityPrefetchKey]ntfsIdentityPrefetchResult, len(requests))
	for rows.Next() {
		var key ntfsIdentityPrefetchKey
		var result ntfsIdentityPrefetchResult
		if err := rows.Scan(&key.volumeID, &key.frn, &key.sequence, &result.id, &result.method); err != nil {
			return nil, fmt.Errorf("scan FI batched NTFS identity: %w", err)
		}
		if result.id <= 0 {
			return nil, errors.New("FI batched NTFS identity has invalid database ID")
		}
		if _, duplicate := results[key]; duplicate {
			return nil, errors.New("FI batched NTFS identity lookup returned duplicate")
		}
		results[key] = result
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate FI batched NTFS identities: %w", err)
	}
	return results, nil
}
