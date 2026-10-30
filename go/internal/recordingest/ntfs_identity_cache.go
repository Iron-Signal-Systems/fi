package recordingest

import (
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const ntfsObjectCacheMaxEntries = 262144

type ntfsObjectCacheContextKey struct{}

type ntfsObjectCacheKey struct {
	volumeID            int64
	fileReferenceNumber string
	sequenceNumber      string
}

type ntfsObjectCacheEntry struct {
	id            int64
	methodVersion string
}

type ntfsObjectCache struct {
	objects      map[ntfsObjectCacheKey]ntfsObjectCacheEntry
	// Oldest-first insertion order. Once full, reuse slots as a bounded FIFO.
	// Eviction affects performance only; PostgreSQL remains the identity authority.
	order        []ntfsObjectCacheKey
	nextEviction int
	hits         uint64
	misses       uint64
	evictions    uint64
}

func newNTFSObjectCache() *ntfsObjectCache {
	return &ntfsObjectCache{
		objects: make(map[ntfsObjectCacheKey]ntfsObjectCacheEntry),
	}
}

func (cache *ntfsObjectCache) lookup(
	volumeID int64,
	value records.NTFSObjectIdentity,
) (int64, bool, error) {
	if cache == nil {
		return 0, false, nil
	}

	key := ntfsObjectCacheKey{
		volumeID:            volumeID,
		fileReferenceNumber: value.FileReferenceNumber,
		sequenceNumber:      value.SequenceNumber,
	}

	entry, found := cache.objects[key]
	if !found {
		cache.misses++
		return 0, false, nil
	}

	cache.hits++

	if entry.methodVersion != value.MethodVersion {
		return 0, true, errors.New(
			"FI NTFS object identity method conflicts with existing relational identity",
		)
	}

	return entry.id, true, nil
}

func (cache *ntfsObjectCache) remember(
	volumeID int64,
	value records.NTFSObjectIdentity,
	id int64,
) {
	if cache == nil {
		return
	}

	key := ntfsObjectCacheKey{
		volumeID:            volumeID,
		fileReferenceNumber: value.FileReferenceNumber,
		sequenceNumber:      value.SequenceNumber,
	}

	// Updating an existing identity must not consume an eviction slot.
	if _, found := cache.objects[key]; !found {
		if len(cache.objects) < ntfsObjectCacheMaxEntries {
			cache.order = append(cache.order, key)
		} else {
			oldest := cache.order[cache.nextEviction]
			delete(cache.objects, oldest)
			cache.order[cache.nextEviction] = key
			cache.nextEviction++
			if cache.nextEviction == ntfsObjectCacheMaxEntries {
				cache.nextEviction = 0
			}
			cache.evictions++
		}
	}

	cache.objects[key] = ntfsObjectCacheEntry{
		id:            id,
		methodVersion: value.MethodVersion,
	}
}
