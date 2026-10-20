// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	ntfsVolumeCacheMaxEntries = 4096
	ntfsRootCacheMaxEntries   = 4096
	ntfsRootCacheMaxKeyBytes  = 8192
)

type ntfsScopeIdentityCacheContextKey struct{}

type ntfsVolumeIdentityKey struct {
	sourceID string
	guid     string
	serial   string
}

type ntfsRootIdentityKey struct {
	sourceID  string
	scopeID   string
	volumeID  int64
	objectID  int64
	requested string
	resolved  string
}

type ntfsScopeIdentityEntry struct {
	id     int64
	method string
}

type ntfsScopeIdentityCache struct {
	volumes map[ntfsVolumeIdentityKey]ntfsScopeIdentityEntry
	roots   map[ntfsRootIdentityKey]ntfsScopeIdentityEntry

	volumeHits   uint64
	volumeMisses uint64
	rootHits     uint64
	rootMisses   uint64
}

func newNTFSScopeIdentityCache() *ntfsScopeIdentityCache {
	return &ntfsScopeIdentityCache{
		volumes: make(map[ntfsVolumeIdentityKey]ntfsScopeIdentityEntry),
		roots:   make(map[ntfsRootIdentityKey]ntfsScopeIdentityEntry),
	}
}

func (c *ntfsScopeIdentityCache) lookupVolume(
	sourceID string, value records.VolumeIdentity,
) (int64, bool, error) {
	if c == nil {
		return 0, false, nil
	}

	key := ntfsVolumeIdentityKey{
		sourceID: sourceID,
		guid:     value.VolumeGUID,
		serial:   value.VolumeSerial,
	}

	entry, found := c.volumes[key]
	if !found {
		c.volumeMisses++
		return 0, false, nil
	}

	c.volumeHits++
	if entry.method != value.MethodVersion {
		return 0, true, errors.New(
			"FI NTFS volume identity method conflicts with existing relational identity",
		)
	}

	return entry.id, true, nil
}

func (c *ntfsScopeIdentityCache) rememberVolume(
	sourceID string, value records.VolumeIdentity, id int64,
) {
	if c == nil || len(c.volumes) >= ntfsVolumeCacheMaxEntries {
		return
	}

	key := ntfsVolumeIdentityKey{
		sourceID: sourceID,
		guid:     value.VolumeGUID,
		serial:   value.VolumeSerial,
	}

	c.volumes[key] = ntfsScopeIdentityEntry{
		id: id, method: value.MethodVersion,
	}
}

func (c *ntfsScopeIdentityCache) lookupRoot(
	sourceID string, volumeID, objectID int64,
	value records.GovernedRootIdentity,
	requested, resolved []byte,
) (int64, bool, error) {
	if c == nil {
		return 0, false, nil
	}

	key := ntfsRootIdentityKey{
		sourceID:  sourceID,
		scopeID:   value.ScopeID,
		volumeID:  volumeID,
		objectID:  objectID,
		requested: string(requested),
		resolved:  string(resolved),
	}

	entry, found := c.roots[key]
	if !found {
		c.rootMisses++
		return 0, false, nil
	}

	c.rootHits++
	if entry.method != value.MethodVersion {
		return 0, true, errors.New(
			"FI governed-root identity method conflicts with existing relational identity",
		)
	}

	return entry.id, true, nil
}

func (c *ntfsScopeIdentityCache) rememberRoot(
	sourceID string, volumeID, objectID int64,
	value records.GovernedRootIdentity,
	requested, resolved []byte, id int64,
) {
	if c == nil || len(c.roots) >= ntfsRootCacheMaxEntries {
		return
	}

	if len(sourceID)+len(value.ScopeID)+
		len(requested)+len(resolved) > ntfsRootCacheMaxKeyBytes {
		return
	}

	key := ntfsRootIdentityKey{
		sourceID:  sourceID,
		scopeID:   value.ScopeID,
		volumeID:  volumeID,
		objectID:  objectID,
		requested: string(requested),
		resolved:  string(resolved),
	}

	c.roots[key] = ntfsScopeIdentityEntry{
		id: id, method: value.MethodVersion,
	}
}
