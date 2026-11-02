package recordingest

import "context"

// Existing local profile implementation, reused unchanged.
func WithFixedFileBulkProfile(ctx context.Context, name string) (context.Context, error) {
	return withFixedFileBulkProfile(ctx, name)
}
func EffectiveFileBulkLimits(ctx context.Context) (sourceRows int, sourceBytes int64, observeRows int, observeBytes int64) {
	v := fileBulkLimitsFromContext(ctx)
	return v.SourceMaxRecords, v.SourceMaxBytes, v.ObserveMaxRecords, v.ObserveMaxBytes
}
