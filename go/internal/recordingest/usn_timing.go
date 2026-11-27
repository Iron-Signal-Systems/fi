package recordingest

import (
	"context"
	"time"
)

type usnTimingContextKey struct{}

type usnTimingCounters struct {
	Observations int64
	Total        time.Duration
	Boundary     time.Duration
	Object       time.Duration
	Observation  time.Duration
	Changes      time.Duration
	Nested       time.Duration
}

func tallyUSN(ctx context.Context, stage string, started time.Time) {
	profile, ok := ctx.Value(usnTimingContextKey{}).(*usnTimingCounters)
	if !ok {
		return
	}

	elapsed := time.Since(started)

	switch stage {
	case "total":
		profile.Total += elapsed
		profile.Observations++
	case "boundary":
		profile.Boundary += elapsed
	case "object":
		profile.Object += elapsed
	case "observation":
		profile.Observation += elapsed
	case "changes":
		profile.Changes += elapsed
	case "nested":
		profile.Nested += elapsed
	}
}
