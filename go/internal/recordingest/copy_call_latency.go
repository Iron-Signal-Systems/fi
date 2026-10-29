// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"
	"time"
)

// copyCallLatency records constant-space metrics for completed COPY calls.
// A call includes client encoding, database execution, constraint and index
// maintenance, and waiting for PostgreSQL. It is NOT a pure SQL or disk timer.
// The caller owns this value for one generation; no global mutable state.
type copyCallLatency struct {
	Calls              int64
	Min                time.Duration
	Max                time.Duration
	AtLeastOneSecond   int64
	AtLeastFiveSeconds int64
}

// observe is constant-time and allocates no memory. Count exactly one COPY
// attempt after CopyFrom returns, including attempts that return an error.
// A failed generation is rolled back and does not emit accepted metrics.
func (c *copyCallLatency) observe(elapsed time.Duration) {
	if elapsed < 0 {
		elapsed = 0
	}
	if c.Calls == 0 || elapsed < c.Min {
		c.Min = elapsed
	}
	if elapsed > c.Max {
		c.Max = elapsed
	}
	c.Calls++
	if elapsed >= time.Second {
		c.AtLeastOneSecond++
	}
	if elapsed >= 5*time.Second {
		c.AtLeastFiveSeconds++
	}
}

// String renders a single compact field value for one end-of-generation log.
// When there are no calls, min and max are zero by design.
func (c copyCallLatency) String() string {
	return fmt.Sprintf(
		"calls=%d,min=%s,max=%s,ge_1s=%d,ge_5s=%d",
		c.Calls,
		c.Min.Round(time.Millisecond),
		c.Max.Round(time.Millisecond),
		c.AtLeastOneSecond,
		c.AtLeastFiveSeconds,
	)
}
