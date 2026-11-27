// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const MaximumBytes = int64(4 * 1024 * 1024)

func ReadHTTP(
	source string,
) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	response, err := client.Get(
		source,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"retrieve transport CRL %q: %w",
			source,
			err,
		)
	}

	defer response.Body.Close()

	if response.StatusCode !=
		http.StatusOK {
		return nil, fmt.Errorf(
			"retrieve transport CRL %q: HTTP status=%d",
			source,
			response.StatusCode,
		)
	}

	limited := io.LimitReader(
		response.Body,
		MaximumBytes+1,
	)

	value, err := io.ReadAll(
		limited,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read transport CRL %q: %w",
			source,
			err,
		)
	}

	if int64(
		len(value),
	) > MaximumBytes {
		return nil, fmt.Errorf(
			"transport CRL %q exceeds FI limit=%d bytes",
			source,
			MaximumBytes,
		)
	}

	return value, nil
}
