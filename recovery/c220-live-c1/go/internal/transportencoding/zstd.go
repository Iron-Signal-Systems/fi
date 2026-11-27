// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportencoding

import (
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

const (
	DataEncodingZstd       = "zstd"
	MaxZstdWindowBytes     = uint64(16 << 20)
)

// NewZstdDecoder returns the single-concurrency FI zstd decoder used for
// transport payload validation.
//
// The decoder rejects frames that request more than FI's bounded zstd window
// before payload decoding begins. Callers must still enforce the signed logical
// byte count and hash while consuming decoded data.
func NewZstdDecoder(reader io.Reader) (*zstd.Decoder, error) {
	if reader == nil {
		return nil, fmt.Errorf("zstd reader is required")
	}

	decoder, err := zstd.NewReader(
		reader,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(MaxZstdWindowBytes),
		zstd.WithDecoderMaxWindow(MaxZstdWindowBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("create FI zstd decoder: %w", err)
	}

	return decoder, nil
}

// NewZstdEncoder returns the fixed FI zstd transport encoder. SpeedFastest is
// deliberate: FI's live Phase 1 corpus compressed to about 4.44 percent of its
// original JSONL size while preserving substantially more source CPU headroom
// than the slower encoder levels.
func NewZstdEncoder(writer io.Writer) (*zstd.Encoder, error) {
	if writer == nil {
		return nil, fmt.Errorf("zstd writer is required")
	}

	encoder, err := zstd.NewWriter(
		writer,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedFastest),
	)
	if err != nil {
		return nil, fmt.Errorf("create FI zstd encoder: %w", err)
	}

	return encoder, nil
}
