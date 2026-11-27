// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportencoding

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestZstdRejectsCorruptPayload(t *testing.T) {
	decoder, err := NewZstdDecoder(bytes.NewReader([]byte("not-zstd")))
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()

	if _, err := io.ReadAll(decoder); err == nil {
		t.Fatal("expected corrupt zstd payload to fail")
	}
}

func TestZstdRejectsOversizedWindow(t *testing.T) {
	var encoded bytes.Buffer
	encoder, err := zstd.NewWriter(
		&encoded,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithWindowSize(32<<20),
	)
	if err != nil {
		t.Fatal(err)
	}

	const logicalBytes = int(MaxZstdWindowBytes) + 1
	payload := bytes.Repeat([]byte("A"), logicalBytes)
	if _, err := encoder.Write(payload); err != nil {
		encoder.Close()
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}

	decoder, err := NewZstdDecoder(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		// Some decoder versions reject the frame while initializing.
		return
	}
	defer decoder.Close()

	if _, err := io.Copy(io.Discard, decoder); err == nil {
		t.Fatal("expected zstd frame above FI maximum window to fail")
	}
}

func TestZstdRoundTrip(t *testing.T) {
	original := bytes.Repeat(
		[]byte(`{"event":"file_write","path":"C:\\Data\\report.txt"}`+"\n"),
		4096,
	)

	var encoded bytes.Buffer
	encoder, err := NewZstdEncoder(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(original); err != nil {
		encoder.Close()
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() >= len(original) {
		t.Fatalf(
			"expected representative FI JSONL to compress: encoded=%d original=%d",
			encoded.Len(),
			len(original),
		)
	}

	decoder, err := NewZstdDecoder(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(decoder)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatal("zstd round-trip changed FI data bytes")
	}
}
