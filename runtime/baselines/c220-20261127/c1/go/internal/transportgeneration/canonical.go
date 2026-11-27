// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// CanonicalArtifactHandler consumes exactly one decoded FI generation
// artifact. A successful handler MUST read the supplied artifact reader through
// io.EOF. Returning early without an error fails closed.
type CanonicalArtifactHandler func(
	name string,
	reader io.Reader,
) error

// ReadCanonicalArtifacts validates one decoded FI generation canonical stream
// and optionally exposes each artifact to a streaming semantic handler.
//
// Framing, artifact ordering, name validation, chunk bounds, declared file byte
// counts, and total artifact count are enforced here. Collector batch semantics
// deliberately remain outside transportgeneration.
func ReadCanonicalArtifacts(
	reader io.Reader,
	descriptor Descriptor,
	handler CanonicalArtifactHandler,
) (
	uint64,
	error,
) {
	if reader == nil {
		return 0,
			errors.New(
				"FI generation canonical reader is required",
			)
	}

	if err :=
		descriptor.Validate(); err != nil {
		return 0,
			fmt.Errorf(
				"validate FI generation descriptor before canonical read: %w",
				err,
			)
	}

	magic :=
		make(
			[]byte,
			len(
				generationCanonicalMagic,
			),
		)

	if _, err :=
		io.ReadFull(
			reader,
			magic,
		); err != nil {
		return 0,
			fmt.Errorf(
				"read FI generation canonical magic: %w",
				err,
			)
	}

	if string(
		magic,
	) != generationCanonicalMagic {
		return 0,
			errors.New(
				"invalid FI generation canonical magic",
			)
	}

	var countBytes [8]byte

	if _, err :=
		io.ReadFull(
			reader,
			countBytes[:],
		); err != nil {
		return 0,
			fmt.Errorf(
				"read FI generation canonical artifact count: %w",
				err,
			)
	}

	artifactCount :=
		binary.BigEndian.Uint64(
			countBytes[:],
		)

	if artifactCount !=
		descriptor.ArtifactCount {
		return 0,
			fmt.Errorf(
				"FI generation canonical artifact count %d does not match signed descriptor %d",
				artifactCount,
				descriptor.ArtifactCount,
			)
	}

	if artifactCount == 0 ||
		artifactCount >
			maxReceiveArtifactCount {
		return 0,
			errors.New(
				"FI generation canonical artifact count is outside bounds",
			)
	}

	var sourceBytes uint64

	previousName :=
		""

	for position :=
		uint64(0); position <
		artifactCount; position++ {
		name, err :=
			readCanonicalArtifactName(
				reader,
				position,
			)
		if err != nil {
			return 0, err
		}

		if previousName != "" &&
			name <= previousName {
			return 0,
				errors.New(
					"FI generation canonical artifact names are not in strict sorted order",
				)
		}

		previousName =
			name

		artifactReader :=
			&canonicalArtifactReader{
				reader: reader,
			}

		if handler == nil {
			if _, err :=
				io.Copy(
					io.Discard,
					artifactReader,
				); err != nil {
				return 0,
					fmt.Errorf(
						"read FI generation artifact %d %q: %w",
						position,
						name,
						err,
					)
			}
		} else {
			if err :=
				handler(
					name,
					artifactReader,
				); err != nil {
				return 0,
					fmt.Errorf(
						"consume FI generation artifact %d %q: %w",
						position,
						name,
						err,
					)
			}

			if !artifactReader.finished {
				return 0,
					errors.New(
						"FI generation canonical artifact handler returned before consuming the complete artifact",
					)
			}
		}

		if artifactReader.fileBytes >
			^uint64(0)-
				sourceBytes {
			return 0,
				errors.New(
					"FI generation source byte count overflow",
				)
		}

		sourceBytes +=
			artifactReader.fileBytes
	}

	return sourceBytes, nil
}

type canonicalArtifactReader struct {
	chunkRemaining uint32
	fileBytes      uint64
	finished       bool
	reader         io.Reader
}

func (
	artifact *canonicalArtifactReader,
) Read(
	value []byte,
) (
	int,
	error,
) {
	if artifact == nil ||
		artifact.reader == nil {
		return 0,
			errors.New(
				"FI generation canonical artifact reader is unavailable",
			)
	}

	if len(value) == 0 {
		return 0, nil
	}

	if artifact.finished {
		return 0, io.EOF
	}

	for artifact.chunkRemaining == 0 {
		var chunkLengthBytes [4]byte

		if _, err :=
			io.ReadFull(
				artifact.reader,
				chunkLengthBytes[:],
			); err != nil {
			return 0,
				fmt.Errorf(
					"read FI generation artifact chunk length: %w",
					err,
				)
		}

		chunkLength :=
			binary.BigEndian.Uint32(
				chunkLengthBytes[:],
			)

		if chunkLength == 0 {
			var declaredFileBytes [8]byte

			if _, err :=
				io.ReadFull(
					artifact.reader,
					declaredFileBytes[:],
				); err != nil {
				return 0,
					fmt.Errorf(
						"read FI generation artifact declared byte count: %w",
						err,
					)
			}

			declared :=
				binary.BigEndian.Uint64(
					declaredFileBytes[:],
				)

			if declared !=
				artifact.fileBytes {
				return 0,
					fmt.Errorf(
						"FI generation artifact byte count %d does not match canonical declaration %d",
						artifact.fileBytes,
						declared,
					)
			}

			artifact.finished =
				true

			return 0, io.EOF
		}

		if chunkLength >
			generationCanonicalChunkBytes {
			return 0,
				fmt.Errorf(
					"FI generation artifact chunk length %d exceeds canonical limit %d",
					chunkLength,
					generationCanonicalChunkBytes,
				)
		}

		if uint64(
			chunkLength,
		) >
			^uint64(0)-
				artifact.fileBytes {
			return 0,
				errors.New(
					"FI generation artifact byte count overflow",
				)
		}

		artifact.chunkRemaining =
			chunkLength
	}

	readLength :=
		len(value)

	if uint32(
		readLength,
	) >
		artifact.chunkRemaining {
		readLength =
			int(
				artifact.chunkRemaining,
			)
	}

	n, err :=
		io.ReadFull(
			artifact.reader,
			value[:readLength],
		)

	if n > 0 {
		artifact.chunkRemaining -=
			uint32(n)

		artifact.fileBytes +=
			uint64(n)
	}

	if err != nil {
		return n,
			fmt.Errorf(
				"read FI generation artifact chunk: %w",
				err,
			)
	}

	return n, nil
}

func readCanonicalArtifactName(
	reader io.Reader,
	position uint64,
) (
	string,
	error,
) {
	var nameLengthBytes [4]byte

	if _, err :=
		io.ReadFull(
			reader,
			nameLengthBytes[:],
		); err != nil {
		return "",
			fmt.Errorf(
				"read FI generation artifact %d name length: %w",
				position,
				err,
			)
	}

	nameLength :=
		binary.BigEndian.Uint32(
			nameLengthBytes[:],
		)

	if nameLength == 0 ||
		nameLength >
			maxCanonicalArtifactNameBytes {
		return "",
			fmt.Errorf(
				"FI generation artifact %d name length is outside bounds",
				position,
			)
	}

	nameBytes :=
		make(
			[]byte,
			int(nameLength),
		)

	if _, err :=
		io.ReadFull(
			reader,
			nameBytes,
		); err != nil {
		return "",
			fmt.Errorf(
				"read FI generation artifact %d name: %w",
				position,
				err,
			)
	}

	name :=
		string(
			nameBytes,
		)

	if !utf8.ValidString(
		name,
	) ||
		strings.ContainsAny(
			name,
			"/\\\x00\r\n",
		) {
		return "",
			fmt.Errorf(
				"FI generation artifact %d name is invalid",
				position,
			)
	}

	return name, nil
}
