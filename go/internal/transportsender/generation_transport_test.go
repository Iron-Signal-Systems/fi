// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestBuildRawTransportGenerationPromotesSemanticFreeObject(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	parent := t.TempDir()
	spoolDir := filepath.Join(parent, "spool")
	stageRoot := filepath.Join(parent, "stage")

	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	writeGenerationTestBatch(
		t,
		spoolDir,
		"20260918T155000.000000000Z-0000000000000001",
		[]byte("{\"record\":1}\n"),
	)

	raw, found, err := RolloverPublishedSpool(spoolDir)
	if err != nil || !found {
		t.Fatalf(
			"roll FI spool: found=%t err=%v",
			found,
			err,
		)
	}

	key, certificate := generationTestSigningCertificate(t, sourceID)

	generation, err := BuildRawTransportGeneration(
		context.Background(),
		GenerationSealConfig{
			BatchSigner:             key,
			BatchSigningCertificate: certificate,
			MaxEncodedBytes:         64 << 20,
			SourceID:                sourceID,
			SpoolDir:                spoolDir,
			StageRoot:               stageRoot,
		},
		raw,
	)
	if err != nil {
		t.Fatal(err)
	}

	if generation.GenerationID != raw.GenerationID {
		t.Fatalf(
			"generation ID = %q, want %q",
			generation.GenerationID,
			raw.GenerationID,
		)
	}

	if generation.Published.Signed.Descriptor.ArtifactCount != 2 {
		t.Fatalf(
			"artifact count = %d, want 2",
			generation.Published.Signed.Descriptor.ArtifactCount,
		)
	}

	if _, err := os.Lstat(raw.GenerationDir); !os.IsNotExist(err) {
		t.Fatalf(
			"raw generation remains after durable transport build: %v",
			err,
		)
	}

	expectedDir := filepath.Join(
		stageRoot,
		generationDirectoryPrefix+raw.GenerationID,
	)

	if generation.GenerationDir != expectedDir {
		t.Fatalf(
			"generation directory = %q, want %q",
			generation.GenerationDir,
			expectedDir,
		)
	}

	if err := transportgeneration.VerifyPublishedGenerationPayload(
		generation.Published,
	); err != nil {
		t.Fatal(err)
	}

	next, found, err := NextTransportGeneration(stageRoot, sourceID)
	if err != nil || !found {
		t.Fatalf(
			"select promoted transport generation: found=%t err=%v",
			found,
			err,
		)
	}

	if next.GenerationID != raw.GenerationID {
		t.Fatalf(
			"selected generation = %q, want %q",
			next.GenerationID,
			raw.GenerationID,
		)
	}
}

func TestBuildRawTransportGenerationRejectsEncodedLimitBeforeActivePublication(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	parent := t.TempDir()
	spoolDir := filepath.Join(parent, "spool")
	stageRoot := filepath.Join(parent, "stage")

	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	writeGenerationTestBatch(
		t,
		spoolDir,
		"20260918T155100.000000000Z-0000000000000002",
		[]byte("{\"record\":1}\n"),
	)

	raw, found, err := RolloverPublishedSpool(spoolDir)
	if err != nil || !found {
		t.Fatalf(
			"roll FI spool: found=%t err=%v",
			found,
			err,
		)
	}

	key, certificate := generationTestSigningCertificate(t, sourceID)

	_, err = BuildRawTransportGeneration(
		context.Background(),
		GenerationSealConfig{
			BatchSigner:             key,
			BatchSigningCertificate: certificate,
			MaxEncodedBytes:         1,
			SourceID:                sourceID,
			SpoolDir:                spoolDir,
			StageRoot:               stageRoot,
		},
		raw,
	)
	if !errors.Is(err, transportgeneration.ErrEncodedLimitExceeded) {
		t.Fatalf(
			"build error = %v, want ErrEncodedLimitExceeded",
			err,
		)
	}

	if _, err := os.Lstat(raw.GenerationDir); err != nil {
		t.Fatalf(
			"raw generation was retired after failed encoded-limit build: %v",
			err,
		)
	}

	if _, found, err := NextTransportGeneration(stageRoot, sourceID); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal(
			"encoded-limit failure published an active transport generation",
		)
	}
}

func TestRecoverTransportGenerationBuildsPromotesVerifiedPrivateObject(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	for _, rawPresent := range []bool{true, false} {
		name := "raw-absent"
		if rawPresent {
			name = "raw-present"
		}

		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			spoolDir := filepath.Join(parent, "spool")
			stageRoot := filepath.Join(parent, "stage")

			if err := os.Mkdir(spoolDir, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.Mkdir(stageRoot, 0o700); err != nil {
				t.Fatal(err)
			}

			writeGenerationTestBatch(
				t,
				spoolDir,
				"20260918T155200.000000000Z-0000000000000003",
				[]byte("{\"record\":1}\n"),
			)

			raw, found, err := RolloverPublishedSpool(spoolDir)
			if err != nil || !found {
				t.Fatalf(
					"roll FI spool: found=%t err=%v",
					found,
					err,
				)
			}

			rawRoot := filepath.Dir(raw.GenerationDir)
			buildRoot, err := ensureTransportGenerationBuildRoot(stageRoot)
			if err != nil {
				t.Fatal(err)
			}

			key, certificate := generationTestSigningCertificate(t, sourceID)

			built, err := transportgeneration.CreateSealedGeneration(
				context.Background(),
				transportgeneration.CreateConfig{
					BatchSigner:             key,
					BatchSigningCertificate: certificate,
					FrozenDir:               raw.GenerationDir,
					GenerationID:            raw.GenerationID,
					MaxEncodedBytes:         64 << 20,
					SealedRoot:              buildRoot,
					SourceID:                sourceID,
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			if _, found, err := NextTransportGeneration(stageRoot, sourceID); err != nil {
				t.Fatal(err)
			} else if found {
				t.Fatal(
					"private transport-generation build became network-visible before promotion",
				)
			}

			if !rawPresent {
				if err := removeRawGenerationDirectory(raw); err != nil {
					t.Fatal(err)
				}
			}

			if err := RecoverTransportGenerationBuilds(
				rawRoot,
				stageRoot,
				sourceID,
				64<<20,
			); err != nil {
				t.Fatal(err)
			}

			if _, err := os.Lstat(raw.GenerationDir); !os.IsNotExist(err) {
				t.Fatalf(
					"raw generation remains after recovery: %v",
					err,
				)
			}

			if _, err := os.Lstat(built.DirectoryPath); !os.IsNotExist(err) {
				t.Fatalf(
					"private built generation remains after promotion: %v",
					err,
				)
			}

			generation, found, err := NextTransportGeneration(stageRoot, sourceID)
			if err != nil || !found {
				t.Fatalf(
					"load recovered transport generation: found=%t err=%v",
					found,
					err,
				)
			}

			if generation.GenerationID != raw.GenerationID {
				t.Fatalf(
					"recovered generation ID = %q, want %q",
					generation.GenerationID,
					raw.GenerationID,
				)
			}
		})
	}
}

func TestRecoverTransportGenerationBuildsRetiresRawBesideActiveGeneration(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	parent := t.TempDir()
	spoolDir := filepath.Join(parent, "spool")
	stageRoot := filepath.Join(parent, "stage")

	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	writeGenerationTestBatch(
		t,
		spoolDir,
		"20260918T155300.000000000Z-0000000000000004",
		[]byte("{\"record\":1}\n"),
	)

	raw, found, err := RolloverPublishedSpool(spoolDir)
	if err != nil || !found {
		t.Fatalf(
			"roll FI spool: found=%t err=%v",
			found,
			err,
		)
	}

	key, certificate := generationTestSigningCertificate(t, sourceID)

	if _, err := transportgeneration.CreateSealedGeneration(
		context.Background(),
		transportgeneration.CreateConfig{
			BatchSigner:             key,
			BatchSigningCertificate: certificate,
			FrozenDir:               raw.GenerationDir,
			GenerationID:            raw.GenerationID,
			MaxEncodedBytes:         64 << 20,
			SealedRoot:              stageRoot,
			SourceID:                sourceID,
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := RecoverTransportGenerationBuilds(
		filepath.Dir(raw.GenerationDir),
		stageRoot,
		sourceID,
		64<<20,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(raw.GenerationDir); !os.IsNotExist(err) {
		t.Fatalf(
			"raw generation remains beside verified active generation: %v",
			err,
		)
	}

	generation, found, err := NextTransportGeneration(stageRoot, sourceID)
	if err != nil || !found {
		t.Fatalf(
			"load reconciled active transport generation: found=%t err=%v",
			found,
			err,
		)
	}

	if generation.GenerationID != raw.GenerationID {
		t.Fatalf(
			"reconciled generation ID = %q, want %q",
			generation.GenerationID,
			raw.GenerationID,
		)
	}
}

func TestNextTransportGenerationOldestFirstAndExactSend(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	stageRoot :=
		t.TempDir()

	key, certificate :=
		testTransportGenerationSigningIdentity(
			t,
			sourceID,
		)

	newer :=
		createTransportGenerationFixture(
			t,
			stageRoot,
			sourceID,
			"20260918T141000.000000000Z-bbbbbbbbbbbbbbbb",
			key,
			certificate,
		)

	_ = newer

	older :=
		createTransportGenerationFixture(
			t,
			stageRoot,
			sourceID,
			"20260918T140000.000000000Z-aaaaaaaaaaaaaaaa",
			key,
			certificate,
		)

	generation, found, err :=
		NextTransportGeneration(
			stageRoot,
			sourceID,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"oldest transport generation was not found",
		)
	}

	if generation.GenerationID !=
		older.Signed.Descriptor.GenerationID {
		t.Fatalf(
			"oldest generation ID = %q, want %q",
			generation.GenerationID,
			older.Signed.Descriptor.GenerationID,
		)
	}

	expectedMetadata, err :=
		os.ReadFile(
			older.MetadataPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	expectedPayload, err :=
		os.ReadFile(
			older.PayloadPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer

	result, err :=
		SendTransportGeneration(
			&wire,
			generation,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw :=
		wire.Bytes()

	if len(raw) < 20 {
		t.Fatalf(
			"wire bytes = %d, want at least 20",
			len(raw),
		)
	}

	if string(
		raw[0:8],
	) != transportgeneration.TransferMagic {
		t.Fatalf(
			"wire magic = %q, want %q",
			string(raw[0:8]),
			transportgeneration.TransferMagic,
		)
	}

	metadataBytes :=
		uint64(
			binary.BigEndian.Uint32(
				raw[8:12],
			),
		)

	payloadBytes :=
		binary.BigEndian.Uint64(
			raw[12:20],
		)

	if metadataBytes !=
		uint64(
			len(expectedMetadata),
		) {
		t.Fatalf(
			"wire metadata bytes = %d, want %d",
			metadataBytes,
			len(expectedMetadata),
		)
	}

	if payloadBytes !=
		uint64(
			len(expectedPayload),
		) {
		t.Fatalf(
			"wire payload bytes = %d, want %d",
			payloadBytes,
			len(expectedPayload),
		)
	}

	expectedWireBytes :=
		uint64(20) +
			metadataBytes +
			payloadBytes

	if uint64(
		len(raw),
	) != expectedWireBytes {
		t.Fatalf(
			"wire bytes = %d, want %d",
			len(raw),
			expectedWireBytes,
		)
	}

	metadataStart :=
		20

	metadataEnd :=
		metadataStart +
			int(
				metadataBytes,
			)

	payloadEnd :=
		metadataEnd +
			int(
				payloadBytes,
			)

	if !bytes.Equal(
		raw[metadataStart:metadataEnd],
		expectedMetadata,
	) {
		t.Fatal(
			"wire metadata is not the exact durable signed-generation.json bytes",
		)
	}

	if !bytes.Equal(
		raw[metadataEnd:payloadEnd],
		expectedPayload,
	) {
		t.Fatal(
			"wire payload is not the exact durable payload.figz bytes",
		)
	}

	metadataDigest :=
		sha256.Sum256(
			expectedMetadata,
		)

	payloadDigest :=
		sha256.Sum256(
			expectedPayload,
		)

	transferDigest :=
		sha256.Sum256(
			raw,
		)

	if result.MetadataSHA256 !=
		hex.EncodeToString(
			metadataDigest[:],
		) {
		t.Fatal(
			"metadata transfer SHA-256 mismatch",
		)
	}

	if result.PayloadSHA256 !=
		hex.EncodeToString(
			payloadDigest[:],
		) {
		t.Fatal(
			"payload transfer SHA-256 mismatch",
		)
	}

	if result.PayloadSHA256 !=
		result.Descriptor.EncodedDataSHA256 {
		t.Fatal(
			"transported payload SHA-256 does not match signed descriptor",
		)
	}

	if result.TransferBytes !=
		uint64(
			len(raw),
		) {
		t.Fatal(
			"exact transfer byte count mismatch",
		)
	}

	if result.TransferSHA256 !=
		hex.EncodeToString(
			transferDigest[:],
		) {
		t.Fatal(
			"exact transfer SHA-256 mismatch",
		)
	}
}

func TestSendTransportGenerationRejectsPayloadMutation(
	t *testing.T,
) {
	const sourceID = "iss-fs-01.iss.local"

	stageRoot :=
		t.TempDir()

	key, certificate :=
		testTransportGenerationSigningIdentity(
			t,
			sourceID,
		)

	published :=
		createTransportGenerationFixture(
			t,
			stageRoot,
			sourceID,
			"20260918T142000.000000000Z-cccccccccccccccc",
			key,
			certificate,
		)

	generation, found, err :=
		NextTransportGeneration(
			stageRoot,
			sourceID,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"transport generation was not found",
		)
	}

	file, err :=
		os.OpenFile(
			published.PayloadPath,
			os.O_RDWR,
			0,
		)
	if err != nil {
		t.Fatal(err)
	}

	var value [1]byte

	if _,
		err :=
		file.ReadAt(
			value[:],
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	value[0] ^= 0xff

	if _,
		err :=
		file.WriteAt(
			value[:],
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Close(); err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		SendTransportGeneration(
			&bytes.Buffer{},
			generation,
		); err == nil {
		t.Fatal(
			"mutated durable generation payload was sent successfully",
		)
	}
}

func createTransportGenerationFixture(
	t *testing.T,
	stageRoot string,
	sourceID string,
	generationID string,
	key *rsa.PrivateKey,
	certificate *x509.Certificate,
) transportgeneration.PublishedGeneration {
	t.Helper()

	frozen :=
		filepath.Join(
			t.TempDir(),
			"frozen",
		)

	if err :=
		os.MkdirAll(
			frozen,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	files :=
		map[string][]byte{
			"batch-a.manifest.json": []byte(
				"{\"batch\":\"a\"}\n",
			),

			"batch-a.jsonl": []byte(
				"{\"record\":1}\n",
			),

			"batch-b.manifest.json": []byte(
				"{\"batch\":\"b\"}\n",
			),

			"batch-b.jsonl": []byte(
				"{\"record\":2}\n{\"record\":3}\n",
			),
		}

	for name, value := range files {
		if err :=
			os.WriteFile(
				filepath.Join(
					frozen,
					name,
				),
				value,
				0o600,
			); err != nil {
			t.Fatal(err)
		}
	}

	published, err :=
		transportgeneration.CreateSealedGeneration(
			context.Background(),
			transportgeneration.CreateConfig{
				BatchSigner: key,

				BatchSigningCertificate: certificate,

				FrozenDir: frozen,

				GenerationID: generationID,

				SealedRoot: stageRoot,

				SourceID: sourceID,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	return published
}

func testTransportGenerationSigningIdentity(
	t *testing.T,
	sourceID string,
) (
	*rsa.PrivateKey,
	*x509.Certificate,
) {
	t.Helper()

	key, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	template :=
		&x509.Certificate{
			SerialNumber: bigIntOne(),

			Subject: pkix.Name{
				CommonName: sourceID,

				OrganizationalUnit: []string{
					transporttrust.BatchSigningOrganizationalUnit,
				},
			},

			NotBefore: time.Now().
				Add(
					-time.Hour,
				),

			NotAfter: time.Now().
				Add(
					time.Hour,
				),

			KeyUsage: x509.KeyUsageDigitalSignature,

			BasicConstraintsValid: true,
		}

	raw, err :=
		x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			&key.PublicKey,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err :=
		x509.ParseCertificate(
			raw,
		)
	if err != nil {
		t.Fatal(err)
	}

	return key, certificate
}

func bigIntOne() *big.Int {
	return big.NewInt(
		1,
	)
}
