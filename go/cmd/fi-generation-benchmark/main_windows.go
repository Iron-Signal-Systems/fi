// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Temporary R2 frozen-generation performance benchmark.
//
//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

func main() {
	var (
		batchSigningSHA string
		maxEncodedBytes uint64
		rawDir          string
		sourceID        string
		stageDir        string
	)

	flag.StringVar(
		&batchSigningSHA,
		"batch-signing-cert-sha256",
		"",
		"LocalMachine batch-signing certificate SHA-256",
	)

	flag.Uint64Var(
		&maxEncodedBytes,
		"max-encoded-bytes",
		68719476736,
		"maximum encoded generation size",
	)

	flag.StringVar(
		&rawDir,
		"raw-dir",
		"",
		"existing frozen FI generation directory",
	)

	flag.StringVar(
		&sourceID,
		"source",
		"",
		"FI source identity",
	)

	flag.StringVar(
		&stageDir,
		"stage-dir",
		"",
		"empty benchmark output directory",
	)

	flag.Parse()

	if rawDir == "" ||
		stageDir == "" ||
		sourceID == "" ||
		batchSigningSHA == "" {
		fail(errors.New(
			"raw-dir, stage-dir, source, and batch-signing-cert-sha256 are required",
		))
	}

	rawDir, err :=
		filepath.Abs(rawDir)

	if err != nil {
		fail(err)
	}

	stageDir, err =
		filepath.Abs(stageDir)

	if err != nil {
		fail(err)
	}

	rawInfo, err :=
		os.Lstat(rawDir)

	if err != nil {
		fail(err)
	}

	if !rawInfo.IsDir() ||
		rawInfo.Mode()&os.ModeSymlink != 0 {
		fail(errors.New(
			"raw-dir must be a real directory",
		))
	}

	base :=
		filepath.Base(rawDir)

	if !strings.HasPrefix(
		base,
		"generation-",
	) {
		fail(errors.New(
			"raw-dir basename must begin with generation-",
		))
	}

	generationID :=
		strings.TrimPrefix(
			base,
			"generation-",
		)

	if generationID == "" {
		fail(errors.New(
			"generation ID is empty",
		))
	}

	if err := os.MkdirAll(
		stageDir,
		0o700,
	); err != nil {
		fail(err)
	}

	stageEntries, err :=
		os.ReadDir(stageDir)

	if err != nil {
		fail(err)
	}

	if len(stageEntries) != 0 {
		fail(errors.New(
			"benchmark stage directory must be empty",
		))
	}

	totalStart :=
		time.Now()

	fmt.Printf(
		"BenchmarkGenerationID: %s\n",
		generationID,
	)

	fmt.Printf(
		"BenchmarkRawDir:       %s\n",
		rawDir,
	)

	fmt.Printf(
		"BenchmarkStageDir:     %s\n",
		stageDir,
	)

	scanStart :=
		time.Now()

	entries, err :=
		os.ReadDir(rawDir)

	if err != nil {
		fail(err)
	}

	manifestPaths :=
		make(
			[]string,
			0,
			len(entries)/2,
		)

	for _, entry := range entries {
		name :=
			entry.Name()

		if entry.Type()&os.ModeSymlink != 0 {
			fail(fmt.Errorf(
				"frozen generation contains symlink %q",
				name,
			))
		}

		if !entry.Type().IsRegular() {
			fail(fmt.Errorf(
				"frozen generation contains non-regular artifact %q",
				name,
			))
		}

		if strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".manifest.json",
			) {
			manifestPaths =
				append(
					manifestPaths,
					filepath.Join(
						rawDir,
						name,
					),
				)
		}
	}

	sort.Strings(manifestPaths)

	fmt.Printf(
		"DirectoryEntries:      %d\n",
		len(entries),
	)

	fmt.Printf(
		"ManifestCandidates:    %d\n",
		len(manifestPaths),
	)

	fmt.Printf(
		"DirectoryScanElapsed:  %s\n",
		time.Since(scanStart),
	)

	indexStart :=
		time.Now()

	index, _, err :=
		transportrecovery.BuildFrozenIndex(
			manifestPaths,
		)

	if err != nil {
		fail(err)
	}

	fmt.Printf(
		"IndexMembers:          %d\n",
		len(index.Members),
	)

	fmt.Printf(
		"IndexElapsed:          %s\n",
		time.Since(indexStart),
	)

	expected :=
		make(
			map[string]struct{},
			len(index.Members)*2,
		)

	for _, member := range index.Members {

		expected["batch-"+
			member.BatchID+
			".manifest.json"] =
			struct{}{}

		expected["batch-"+
			member.BatchID+
			".jsonl"] =
			struct{}{}
	}

	if len(entries) != len(expected) {
		fail(fmt.Errorf(
			"directory contains %d entries; expected exactly %d",
			len(entries),
			len(expected),
		))
	}

	for _, entry := range entries {

		if _, ok :=
			expected[entry.Name()]; !ok {

			fail(fmt.Errorf(
				"unexpected frozen generation artifact %q",
				entry.Name(),
			))
		}
	}

	canonicalBytes, err :=
		index.CanonicalBytes()

	if err != nil {
		fail(err)
	}

	fmt.Printf(
		"CanonicalBytesExpected:%d\n",
		canonicalBytes,
	)

	identityStart :=
		time.Now()

	identity, err :=
		certstore.LoadLocalMachineSigningIdentity(
			batchSigningSHA,
		)

	if err != nil {
		fail(err)
	}

	fmt.Printf(
		"SigningIdentityElapsed:%s\n",
		time.Since(identityStart),
	)

	prepareStart :=
		time.Now()

	prepared, err :=
		transportrecovery.PrepareFrame(
			transportrecovery.PrepareConfig{
				BatchSigner: identity.Signer,

				BatchSigningCertificate: identity.Certificate,

				Index: index,

				MaxEncodedBytes: maxEncodedBytes,

				RecoveryID: generationID,

				SourceID: sourceID,

				SourcesFrozen: true,

				StageDir: stageDir,
			},
		)

	closeErr :=
		identity.Close()

	if err != nil {
		fail(err)
	}

	if closeErr != nil {
		fail(closeErr)
	}

	fmt.Printf(
		"PrepareElapsed:        %s\n",
		time.Since(prepareStart),
	)

	validateStart :=
		time.Now()

	if err :=
		transportrecovery.ValidatePreparedFrameCanonical(
			prepared,
		); err != nil {
		fail(err)
	}

	fmt.Printf(
		"CanonicalValidateElapsed:%s\n",
		time.Since(validateStart),
	)

	fmt.Printf(
		"MemberCount:           %d\n",
		prepared.Descriptor.MemberCount,
	)

	fmt.Printf(
		"CanonicalBytes:        %d\n",
		prepared.Descriptor.CanonicalBytes,
	)

	fmt.Printf(
		"EncodedBytes:          %d\n",
		prepared.Descriptor.EncodedDataBytes,
	)

	fmt.Printf(
		"FrameBytes:            %d\n",
		prepared.FrameBytes,
	)

	fmt.Printf(
		"FrameSHA256:           %s\n",
		prepared.FrameSHA256,
	)

	fmt.Printf(
		"FramePath:             %s\n",
		prepared.FramePath,
	)

	fmt.Printf(
		"TotalElapsed:          %s\n",
		time.Since(totalStart),
	)

	fmt.Println(
		"PASS: frozen generation built and validated; raw generation was not modified",
	)
}

func fail(err error) {
	fmt.Fprintf(
		os.Stderr,
		"ERROR: %v\n",
		err,
	)

	os.Exit(1)
}
