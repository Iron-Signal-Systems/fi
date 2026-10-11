// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	sorPostgreSQLDatabasePassfileMaximumBytes = 4096

	sorPostgreSQLDatabaseSCRAMMaximumIterations = 1000000
)

func inspectSORPostgreSQLDatabasePassfile(
	policy sorPostgreSQLDatabasePolicy,
) (
	sorPostgreSQLDatabasePassfileFacts,
	string,
	error,
) {
	info, err :=
		os.Lstat(
			policy.PassfilePath,
		)

	if os.IsNotExist(err) {
		return sorPostgreSQLDatabasePassfileFacts{
				Observed: true,
			},
			"",
			nil
	}

	if err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			fmt.Errorf(
				"inspect FI PostgreSQL passfile: %w",
				err,
			)
	}

	facts :=
		sorPostgreSQLDatabasePassfileFacts{
			Exists:   true,
			Observed: true,
			Regular:  info.Mode().IsRegular(),
		}

	if err := populateSORPostgreSQLDatabasePassfileMetadata(
		&facts,
		info,
	); err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			err
	}

	if !facts.Regular {
		return facts,
			"",
			nil
	}

	file, err :=
		os.Open(
			policy.PassfilePath,
		)
	if err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			fmt.Errorf(
				"open FI PostgreSQL passfile: %w",
				err,
			)
	}

	defer file.Close()

	openedInfo, err :=
		file.Stat()
	if err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			fmt.Errorf(
				"stat opened FI PostgreSQL passfile: %w",
				err,
			)
	}

	if !os.SameFile(
		info,
		openedInfo,
	) {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			fmt.Errorf(
				"FI PostgreSQL passfile changed during inspection",
			)
	}

	facts.Regular =
		openedInfo.Mode().IsRegular()

	if err := populateSORPostgreSQLDatabasePassfileMetadata(
		&facts,
		openedInfo,
	); err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			err
	}

	content, err :=
		io.ReadAll(
			io.LimitReader(
				file,
				sorPostgreSQLDatabasePassfileMaximumBytes+1,
			),
		)
	if err != nil {
		return sorPostgreSQLDatabasePassfileFacts{},
			"",
			fmt.Errorf(
				"read FI PostgreSQL passfile: %w",
				err,
			)
	}

	if len(content) >
		sorPostgreSQLDatabasePassfileMaximumBytes {
		return facts,
			"",
			nil
	}

	secret,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	facts.PrefixMatches =
		prefixMatches

	facts.SecretValid =
		secretValid

	return facts,
		secret,
		nil
}

func parseSORPostgreSQLDatabasePassfile(
	policy sorPostgreSQLDatabasePolicy,
	content []byte,
) (
	string,
	bool,
	bool,
) {
	text :=
		string(content)

	prefixMatches :=
		strings.HasPrefix(
			text,
			policy.PassfilePrefix,
		)

	if !prefixMatches {
		return "",
			false,
			false
	}

	if !strings.HasSuffix(
		text,
		"\n",
	) ||
		strings.Count(
			text,
			"\n",
		) != 1 {
		return "",
			true,
			false
	}

	line :=
		strings.TrimSuffix(
			text,
			"\n",
		)

	secret :=
		strings.TrimPrefix(
			line,
			policy.PassfilePrefix,
		)

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return secret,
			true,
			false
	}

	return secret,
		true,
		true
}

func verifySORPostgreSQLDatabaseSCRAMSHA256(
	secret string,
	verifier string,
) (
	bool,
	error,
) {
	if verifier !=
		strings.TrimSpace(
			verifier,
		) {
		return false,
			fmt.Errorf(
				"PostgreSQL SCRAM verifier contains surrounding whitespace",
			)
	}

	parts :=
		strings.Split(
			verifier,
			"$",
		)

	if len(parts) != 3 ||
		parts[0] !=
			"SCRAM-SHA-256" {
		return false,
			fmt.Errorf(
				"invalid PostgreSQL SCRAM-SHA-256 verifier format",
			)
	}

	iterationSalt :=
		strings.Split(
			parts[1],
			":",
		)

	if len(iterationSalt) != 2 {
		return false,
			fmt.Errorf(
				"invalid PostgreSQL SCRAM iteration/salt field",
			)
	}

	iterations, err :=
		strconv.Atoi(
			iterationSalt[0],
		)
	if err != nil {
		return false,
			fmt.Errorf(
				"invalid PostgreSQL SCRAM iteration count: %w",
				err,
			)
	}

	if iterations < 1 ||
		iterations >
			sorPostgreSQLDatabaseSCRAMMaximumIterations {
		return false,
			fmt.Errorf(
				"PostgreSQL SCRAM iteration count outside accepted bounds",
			)
	}

	salt, err :=
		base64.StdEncoding.DecodeString(
			iterationSalt[1],
		)
	if err != nil {
		return false,
			fmt.Errorf(
				"decode PostgreSQL SCRAM salt: %w",
				err,
			)
	}

	if len(salt) == 0 ||
		len(salt) >
			sorPostgreSQLDatabasePassfileMaximumBytes {
		return false,
			fmt.Errorf(
				"PostgreSQL SCRAM salt length outside accepted bounds",
			)
	}

	keys :=
		strings.Split(
			parts[2],
			":",
		)

	if len(keys) != 2 {
		return false,
			fmt.Errorf(
				"invalid PostgreSQL SCRAM key field",
			)
	}

	storedKey, err :=
		base64.StdEncoding.DecodeString(
			keys[0],
		)
	if err != nil {
		return false,
			fmt.Errorf(
				"decode PostgreSQL SCRAM stored key: %w",
				err,
			)
	}

	serverKey, err :=
		base64.StdEncoding.DecodeString(
			keys[1],
		)
	if err != nil {
		return false,
			fmt.Errorf(
				"decode PostgreSQL SCRAM server key: %w",
				err,
			)
	}

	if len(storedKey) !=
		sha256.Size ||
		len(serverKey) !=
			sha256.Size {
		return false,
			fmt.Errorf(
				"invalid PostgreSQL SCRAM key length",
			)
	}

	saltedPassword :=
		deriveSORPostgreSQLDatabaseSCRAMSHA256(
			[]byte(secret),
			salt,
			iterations,
		)

	clientMAC :=
		hmac.New(
			sha256.New,
			saltedPassword,
		)

	_, _ =
		clientMAC.Write(
			[]byte("Client Key"),
		)

	clientKey :=
		clientMAC.Sum(nil)

	calculatedStoredKey :=
		sha256.Sum256(
			clientKey,
		)

	serverMAC :=
		hmac.New(
			sha256.New,
			saltedPassword,
		)

	_, _ =
		serverMAC.Write(
			[]byte("Server Key"),
		)

	calculatedServerKey :=
		serverMAC.Sum(nil)

	return hmac.Equal(
			calculatedStoredKey[:],
			storedKey,
		) &&
			hmac.Equal(
				calculatedServerKey,
				serverKey,
			),
		nil
}

func deriveSORPostgreSQLDatabaseSCRAMSHA256(
	password []byte,
	salt []byte,
	iterations int,
) []byte {
	block :=
		make(
			[]byte,
			4,
		)

	binary.BigEndian.PutUint32(
		block,
		1,
	)

	mac :=
		hmac.New(
			sha256.New,
			password,
		)

	_, _ =
		mac.Write(
			salt,
		)

	_, _ =
		mac.Write(
			block,
		)

	current :=
		mac.Sum(nil)

	result :=
		append(
			[]byte(nil),
			current...,
		)

	for iteration := 1; iteration < iterations; iteration++ {
		mac =
			hmac.New(
				sha256.New,
				password,
			)

		_, _ =
			mac.Write(
				current,
			)

		current =
			mac.Sum(nil)

		for index := range result {
			result[index] ^=
				current[index]
		}
	}

	return result
}

func isSORPostgreSQLDatabaseCredentialSecret(
	secret string,
) bool {
	if len(secret) != 64 {
		return false
	}

	for _, character := range secret {
		if character >= '0' &&
			character <= '9' {
			continue
		}

		if character >= 'a' &&
			character <= 'f' {
			continue
		}

		return false
	}

	return true
}

func populateSORPostgreSQLDatabasePassfileMetadata(
	facts *sorPostgreSQLDatabasePassfileFacts,
	info os.FileInfo,
) error {
	stat, ok :=
		info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf(
			"FI PostgreSQL passfile metadata does not expose syscall.Stat_t",
		)
	}

	facts.GID =
		uint64(
			stat.Gid,
		)

	facts.LinkCount =
		uint64(
			stat.Nlink,
		)

	facts.Mode =
		uint32(
			info.Mode().Perm(),
		)

	facts.UID =
		uint64(
			stat.Uid,
		)

	return nil
}
