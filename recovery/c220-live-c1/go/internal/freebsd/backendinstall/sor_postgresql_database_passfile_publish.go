// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"path/filepath"
)

type sorPostgreSQLDatabasePassfileInspectFunc func(
	sorPostgreSQLDatabasePolicy,
) (
	sorPostgreSQLDatabasePassfileFacts,
	string,
	error,
)

type sorPostgreSQLDatabasePassfilePublishFunc func(
	string,
	string,
	[]byte,
	uint64,
	uint64,
) error

type sorPostgreSQLDatabasePassfileStageFunc func(
	string,
	[]byte,
	uint64,
	uint64,
) (string, error)

type sorPostgreSQLDatabasePassfileSyncDirectoryFunc func(
	string,
) error

type sorPostgreSQLDatabasePassfilePrepareFunc func(
	sorPostgreSQLDatabasePolicy,
	string,
) (
	sorPostgreSQLDatabaseStagedPassfile,
	error,
)

type sorPostgreSQLDatabaseStagedPassfile struct {
	Content []byte
	Temp    string
}

func buildSORPostgreSQLDatabasePassfileContent(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
) ([]byte, error) {
	if policy.PassfilePath == "" {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL passfile path is required",
			)
	}

	if policy.PassfilePrefix == "" {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL passfile prefix is required",
			)
	}

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL credential secret is invalid",
			)
	}

	content :=
		[]byte(
			policy.PassfilePrefix +
				secret +
				"\n",
		)

	if len(content) >
		sorPostgreSQLDatabasePassfileMaximumBytes {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL passfile exceeds maximum size",
			)
	}

	parsedSecret,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	if !prefixMatches ||
		!secretValid ||
		parsedSecret != secret {
		return nil,
			fmt.Errorf(
				"generated FI PostgreSQL passfile does not satisfy policy",
			)
	}

	return content, nil
}

func publishSORPostgreSQLDatabasePassfile(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
) error {
	staged, err :=
		stageSORPostgreSQLDatabasePassfile(
			policy,
			secret,
		)
	if err != nil {
		return err
	}

	defer removeSORPostgreSQLPolicyTemp(
		staged.Temp,
	)

	return publishStagedSORPostgreSQLDatabasePassfile(
		policy,
		secret,
		staged,
	)
}

func publishSORPostgreSQLDatabasePassfileWith(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	stage sorPostgreSQLDatabasePassfileStageFunc,
	publish sorPostgreSQLDatabasePassfilePublishFunc,
	syncDirectory sorPostgreSQLDatabasePassfileSyncDirectoryFunc,
	inspect sorPostgreSQLDatabasePassfileInspectFunc,
) error {
	staged, err :=
		stageSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			stage,
		)
	if err != nil {
		return err
	}

	defer removeSORPostgreSQLPolicyTemp(
		staged.Temp,
	)

	return publishStagedSORPostgreSQLDatabasePassfileWith(
		policy,
		secret,
		staged,
		publish,
		syncDirectory,
		inspect,
	)
}

func publishStagedSORPostgreSQLDatabasePassfile(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	staged sorPostgreSQLDatabaseStagedPassfile,
) error {
	if err :=
		validateSORPostgreSQLDatabaseStagedPassfile(
			policy,
			secret,
			staged,
		); err != nil {
		return err
	}

	if err :=
		verifySORPostgreSQLExactPolicyFile(
			staged.Temp,
			staged.Content,
			sorPostgreSQLDatabasePassfileUID,
			sorPostgreSQLDatabasePassfileGID,
		); err != nil {
		return fmt.Errorf(
			"verify staged FI PostgreSQL passfile before publication: %w",
			err,
		)
	}

	return publishStagedSORPostgreSQLDatabasePassfileWith(
		policy,
		secret,
		staged,
		publishAbsentSORPostgreSQLPolicyFile,
		syncHostFileDirectory,
		inspectSORPostgreSQLDatabasePassfile,
	)
}

func publishStagedSORPostgreSQLDatabasePassfileWith(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	staged sorPostgreSQLDatabaseStagedPassfile,
	publish sorPostgreSQLDatabasePassfilePublishFunc,
	syncDirectory sorPostgreSQLDatabasePassfileSyncDirectoryFunc,
	inspect sorPostgreSQLDatabasePassfileInspectFunc,
) error {
	if publish == nil {
		return fmt.Errorf(
			"FI PostgreSQL passfile publication function is required",
		)
	}

	if syncDirectory == nil {
		return fmt.Errorf(
			"FI PostgreSQL passfile directory sync function is required",
		)
	}

	if inspect == nil {
		return fmt.Errorf(
			"FI PostgreSQL passfile inspection function is required",
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseStagedPassfile(
			policy,
			secret,
			staged,
		); err != nil {
		return err
	}

	if err :=
		publish(
			staged.Temp,
			policy.PassfilePath,
			staged.Content,
			sorPostgreSQLDatabasePassfileUID,
			sorPostgreSQLDatabasePassfileGID,
		); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL passfile: %w",
			err,
		)
	}

	if err :=
		syncDirectory(
			filepath.Dir(
				policy.PassfilePath,
			),
		); err != nil {
		return fmt.Errorf(
			"sync FI PostgreSQL passfile directory: %w",
			err,
		)
	}

	facts,
		observedSecret,
		err :=
		inspect(
			policy,
		)
	if err != nil {
		return fmt.Errorf(
			"verify published FI PostgreSQL passfile: %w",
			err,
		)
	}

	if observedSecret != secret {
		return fmt.Errorf(
			"published FI PostgreSQL passfile secret does not match generated credential",
		)
	}

	if state :=
		classifySORPostgreSQLDatabasePassfile(
			facts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		return fmt.Errorf(
			"published FI PostgreSQL passfile state = %s, want OWNED_MATCH",
			state,
		)
	}

	return nil
}

func stageSORPostgreSQLDatabasePassfile(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
) (
	sorPostgreSQLDatabaseStagedPassfile,
	error,
) {
	return stageSORPostgreSQLDatabasePassfileWith(
		policy,
		secret,
		stageSORPostgreSQLPolicyFile,
	)
}

func stageSORPostgreSQLDatabasePassfileWith(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	stage sorPostgreSQLDatabasePassfileStageFunc,
) (
	sorPostgreSQLDatabaseStagedPassfile,
	error,
) {
	if stage == nil {
		return sorPostgreSQLDatabaseStagedPassfile{},
			fmt.Errorf(
				"FI PostgreSQL passfile staging function is required",
			)
	}

	content, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			policy,
			secret,
		)
	if err != nil {
		return sorPostgreSQLDatabaseStagedPassfile{},
			err
	}

	temp, err :=
		stage(
			policy.PassfilePath,
			content,
			sorPostgreSQLDatabasePassfileUID,
			sorPostgreSQLDatabasePassfileGID,
		)
	if err != nil {
		return sorPostgreSQLDatabaseStagedPassfile{},
			fmt.Errorf(
				"stage FI PostgreSQL passfile: %w",
				err,
			)
	}

	staged :=
		sorPostgreSQLDatabaseStagedPassfile{
			Content: append(
				[]byte(nil),
				content...,
			),
			Temp: temp,
		}

	if err :=
		validateSORPostgreSQLDatabaseStagedPassfile(
			policy,
			secret,
			staged,
		); err != nil {
		removeSORPostgreSQLPolicyTemp(
			temp,
		)

		return sorPostgreSQLDatabaseStagedPassfile{},
			err
	}

	return staged, nil
}

func validateSORPostgreSQLDatabaseStagedPassfile(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	staged sorPostgreSQLDatabaseStagedPassfile,
) error {
	if staged.Temp == "" {
		return fmt.Errorf(
			"staged FI PostgreSQL passfile path is required",
		)
	}

	expected, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			policy,
			secret,
		)
	if err != nil {
		return err
	}

	if !bytes.Equal(
		staged.Content,
		expected,
	) {
		return fmt.Errorf(
			"staged FI PostgreSQL passfile content does not match generated credential",
		)
	}

	return nil
}
