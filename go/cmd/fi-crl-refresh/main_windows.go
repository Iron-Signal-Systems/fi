// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
)

func main() {
	isService, err :=
		runWindowsCRLRefresherServiceIfNeeded()
	if err != nil {
		fail(err)
	}

	if isService {
		return
	}

	once :=
		flag.Bool(
			"once",
			false,
			"perform one CRL refresh attempt and exit",
		)

	flag.Parse()

	ctx, stop :=
		signal.NotifyContext(
			context.Background(),
			os.Interrupt,
		)
	defer stop()

	config :=
		defaultRuntimeConfig()

	dependencies :=
		defaultRuntimeDependencies()

	if *once {
		if _, err := runRefreshAttempt(
			ctx,
			config,
			dependencies,
		); err != nil {
			fail(err)
		}

		return
	}

	if err := runRefreshLoop(
		ctx,
		config,
		dependencies,
	); err != nil {
		fail(err)
	}
}

func fail(
	err error,
) {
	fmt.Fprintln(
		os.Stderr,
		err,
	)

	os.Exit(
		1,
	)
}
