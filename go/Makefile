# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

SHELL := /usr/bin/env bash

.PHONY: fmt test test-windows-build build-windows verify

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

test:
	go test ./...

test-windows-build:
	GOOS=windows GOARCH=amd64 go test -c ./internal/windows/ntfs -o /tmp/fi-ntfs-windows.test.exe
	GOOS=windows GOARCH=amd64 go build -o /tmp/fi.exe ./cmd/fi

build-windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -o bin/fi.exe ./cmd/fi

verify: test test-windows-build
