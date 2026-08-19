SHELL := /usr/bin/env bash

.PHONY: fmt test test-windows-build verify

fmt:
	gofmt -w $$(find internal -name '*.go' -type f)

test:
	go test ./...

test-windows-build:
	GOOS=windows GOARCH=amd64 go test -c ./internal/windows/ntfs -o /tmp/fi-ntfs-windows.test.exe
	GOOS=windows GOARCH=amd64 go test -c ./internal/windows/readbroker -o /tmp/fi-readbroker-windows.test.exe

verify: test test-windows-build
