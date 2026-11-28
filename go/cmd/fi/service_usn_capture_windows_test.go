// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "testing"
)

func TestDrainUSNCaptureStopsAtHead(t *testing.T) {
    calls := 0
    count, saturated, err := drainUSNCapture(context.Background(), func(context.Context) (bool, error) {
        calls++
        return calls <= 3, nil
    }, 32)
    if err != nil || count != 3 || saturated || calls != 4 {
        t.Fatalf("expected three captured segments and then journal head; count=%d saturated=%v calls=%d err=%v", count, saturated, calls, err)
    }
}

func TestDrainUSNCaptureYieldsAfterBurst(t *testing.T) {
    calls := 0
    count, saturated, err := drainUSNCapture(context.Background(), func(context.Context) (bool, error) {
        calls++
        return true, nil
    }, 5)
    if err != nil || count != 5 || !saturated || calls != 5 {
        t.Fatalf("expected bounded burst to yield; count=%d saturated=%v calls=%d err=%v", count, saturated, calls, err)
    }
}

func TestDrainUSNCapturePropagatesGapWithoutSkipping(t *testing.T) {
    expected := errors.New("journal checkpoint aged out")
    calls := 0
    count, saturated, err := drainUSNCapture(context.Background(), func(context.Context) (bool, error) {
        calls++
        if calls == 2 {
            return false, expected
        }
        return true, nil
    }, 32)
    if !errors.Is(err, expected) || count != 1 || saturated {
        t.Fatalf("expected fail-closed after one segment; count=%d saturated=%v err=%v", count, saturated, err)
    }
}

func TestDrainUSNCaptureHonorsCancellation(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    calls := 0
    count, _, err := drainUSNCapture(ctx, func(context.Context) (bool, error) {
        calls++
        cancel()
        return true, nil
    }, 32)
    if !errors.Is(err, context.Canceled) || count != 1 || calls != 1 {
        t.Fatalf("expected cancellation after first segment; count=%d calls=%d err=%v", count, calls, err)
    }
}
