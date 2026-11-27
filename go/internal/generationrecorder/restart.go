// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"context"
	"errors"
	"io"
	"fmt"
	"io"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// RecordDiscoveredCustodyDurably processes one custody object returned by
// transportgeneration restart recovery.
//
// The custody payload is streamed once through transport validation and the
// collector semantic recorder gate. Only then may the immutable recorded
// receipt be published. The durable FIGT custody object is retained.
//
// This function deliberately does not transmit a generation acknowledgement or
// retire sender-side state.
func RecordDiscoveredCustodyDurably(
	discovered transportgeneration.DiscoveredCustody,
	custodyConfig transportgeneration.CustodyConfig,
	recorderConfig DurableConfig,
) (DurableResult,error) {
	return RecordDiscoveredCustodyDurablyContext(context.Background(),discovered,custodyConfig,recorderConfig)
}

// Backfill uses this source-compatible cancellation-aware entry point.
// The live receiver's existing startup behavior remains unchanged.
func RecordDiscoveredCustodyDurablyContext(ctx context.Context,
	discovered transportgeneration.DiscoveredCustody,
	custodyConfig transportgeneration.CustodyConfig,
	recorderConfig DurableConfig,
) (DurableResult,error) {
	if ctx==nil{return DurableResult{},errors.New("FI recorder: context required")}
	if err:=ctx.Err();err!=nil{return DurableResult{},err}
	if err := validateDurableConfig(recorderConfig); err != nil {
		return DurableResult{}, err
	}

	cache, err := newReceiverVerifiedBatchWriter(recorderConfig.VerifiedBatchRoot)
	if err != nil { return DurableResult{}, err }
	if cache != nil { defer cache.Discard() }
	var state *validator

	custody, err := transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
		discovered,
		custodyConfig,
		func(
			descriptor transportgeneration.Descriptor,
		) (
			transportgeneration.CanonicalArtifactHandler,
			error,
		) {
			if state != nil {
				return nil, errors.New(
					"FI generation restart recorder validator was initialized more than once",
				)
			}

			created, err := newValidator(
				descriptor,
				recorderConfig.Semantic,
			)
			if err != nil {
				return nil, err
			}

			state = created
			return func(name string, reader io.Reader) error {
				if err:=ctx.Err();err!=nil{return err}
				bounded:=receiverCacheContextReader{ctx:ctx,reader:reader}
				if cache == nil { return state.consumeArtifact(name,&bounded) }
				return cache.Consume(name,&bounded,state.consumeArtifact)
			}, nil
		},
	)
	if err != nil {
		return DurableResult{}, fmt.Errorf(
			"read restart-discovered FI generation custody for recorder: %w",
			err,
		)
	}

	if state == nil {
		return DurableResult{}, errors.New(
			"FI generation restart recorder validator was not initialized",
		)
	}

	semantic, err := state.result(
		custody.Transfer.Descriptor,
		custody.Transfer.Descriptor.SourceBytes,
	)
	if err != nil {
		return DurableResult{}, err
	}

	recorded, err := publishRecordedSemanticResult(
		custody.Transfer,
		semantic,
		recorderConfig,
	)
	if err != nil { return DurableResult{}, err }
	if cache != nil {
		if err := cache.Publish(recorded); err != nil {
			return DurableResult{}, fmt.Errorf("publish receiver-authenticated restart cache: %w",err)
		}
	}
	return recorded, nil

}

// receiverCacheContextReader makes one-time historical backfill interruptible
// during the large immutable signed batch stream without changing custody.
type receiverCacheContextReader struct {
	ctx context.Context
	reader io.Reader
}
func(r *receiverCacheContextReader)Read(b []byte)(int,error){
	if err:=r.ctx.Err();err!=nil{return 0,err}
	return r.reader.Read(b)
}
