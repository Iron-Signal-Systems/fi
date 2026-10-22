// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

type identityPrefetchNoSQLTx struct{ pgx.Tx }

func TestCanonicalNTFSIdentityNumber(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"0", "0"}, {"0000000000123", "123"}, {"18446744073709551615", "18446744073709551615"},
	} {
		got, err := canonicalNTFSIdentityNumber(test.input)
		if err != nil || got != test.want {
			t.Fatalf("canonical %q got=%q err=%v want=%q", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{"", "-1", "not-an-ID", "1.5", "0x123"} {
		if _, err := canonicalNTFSIdentityNumber(input); err == nil {
			t.Fatalf("accepted malformed NTFS identity %q", input)
		}
	}
}

func TestNTFSIdentityPrefetchArrayOrdering(t *testing.T) {
	requests := []*ntfsIdentityPrefetchRequest{
		{key: ntfsIdentityPrefetchKey{volumeID: 2, frn: "100", sequence: "7"}, method: "v1"},
		{key: ntfsIdentityPrefetchKey{volumeID: 3, frn: "101", sequence: "8"}, method: "v2"},
	}
	volumes, frns, sequences, methods := ntfsIdentityPrefetchArrays(requests)
	if len(volumes) != 2 || volumes[0] != 2 || volumes[1] != 3 || frns[0] != "100" || sequences[1] != "8" || methods[0] != "v1" {
		t.Fatalf("batch argument order corrupted: %#v %#v %#v %#v", volumes, frns, sequences, methods)
	}
}

func TestNTFSIdentityPrefetchBounds(t *testing.T) {
	req := &ntfsIdentityPrefetchRequest{key: ntfsIdentityPrefetchKey{volumeID: 1, frn: "4", sequence: "1"}, method: "v1", originals: []records.NTFSObjectIdentity{{MethodVersion: "v1", FileReferenceNumber: "4", SequenceNumber: "1"}}}
	// A nil transaction cannot be used even with a valid cache and context.
	err := prefetchNTFSObjectBatch(context.Background(), nil, newNTFSObjectCache(), []*ntfsIdentityPrefetchRequest{req})
	if err == nil {
		t.Fatal("accepted missing transaction")
	}
	over := make([]*ntfsIdentityPrefetchRequest, ntfsIdentityPrefetchBatchRows+1)
	err = prefetchNTFSObjectBatch(context.Background(), identityPrefetchNoSQLTx{}, newNTFSObjectCache(), over)
	if err == nil || !strings.Contains(err.Error(), "bounds") {
		t.Fatalf("unbounded batch accepted: %v", err)
	}
}
