// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Disposable C220 clone ONLY. The P12 experiment changes the bounded
// Security FIELD COPY envelope, never source/event/Security family buffer
// limits, PostgreSQL permissions, FK semantics, or the five SQL writers.
package recordingest

import "context"

type privateP12SecurityFieldEnvelopeKey struct{}

// This context is installed ONLY on the Security lane of the private P11
// five-family writer; all other lanes and the original P1/P3 defaults retain
// their existing limits. No environment-variable or global mutable selector.
func privateP12SecurityFieldEnvelopeContext(ctx context.Context) context.Context {
    return context.WithValue(ctx,privateP12SecurityFieldEnvelopeKey{},true)
}
func privateP12SecurityFieldEnvelopeSelected(ctx context.Context) bool {
    return ctx!=nil && ctx.Value(privateP12SecurityFieldEnvelopeKey{})==true
}
