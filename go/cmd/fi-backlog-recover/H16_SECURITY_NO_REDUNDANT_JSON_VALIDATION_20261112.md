# FI Security source JSON: single decode, no redundant validity checks

**Status: development source staged; FreeBSD execution/performance has not yet been measured for this revision.** The accepted private two-window H16+SHA-once+JSON-once result remains 89.931s / 2,881.9 records/sec with the earlier pinned source.

## Established trust boundary

The Windows collector validates the source JSON before it is sent to the sender and batched. The receiver authenticates and verifies the signed batch; the private FreeBSD source-to-database COW handoff reuses that proven batch digest. Repeating a JSON syntax-validation traversal is unnecessary work. The backend **must still decode** bytes to materialize typed relational rows, and decoder failures must still reject input (including corrupt or malformed cache items).

## Changes

- `go/internal/recordingest/security_single_pass_candidate.go`: removed every explicit `json.Valid(...)` call from the Security fast path, including the old smaller scope and written-at string checks and the rare strict-decoder-error recheck.
- One mandatory `decodeStrictPayload(json.RawMessage(body), &parsed)` remains. Its JSONv2 strict typed decoder provides the parser, error checks, nested field type handling and unknown-member rejection. It does not run a second syntax validator.
- The small canonical shape guards and existing comma scan remain only to locate the original payload byte span for exact signed source-record evidence. No replacement structural scanner has been introduced.
- Any decoding error is rejected directly. The general signed-record path already uses strict decoding without standalone `json.Valid`.
- Record SHA-256, Windows Security event value validation, SQL COPY, signed-cache custody, immutable H16 baseline, 10-minute-window transaction boundary, and PostgreSQL settings are unchanged.

## Tests

`go/internal/recordingest/security_json_once_test.go` retains the independent historical source-selection oracle (which intentionally calls `json.Valid` **only in tests**, never in the ingestion code). Added malformed JSON tests for `scope_id`, `written_at` and nested Security `event_id` values: the single strict parser must reject all three. Existing real signed 512-record preflight and hard W3/W4 one-pass-selection acceptance gates stay in the pinned runner.

Latest source blob `9d7ba5fd99dc79d859023885810a95e869b8c1f1`; latest unit test blob `d8b7603774f91209471ce42e311caf45f3d3fd9e`; runner blob `2a0bf21c32628ff1d4f3dc426fc3722ae8984cf6`.

**Important:** Do not claim new performance gains from these latest changes until they are run in the private FreeBSD fixture. The previously accepted W3/W4 results cannot be attributed to this later edit.
