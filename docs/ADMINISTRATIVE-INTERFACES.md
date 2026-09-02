# FI Administrative Interfaces

## Purpose

FI's administrative and diagnostic interfaces exist for professionals who deploy,
operate, validate, troubleshoot, and verify FI itself.

They are not governed by the same abstraction boundary as the product/query user
experience.

The product UX answers questions about the customer's environment.
Administrative interfaces answer questions about FI's operation.

Both represent the same underlying FI truth.

---

## Core Rule

> **Administrative interfaces favor precision over abstraction.**

A professional running FI locally on a governed Windows system or diagnosing an
FI service is operating at the engineering boundary. FI should therefore expose
the actual technical information required to understand what the system did,
what source it used, where its durable boundary is, and why an operation failed
or became incomplete.

Administrative output must not replace technically meaningful information with a
generic friendly status when the underlying information is available.

---

## Information That Should Remain Explicit

Where applicable to the operation, administrative and diagnostic interfaces may
and should expose technical information such as:

- `FICollector` and `FIUSNReader` service identity;
- Windows service SID and gMSA identity;
- relevant enabled or unavailable privileges;
- governed root and associated volume;
- volume identity and filesystem information;
- USN Journal ID;
- `FirstUSN`, `LowestValidUSN`, `NextUSN`, and accepted USN checkpoint;
- Windows Security Event Record ID and accepted Security checkpoint;
- source/feed status;
- operation identifier and operation lifecycle status;
- spool batch and manifest identity;
- record count, byte count, and integrity verification status;
- continuity and reconciliation status;
- Windows error code and the operation that produced it;
- source-unavailable, access-denied, interrupted, or resource-related status;
- exact supported build/version behavior where FI intentionally branches on a
  characterized platform; and
- other bounded source or runtime facts required to understand FI's behavior.

Friendly explanatory text may accompany those facts. It must not replace them.

---

## Failure Presentation

An administrative failure should identify, where FI knows the information:

1. **what operation failed**;
2. **which governed scope or source was involved**;
3. **the last accepted durable boundary**;
4. **the newly observed boundary or state, when applicable**;
5. **the operating-system or FI error/status**;
6. **what FI did in response**; and
7. **whether coverage or history is now incomplete**.

For example, a USN continuity failure should expose the relevant Journal ID and
USN boundaries rather than only reporting that collection encountered a problem.

A Security source failure should expose the applicable event/checkpoint boundary
and Windows status rather than only reporting that activity collection failed.

A spool failure should identify the affected batch or finalization boundary and
must not imply that a checkpoint advanced when the applicable durable boundary
was not satisfied.

---

## No False Simplicity

Administrative interfaces must not hide:

- continuity gaps;
- checkpoint state;
- partial or incomplete collection;
- degraded source coverage;
- privilege-boundary failures;
- source-specific ambiguity;
- operating-system errors that materially explain a failure; or
- FI's own recovery or reconciliation actions.

A simplified summary may be shown first, but the underlying technical state must
remain directly available to the administrator.

---

## Stable Truth Across Interfaces

The product UX and administrative interfaces may use different language and
different levels of detail, but they do not maintain separate truths.

```text
                 FI Historical Truth
                        |
           +------------+------------+
           |                         |
           v                         v
      Product / Query UX       Administrative CLI
           |                         |
  Environment questions        FI operation questions
           |                         |
  What happened?               What source was used?
  Why?                         What checkpoint advanced?
  Who has access?              What Windows operation failed?
  What changed?                What spool batch was accepted?
           |                         |
           +------------+------------+
                        |
                  SAME FI TRUTH
```

An authorized user may drill from a product answer into deeper FI source facts.
An administrator may start directly at those source and runtime facts. Neither
interface is allowed to contradict the authoritative history or hide known
uncertainty.

---

## Engineering Guidance

New administrative commands, diagnostic modes, validation tools, and local
runtime status output should be reviewed against this contract.

If an engineering choice makes an administrative interface easier to read but
removes information required to diagnose or verify FI, the information should be
restored or made directly accessible.

If an engineering choice exposes internal implementation detail that is not
needed to operate or verify FI, that detail does not become mandatory merely
because it exists.

The goal is precise operational transparency, not uncontrolled debug output.
