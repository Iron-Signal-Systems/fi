# File Intelligence (FI) — Product Definition

## Product

**File Intelligence (FI)** is a read-only, historical file-intelligence platform.

FI builds and preserves an understanding of explicitly governed files over time so
IT professionals can answer difficult operational, security, support, recovery,
and investigation questions without repeatedly reconstructing the same file,
identity, access, and historical relationships by hand.

The file is the primary subject of FI.

FI is built around one simple question:

> **What do we know about this file?**

The answer may include the file's identity, location, state, storage, security,
access, activity, relationships, history, uncertainty, and later classification.

FI does not exist merely to collect events or report that a filesystem action
occurred. Activity is one part of the larger historical understanding of a file.

---

## Core Product Goal

FI exists to turn fragmented file-environment information into durable,
correlated, explainable intelligence.

Today, answering one file-related question may require an experienced
administrator to manually combine information from:

- NTFS;
- file and directory paths;
- file identity and metadata;
- Windows security descriptors and ACLs;
- SMB shares and share security;
- local Windows identities;
- Active Directory identities and group relationships;
- Windows Security activity;
- the USN journal;
- historical records;
- tickets, documentation, and institutional knowledge; and
- other source information required by the question.

FI is intended to preserve and correlate the applicable source facts once so the
resulting knowledge can be reused.

What takes an experienced professional hours to reconstruct manually should,
when FI has the required information, be answerable in seconds or minutes.

---

## File-Centered Intelligence

A pathname is not a file identity.

A file may be renamed, moved, linked, exposed through different shares, have its
security changed, become reachable through changing identity relationships, or
have different meaning at different points in time.

FI therefore treats a governed file as a historical object with relationships.

Where available and applicable, FI is intended to understand:

- file and volume identity;
- current and historical location;
- metadata and storage state;
- content identity and stream state;
- reparse and link relationships;
- NTFS security;
- SMB exposure and share security;
- local and directory identities;
- direct and later correlated group relationships;
- access-analysis inputs;
- observed governed-file activity;
- changes over time;
- continuity and collection gaps;
- classification and enrichment; and
- the relationship between all of those facts at a particular point in time.

The file remains the center of that history.

---

## Questions FI Exists to Answer

FI should eventually make questions such as these practical to answer:

- What file is this?
- Where is it now?
- Where has it been?
- Was it renamed, moved, replaced, linked, or modified?
- What was its state at a particular point in time?
- What security applied to it then?
- Which SMB shares exposed it?
- Who could access it?
- Why could that identity access it?
- Was access direct, inherited, share-derived, or obtained through group
  membership?
- When did that access relationship change?
- What identity, process, host, or session interacted with the file where the
  available source information can establish that?
- What changed before or during an incident?
- What governed files could a compromised identity potentially reach?
- Which other governed files are exposed by the same access relationship?
- Which facts are directly observed?
- Which conclusions are deterministically derived from those observations?
- What remains unknown, incomplete, stale, conflicting, or unavailable?
- Where did collection continuity fail?
- What current state can be re-established after a gap without pretending the
  missing history was reconstructed?

FI should make the limits of an answer visible rather than hide uncertainty.

---

## Professional in the Driver's Seat

FI is an intelligence system, not an autonomous administrator.

FI observes, preserves, correlates, explains, and presents.

The IT professional remains responsible for deciding:

- whether a condition is actually a problem;
- whether a change should be made;
- what operational risk is acceptable;
- whether additional investigation is required; and
- when an action should occur.

FI may identify conditions, relationships, risks, conflicts, or improvement
candidates. Those findings are information for a professional decision. They are
not authority to change the environment.

FI must not turn a recommendation, classification, detection, or inferred risk
into an automatic infrastructure change.

---

## Read-Only Product Boundary

FI is intentionally read-only toward the customer environment.

FI may observe the information required to build its historical model, but FI
does not:

- modify customer files;
- change ACLs or ownership;
- grant or revoke access;
- modify users or groups;
- change SMB shares;
- quarantine systems;
- alter network configuration;
- automatically remediate findings; or
- treat possession of credentials as permission to act.

Administrator-run deployment actions may configure prerequisites such as service
identities, audit policy, SACLs, or other required source settings. Those are
explicit customer administrative actions, not FI runtime behavior.

---

## What FI Is Not

FI is not defined by any single source or capability it uses.

FI is **not**:

- a file-auditing product;
- a general Windows event collector;
- a SIEM;
- an EDR platform;
- a DLP platform;
- a file manager;
- an Active Directory inventory product;
- an automated remediation platform; or
- a clone of a larger data-security suite.

FI may consume source information that some of those products also use. That
does not make FI one of those products.

Windows Security events, for example, are useful because they can contribute
actor, process, access, share, session, and outcome facts to the history of a
governed file. The event itself is not the product.

---

## Product Architecture Boundary

FI keeps responsibilities separate:

```text
Windows / File / Identity Sources
              |
              v
           Observe
              |
              v
     Preserve Source Facts
              |
              v
      Historical Records
              |
              v
          Correlate
              |
              v
       Query / Views / API
              |
              v
        Useful Answers
```

Collectors should remain source-focused and simple.

The backend owns historical preservation, cross-source correlation, derived
relationships, and higher-level interpretation.

The query and user-experience layers present that knowledge in forms appropriate
to the professional asking the question.

---

## FI and Atlas — Complementary Intelligence

FI and Atlas are separate products with different primary subjects.

**FI** centers on files, file state, storage, identity, access, activity, and
history.

**Atlas** centers on infrastructure: devices, interfaces, networks, paths,
policies, dependencies, topology, and infrastructure history.

Each product must remain useful when deployed independently.

When both are present, they can support a broader operational view without
collapsing into one product or one source of truth.

```text
                         Professional
                              |
                 asks an operational question
                              |
              +---------------+---------------+
              |                               |
              v                               v
             FI                             Atlas
   File / Identity / Access        Network / Infrastructure
   State / Activity / History      Path / Policy / Dependency
              |                               |
              +---------------+---------------+
                              |
                              v
                    Correlated Environment View
```

Examples of combined questions include:

- A compromised identity can reach these governed files. Where are the hosting
  systems located in the infrastructure and what network paths expose them?
- A file server is affected by an infrastructure outage. Which governed files,
  shares, identities, applications, or organizational functions may therefore be
  affected?
- An application cannot reach a file location. Does the problem come from file
  access, identity, SMB exposure, routing, firewall policy, or another network
  dependency?
- A network or firewall change occurred before a file-access problem began. What
  changed on each side and which relationships overlap?
- A server, VLAN, site, circuit, firewall, or network path is at risk. Which
  governed file resources and access relationships depend on infrastructure
  behind that boundary?

The products should exchange stable references and correlated relationships where
useful while preserving their own source ownership and historical integrity.

FI should not pretend to be the network authority, and Atlas should not pretend
to be the file authority.

Together they provide a wider view because each contributes the part of the
environment it actually understands.

---

## FI, Atlas, and Sentinel — Observe, Decide, Act, Verify

FI and Atlas remain read-only intelligence products even when Sentinel is
present.

Their job is to detect, reconstruct, explain, and verify. They do not gain
corrective authority merely because a controlled execution platform exists.

The professional remains in the driver's seat.

The intended Iron Signal Systems control model is:

```text
FI / Atlas
DETECT and EXPLAIN
      |
      v
Professional
DECIDE what should be done
      |
      v
DNP
GOVERN identity, authority, approval,
and the exact permitted operation
      |
      v
Sentinel
EXECUTE only the governed,
explicitly authorized operation
      |
      v
FI / Atlas
VERIFY through independent observation
```

In this model:

- FI and Atlas provide context, not authority;
- the professional decides whether action is appropriate;
- DNP determines whether the authenticated person may perform the exact governed
  operation;
- Sentinel provides the controlled execution path to the target platform;
- unrestricted platform access is not substituted for a governed operation;
- the executed action is attributable and reviewable; and
- FI or Atlas independently re-observes the environment rather than trusting an
  executor's claim that the intended state now exists.

This creates separation between **knowing**, **deciding**, **authorizing**,
**executing**, and **verifying**.

That separation is intentional.

A detection must never become authority simply because software can automate the
next step.

---

## Combined Operational View

The long-term value of the ISS products is not that one platform attempts to own
every domain.

The value comes from separately trustworthy products being able to contribute to
a larger operational picture.

```text
FI
Files / Identity / Access / History
                 \
                  \
                   > Professional Understanding
                  /
                 /
Atlas
Infrastructure / Path / Policy / Dependency

Professional Decision
        |
        v
Governed Authorization
        |
        v
Sentinel Execution
        |
        v
Independent FI / Atlas Verification
```

A professional investigating an incident or planning a change should be able to
move from a file or identity question into the related infrastructure context,
or from an infrastructure problem into the affected file and access context,
without surrendering control of the decision to the software.

The goal is better understanding, faster investigation, safer decisions, and
controlled execution — not autonomous administration.

---

## Product Success

FI succeeds when it gives professionals durable, explainable answers that would
otherwise require significant manual reconstruction.

Success means:

- the file remains the primary subject;
- historical state is preserved rather than overwritten;
- relationships can be explained;
- current conclusions can be traced back to preserved source facts;
- uncertainty and gaps remain visible;
- collection remains bounded and operationally responsible;
- FI remains read-only toward the customer environment;
- professionals retain decision authority; and
- integration with Atlas, Sentinel, or other ISS products increases context or
  control without weakening the independent boundaries of any product.

FI should reduce the time required to understand a file environment without
replacing the judgment of the professionals responsible for it.
