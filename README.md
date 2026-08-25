# File Intelligence (FI)

<p align="center">
  <img src="docs/images/fi.png" alt="FI — File Intelligence" width="100%">
</p>

**File Intelligence (FI)** is a read-only system for building a historical
understanding of explicitly governed files.

FI is designed around a simple question:

> **What do we know about this file?**

Over time that includes its identity, locations, metadata, storage, security,
access, activity, relationships, history, and later classification.

The file remains the center of that history.

FI does not modify customer files, permissions, identities, shares, systems, or
infrastructure.

---

## Why FI exists

Understanding a file in a real environment often requires information from many
different sources.

A question such as:

> Why can this user access this file?

may require correlating:

- the file's identity;
- current and historical paths;
- NTFS permissions;
- SMB share permissions;
- local identities;
- Active Directory identities and membership;
- inheritance;
- effective-access inputs;
- changes to permissions;
- governed-file activity; and
- the state of those facts at the time being investigated.

A different question may start with an identity:

> If this account is compromised, what governed files could it affect?

Or with a file:

> Where has this file been, who could access it, what happened to it, and what
> changed?

FI preserves the source facts needed to answer those questions without changing
the systems being examined.

---

## File-centered intelligence

FI treats a governed file as more than a pathname.

A pathname can change. A file can be renamed, moved, exposed through different
shares, have its permissions changed, or have relationships to different
identities over time.

For a governed file, FI is intended to answer questions such as:

- What file is this?
- Where is it now?
- Where has it been?
- Has it been renamed or moved?
- What metadata has been observed?
- What NTFS security applied to it?
- What SMB shares exposed it?
- Who could access it?
- Why could that identity access it?
- Was access direct, inherited, or obtained through group membership?
- When did access change?
- Who changed permissions when the available source information can establish
  that?
- What access, attempted access, modification, creation, deletion, rename/move,
  or security activity involving the file has been observed?
- What was known about the file at a particular point in time?
- Where are there gaps that prevent FI from making a definitive conclusion?
- What classification was later associated with a particular observation?

FI must distinguish between what was directly observed, what can be
deterministically derived, what was classified, and what remains unknown or
incomplete.

A gap in available information must never be presented as proof that an event
did not occur.

---

## Governed-file activity

FI is not intended to become a general Windows event collector or SIEM.

Activity collection is file-centered.

FI should preserve Windows activity when it concerns a governed file or
directory, including where observable:

- access and attempted access;
- successful and denied access;
- creation;
- modification;
- deletion;
- rename and move activity;
- ownership, ACL, and other security changes;
- hard-link activity; and
- SMB/share activity associated with the governed object.

Where Windows provides the information, FI should preserve source facts such as:

- account/SID;
- process;
- object identity and path;
- access requested or used;
- success/failure;
- timestamp and source record identity;
- share used;
- remote workstation or IP; and
- session/logon identifiers needed to explain the governed-object activity.

Supporting SMB, logon, or session records are collected only when needed to
explain activity associated with governed objects. FI does not collect broad
server activity merely because Windows exposes it.

Windows auditing is not perfect. FI must report coverage and limitations
explicitly and must never interpret the absence of an event as proof that no
activity occurred.

---

## Useful across IT

FI records one underlying history. Different parts of an IT organization can use
views over that same recorded and correlated information for different purposes.

### Service Desk

Examples include:

- Why did a user lose access to a file or directory?
- What access should the user currently have?
- Through which group or ACL is access granted?
- Did something recently change?

### Developers and DevOps

Examples include:

- What application files changed?
- Which identities can modify application-controlled locations?
- Did filesystem security or ownership change around a deployment?
- What related file state changed during an incident or application failure?

### System Administration

Examples include:

- Who has effective access to a governed location?
- Which shares expose it?
- Which permissions are direct or inherited?
- What changed in the filesystem or security configuration?
- What objects may require review following compromise of a privileged identity?

### Security

Examples include:

- What governed files could a compromised identity reach?
- What did that identity actually interact with where source information supports
  that conclusion?
- What permissions changed?
- What is the difference between observed activity and potential reach?
- What is the possible blast radius?
- Where are there gaps or incomplete coverage?

### Management and Reporting

Examples include:

- Which organizational areas may be affected?
- What is confirmed versus potentially affected?
- What information is currently known?
- What remains unknown?
- Which teams or reporting chains need to become involved?

These are different views of the same underlying recorded history, not
independent copies of the data.

---

## Read-only by design

FI is intentionally read-only with respect to the customer environment.

FI may observe files, filesystem metadata, security information, identities,
shares, activity sources, and other configured sources necessary to build its
historical model.

FI does not:

- modify files;
- change ACLs;
- grant or revoke access;
- modify users or groups;
- change SMB shares;
- quarantine systems;
- alter network configuration; or
- automatically remediate the environment.

The ability to observe and explain a problem remains separate from the authority
to change the systems involved.

---

## Customer-controlled deployment

FI is designed to operate entirely within infrastructure controlled by the
customer.

Windows collectors, FI records, historical information, identity and security
metadata, classification results, PostgreSQL data, and other FI backend
information remain on customer-controlled systems unless the customer explicitly
chooses otherwise.

The FI backend may be deployed on a customer-provided server or virtual machine,
or on a dedicated FI appliance located within the customer environment.

Iron Signal Systems does not require persistent administrative or remote access
for FI to operate.

Customers may optionally grant Iron Signal Systems controlled access for
maintenance, upgrades, troubleshooting, or other support services. Any such
access is customer-authorized and is not required for normal FI operation.

FI is intended to remain fully operational in environments where no vendor remote
access is permitted.

---

## Initial platform scope

Initial development targets **Windows Server and NTFS file services**.

Monitoring is explicitly scope-driven. FI operates only against configured
**governed roots**. Installing FI on a server does not mean the entire server,
volume, or share is governed.

The initial Windows collector is intended to preserve:

- NTFS object and volume identity;
- exact path representation;
- file and directory metadata;
- content hashes;
- alternate data streams;
- reparse information;
- Windows security descriptors, ACLs, and ACEs;
- SMB share exposure and share security;
- local Windows identities;
- Active Directory identities and direct membership facts;
- effective-access inputs;
- USN journal change signals;
- governed-file Windows activity; and
- explicit collection continuity.

Other filesystems and operating systems are outside the initial scope.

### Current Windows Security activity validation

FI reads Windows Security activity as an independent source. FI does not
automatically enable Windows audit policy or add SACLs to governed roots. Those
are administrator-controlled deployment settings.

Current Windows Server 2016 validation uses:

- **Audit File System**: Success and Failure;
- **Audit Handle Manipulation**: Failure;
- **Audit Policy Change**: Success; and
- a matching Success/Failure audit ACE on each governed root.

During validation on Windows Server 2016 build `10.0.14393`, successful
change-capable file activity produced Event ID `4663`, while a denied file-handle
request did not produce Event ID `4656` until Handle Manipulation Failure auditing
was enabled.

The currently validated FI SACL is intentionally change-capable rather than
read-complete. Complete governed-file read/access visibility remains Phase 1 work
and must be validated separately before FI claims that coverage.

FI treats observed behavior as platform-specific validation rather than assuming
every Windows Server version emits the same events under the same settings.

See the [Windows auditing example](examples/windows/file-auditing/README.md) for
the current PowerShell activation and SACL examples.

---

## Historical model

FI is not intended to keep only the latest state of a file.

An initial governed-root baseline establishes what FI knows at the beginning of
observation. Subsequent observations add history.

Material changes create new records rather than silently rewriting prior history.

Historical records are authoritative. Current-state, operational, reporting, and
role-oriented backend views are rebuildable representations of that history.

---

## Collection and continuity

The Windows source-side model is:

1. establish an initial governed-root baseline;
2. use the NTFS USN journal and relevant Windows activity as change/activity
   signals;
3. freshly observe affected governed objects;
4. preserve applicable identity, security, share, and governed-file activity
   source facts;
5. write and verify durable local FI spool batches;
6. advance source checkpoints only after the applicable local batch is safely
   written and verified; and
7. explicitly record continuity gaps, interruptions, or degraded coverage.

Phase 1 owns local source collection and local durable queueing.

Phase 2 owns authenticated transport, retries, downstream acknowledgement, and
removal of acknowledged batches from the source spool.

FI must not silently convert missing coverage into certainty.

---

## Source file content and classification

Normal FI record transport does not carry customer source-file content.

Later classification and enrichment may require bounded access to file or stream
content. That capability belongs to the **Separate Protected Classification
Stream** and its streaming/read-broker service, not to the normal Phase 1 record
collector.

Source content is processed transiently and is not stored as normal FI source-file
content in the backend.

Classification results become additional records associated with the exact file
or stream observation that was classified.

**Classification enriches FI's understanding of a file. It does not define the
file's identity or history.**

---

## High-level architecture

```text
             Windows File & Identity Collection
                         |
                         v
                 Durable Local Spool
                         |
                         v
                  Secure Transport
                         |
                         v
                      Ingest
                         |
                         v
                 PostgreSQL Recorder
                         |
              +----------+----------+
              |                     |
              v                     v
        Historical Records      Correlation
                                    |
                                    v
                             PostgreSQL Views
                                    |
                                    v
                             Query / UI / API
```

The collector observes.

The backend preserves and correlates.

Views present the same underlying information for different operational
questions.

FI remains read-only toward the systems it observes.

---

## Core design principles

- The file is the primary subject of FI.
- File identity must not depend solely on pathname.
- FI operates only on explicitly governed roots.
- FI observes customer systems but does not change them.
- Preserve historical state instead of keeping only current state.
- Preserve native source information needed for later verification or
  reinterpretation.
- Keep observed, derived, classified, unknown, and incomplete information
  distinct.
- Never hide collection gaps or uncertainty.
- Never interpret a missing Windows activity record as proof that no activity
  occurred.
- Maintain relationships between files, storage, paths, shares, permissions,
  identities, governed-file activity, and time.
- Make historical records append-only.
- Keep normal customer source-file content outside the FI record path.
- Add classification only after the underlying file/stream observation exists.
- Prefer simple collectors that report source facts over collectors that make
  organizational decisions.

---

## Development roadmap

FI is being developed in phases:

1. **Windows File & Identity Intelligence**
2. **Secure Record Transport**
3. **Ingest & Recorder**
4. **Classification & Enrichment**
5. **Projection, Query & Protected UX**
6. **Integrated Deployment & Release**

See the [FI Roadmap](fi-roadmap/roadmap.md) for detailed implementation status,
boundaries, and phase gates.

---

## Project status

FI is currently **pre-alpha** and under active development.

Current code, record structures, schemas, command names, interfaces, and internal
package layouts may change as the architecture is implemented and validated.

No production-readiness or compatibility guarantee should be inferred from the
current repository.

---

## Licensing

**FI is proprietary source-available software. It is not open-source software.**

Source review and non-production evaluation are permitted only under the terms of
the repository [LICENSE](LICENSE).

FI is developed by **John J. Wood** under the **Iron Signal Systems** project and
brand name.

**Iron Signal Systems is currently a project/brand name and GitHub/domain
identity used by John Joseph Wood. It is not represented by this repository as a
separate corporation, LLC, or other legal entity.**

Copyright ownership and licensing for FI are held and granted by
**John Joseph Wood** unless a future written agreement expressly states otherwise.

---

## Security

Security issues that could expose an active vulnerability or sensitive
implementation detail should not be reported through public GitHub issues.

See [SECURITY.md](SECURITY.md) for the current security reporting process.
