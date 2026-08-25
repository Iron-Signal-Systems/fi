# File Intelligence (FI)

<p align="center">
  <img src="docs/images/fi.png" alt="FI — File Intelligence" width="100%">
</p>

**File Intelligence (FI)** is a read-only system for building a historical
understanding of governed files.

FI is designed around a simple question:

> **What do we know about this file?**

Over time that includes its identity, locations, storage, metadata, security,
access, activity, relationships, history, and eventually classification.

The file remains the center of that history.

FI does not modify customer files, permissions, identities, shares, systems,
or infrastructure.

---

## Why FI exists

Understanding a file in a real environment often requires information from
many different places.

A single question such as:

> Why can this user access this file?

may require correlating:

- the file's identity;
- its current and historical paths;
- NTFS permissions;
- SMB share permissions;
- local identities;
- Active Directory identities and nested group membership;
- permission inheritance;
- effective access;
- changes to those permissions;
- available activity records; and
- the state of all of those things at the time being investigated.

A different question may start with an identity:

> If this account is compromised, what governed files could it affect?

Or with a file:

> Where has this file been, who could access it, what happened to it, and what
> changed?

FI is intended to preserve and correlate the information needed to answer
those questions without changing the systems being examined.

---

## File-centered intelligence

FI treats a governed file as more than a pathname.

A pathname can change.

A file can be renamed, moved, exposed through different shares, have its
permissions changed, or have relationships to different identities over time.

FI is being designed to maintain the history necessary to understand those
changes.

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
- Was that access direct, inherited, or obtained through group membership?
- When did access change?
- Who changed permissions when the available source information can establish
  that?
- What activity involving the file has been observed?
- What was known about the file at a particular point in time?
- Where are there gaps that prevent FI from making a definitive conclusion?
- What classification was later associated with a particular observation of
  the file?

FI must distinguish between what was directly observed, what can be
deterministically derived, what was classified, and what remains unknown or
incomplete.

A gap in available information must never be presented as proof that an event
did not occur.

---

## Useful across IT

FI records one underlying history.

Different parts of an IT organization can use PostgreSQL views over that same
recorded and correlated information for different purposes.

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
- What objects may require review following compromise of a privileged
  identity?

### Network Administration

FI is not a network-management system.

However, file relationships can identify systems and services that may matter
to network operations during troubleshooting or incident response.

Future integration with other read-only intelligence systems may allow file,
system, identity, and network relationships to be viewed together.

### Security

Examples include:

- What governed files could a compromised identity reach?
- What did that identity actually interact with where source information
  supports that conclusion?
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

The purpose of FI is to help people understand the environment.

The ability to observe and explain a problem must remain separate from the
authority to change the systems involved.

---

## Customer-controlled deployment

FI is designed to operate entirely within infrastructure controlled by the customer.

Windows collectors, FI records, historical information, identity and security metadata, classification results, PostgreSQL data, and other FI backend information remain on customer-controlled systems unless the customer explicitly chooses otherwise.

The FI backend may be deployed on a customer-provided server or virtual machine, or on a dedicated FI appliance located within the customer environment.

Iron Signal Systems does not require persistent administrative or remote access for FI to operate.

Customers may optionally grant Iron Signal Systems controlled access for maintenance, upgrades, troubleshooting, or other support services. Any such access is customer-authorized and is not required for normal FI operation.

FI is intended to remain fully operational in environments where no vendor remote access is permitted.

---

## Initial platform scope

Initial development targets **Windows Server and NTFS file services**.

Monitoring is explicitly scope-driven.

FI operates only against configured **governed roots**, such as approved
drives or directories. Installing FI on a server does not mean the entire
server is governed.

The Windows collector is being designed to observe the native Windows and
NTFS information needed to establish file identity and history accurately.

This includes, as development progresses:

- NTFS object identity;
- volume identity;
- exact path representation;
- file and directory metadata;
- alternate data streams;
- reparse points;
- Windows security descriptors;
- ACLs and ACEs;
- SMB share exposure;
- local Windows identities;
- Active Directory identities;
- effective-access inputs;
- USN journal changes;
- available activity history; and
- continuity of collection.

Other filesystems and operating systems are outside the initial scope.

### Windows Security activity prerequisites

FI reads Windows Security activity as an independent source. FI does not
automatically enable Windows audit policy or add SACLs to governed roots.
Those are administrator-controlled deployment settings.

Current Windows Server 2016 validation uses:

- **Audit File System**: Success and Failure;
- **Audit Handle Manipulation**: Failure;
- **Audit Policy Change**: Success; and
- a matching Success/Failure audit ACE on each governed root.

During validation on Windows Server 2016 build `10.0.14393`, successful file
activity produced Event ID `4663` with File System auditing enabled, while a
denied file-handle request did not produce Event ID `4656` until Handle
Manipulation Failure auditing was also enabled.

FI treats this as validated platform behavior rather than assuming every
Windows Server version emits the same events under the same settings. Later
Windows versions should be validated independently.

See the [Windows auditing example](examples/windows_auditing/README.md) for the
current PowerShell activation and SACL examples.

---

## Historical model

FI is not intended to keep only the latest state of a file.

An initial governed-root baseline establishes what FI knows at the beginning
of observation.

Subsequent observations add history.

Material changes create new records rather than silently rewriting prior
history.

This allows FI to reconstruct questions such as:

> What did FI know about this file at 10:00 yesterday?

rather than being limited to:

> What does this file look like right now?

Historical records are authoritative.

Current-state, operational, reporting, and role-oriented PostgreSQL views are
rebuildable representations of that recorded history.

---

## Collection and continuity

FI is being designed to maintain governed file history continuously.

The intended Windows model includes:

1. establishing an initial baseline;
2. detecting changes using appropriate Windows facilities such as the NTFS
   USN journal;
3. freshly observing affected objects;
4. recording applicable Windows identity, security, share, and activity
   information;
5. transporting records safely to FI;
6. preserving accepted records as historical facts; and
7. explicitly recording gaps, interruptions, or degraded collection.

FI must not silently convert missing coverage into certainty.

---

## Source file content

Normal FI collection does not require customer source-file content to become
part of the FI record stream.

Most FI intelligence is derived from filesystem, security, identity, activity,
and relationship information.

Later classification and enrichment may require access to file content.

When that capability is implemented, source content is intended to be read
through a separate protected and bounded mechanism, processed transiently,
and not stored as normal FI source-file content in the backend.

Classification results become additional records associated with the
particular file observation that was classified.

**Classification enriches FI's understanding of a file. It does not define
the file's identity or history.**

---

## High-level architecture

```text
             Windows File & Identity Collection
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

PostgreSQL preserves and correlates.

Views present the same underlying information for different operational
questions.

FI remains read-only toward the systems it observes.

---

## Core design principles

- The file is the primary subject of FI.
- File identity must not depend solely on pathname.
- FI observes customer systems but does not change them.
- Preserve historical state instead of keeping only current state.
- Preserve native source information where required for later verification or
  reinterpretation.
- Keep observed, derived, classified, unknown, and incomplete information
  distinct.
- Never hide collection gaps or uncertainty.
- Maintain relationships between files, storage, paths, shares, permissions,
  identities, activity, and time.
- Make historical records append-only.
- Treat current-state and purpose-specific PostgreSQL views as rebuildable
  views of recorded history.
- Keep normal customer source-file content outside the FI record path.
- Add classification as enrichment after the underlying file observation
  exists.
- Prefer simple collectors that report facts over collectors that make
  organizational decisions.

---

## Development roadmap

FI is being developed in phases.

The current roadmap covers:

1. **Windows File & Identity Intelligence**
2. **Secure Record Transport**
3. **Ingest & Recorder**
4. **Classification & Enrichment**
5. **Projection, Query & Protected UX**
6. **Integrated Deployment & Release**

See the [FI Roadmap](fi-roadmap/roadmap.md) for detailed implementation
status, boundaries, and phase gates.

---

## Project status

FI is currently **pre-alpha** and under active development.

Current code, record structures, schemas, command names, interfaces, and
internal package layouts may change as the architecture is implemented and
validated.

No production-readiness or compatibility guarantee should be inferred from
the current repository.

---

## Licensing

**FI is proprietary source-available software. It is not open-source
software.**

Source review and non-production evaluation are permitted only under the terms
of the repository [LICENSE](LICENSE).

FI is developed by **John J. Wood** under the **Iron Signal Systems** project
and brand name.

**Iron Signal Systems is currently a project/brand name and GitHub/domain
identity used by John Joseph Wood. It is not represented by this repository
as a separate corporation, LLC, or other legal entity.**

Copyright ownership and licensing for FI are held and granted by
**John Joseph Wood** unless a future written agreement expressly states
otherwise.

---

## Security

Security issues that could expose an active vulnerability or sensitive
implementation detail should not be reported through public GitHub issues.

See [SECURITY.md](SECURITY.md) for the current security reporting process.
