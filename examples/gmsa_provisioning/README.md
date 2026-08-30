# FI gMSA Provisioning Example

This example shows how to create and install the **two unique Group Managed
Service Accounts (gMSAs) used by each FI Windows collector host**.

Windows Security auditing is documented separately in the
[FI Windows file-auditing example](../windows/file-auditing/README.md).

## Current runtime model

Each monitored Windows host uses two identities with different responsibilities:

```text
<HOST>
    gFI-<HOST>$          -> FICollector
                            restricted / non-admin

    gFI-USN-<HOST>$      -> FIUSNReader
                            local Administrator on that host only
```

`FICollector` performs normal collection. `FIUSNReader` exists only because the
validated Windows Server 2016 direct-volume USN path requires administrative
access.

The services communicate over a local named pipe. The helper requires the
connected client token to carry the enabled `NT SERVICE\FICollector` service SID.
An ordinary process running as the collector gMSA does not qualify merely because
it uses the same account.

The complete boundary is documented in:

```text
docs/security/usn-privilege-boundary.md
```

## What this example does

The scripts in this folder:

- create or update the two gMSAs for each configured FI host;
- authorize only the matching computer account to retrieve each managed password;
- install both gMSAs on the matching collector host; and
- verify `Test-ADServiceAccount` for both identities.

They do **not** silently register services, change local Administrator membership,
change audit policy, change SACLs, or modify FI runtime directories.

Those remain deliberate administrator-controlled deployment actions.

## Example layout

```text
gmsa_provisioning\
├── config\
│   └── gmsa.psd1
└── scripts\
    ├── Setup-FIGMSA-DC.ps1
    └── Install-FIGMSA-Collector.ps1
```

## Purpose and security model

These files are **administrator examples and reference material**. They are not
an automatic FI installer, and FI does not provision or modify Active Directory
as part of normal runtime operation.

Each host receives one identity pair. Neither gMSA is shared between monitored
hosts.

Example:

```text
ISS-FS-01
    ISS\gFI-FS01$       -> FICollector
    ISS\gFI-USN-FS01$   -> FIUSNReader

ISS-FS-02
    ISS\gFI-FS02$       -> FICollector
    ISS\gFI-USN-FS02$   -> FIUSNReader
```

Only the matching server computer account is authorized to retrieve either
managed password.

No static gMSA password is stored in FI configuration or scripts.

### Collector identity

The `FICollector` gMSA is intended to remain non-administrative.

Its required access is the minimum practical access needed for normal FI source
collection, including as applicable:

- Security log reading;
- governed-root traversal and file reading;
- security descriptor/SACL reading;
- content hashing;
- SMB share query;
- local identity query;
- LDAPS/AD lookup;
- FI configuration read;
- FI state/spool write; and
- FI operation/resource journal write.

Expected source access failures should remain visible rather than being hidden by
making the collector an Administrator.

### Privileged USN identity

The `FIUSNReader` gMSA is intentionally separate.

On the currently validated Windows Server 2016 design it is local Administrator
on its assigned host because testing established that FI's direct-volume
`FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` path requires
administrative-capable volume access.

The helper's code is deliberately narrow:

```text
open approved local NTFS volume
query USN journal
read one bounded USN buffer
return result
```

It does not own:

- USN parsing policy;
- File-ID re-observation;
- governed-root containment;
- hashing;
- checkpoint persistence or advancement;
- spool writes;
- supporting-source collection; or
- FI configuration writes.

## KDS root key

The domain-controller example may create a KDS root key when one does not already
exist. This is an explicit administrator-run action, not FI runtime behavior.

The backdated KDS method in the example is intended only for a single-domain-
controller lab/test environment. Production environments with multiple domain
controllers should use the normal KDS replication process.

---

## Configuration

`config\gmsa.psd1`

```powershell
@{
    Version = '1.0'

    Collectors = @(
        @{
            Host          = 'ISS-FS-01'
            CollectorGMSA = 'gFI-FS01'
            USNGMSA       = 'gFI-USN-FS01'
        },
        @{
            Host          = 'ISS-FS-02'
            CollectorGMSA = 'gFI-FS02'
            USNGMSA       = 'gFI-USN-FS02'
        }
    )
}
```

Every `CollectorGMSA` and `USNGMSA` value must be unique.

---

## 1. Prepare the KDS root key on the domain controller

Run from an elevated PowerShell prompt on the domain controller.

Check for an existing KDS root key:

```powershell
Get-KdsRootKey
```

If no key is returned and this is a single-domain-controller lab/test
environment:

```powershell
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

Verify the key:

```powershell
$k = Get-KdsRootKey
$k | Format-List KeyId,CreationTime,EffectiveTime,IsFormatValid
Test-KdsRootKey -KeyId $k.KeyId
```

The final command should return:

```text
True
```

> The backdated `-10` hour method is for a single-DC lab/test environment.
> Production environments with multiple domain controllers should use normal
> KDS replication and allow the required replication time.

---

## 2. Create the FI gMSAs on the domain controller

From the `examples\gmsa_provisioning\scripts` directory:

```powershell
.\Setup-FIGMSA-DC.ps1
```

Expected output resembles:

```text
KDS root key already exists.
Creating FICollector gMSA gFI-FS01 for ISS-FS-01...
Creating FIUSNReader gMSA gFI-USN-FS01 for ISS-FS-01...

FI gMSA domain setup complete.

  ISS-FS-01            FICollector  -> ISS\gFI-FS01$
                       FIUSNReader  -> ISS\gFI-USN-FS01$
```

The script creates or updates both accounts and limits managed-password retrieval
to the matching host computer account.

---

## 3. Install both gMSAs on the collector host

Copy the `gmsa_provisioning` folder to the collector host, or otherwise make the
same configuration and scripts available.

Run from an elevated PowerShell prompt on the collector:

```powershell
.\Install-FIGMSA-Collector.ps1
```

The script selects the entry matching `$env:COMPUTERNAME`, installs both gMSAs if
needed, and validates both.

Expected output resembles:

```text
FI gMSA collector-host setup complete.
  Host:              ISS-FS-01
  FICollector:       ISS\gFI-FS01$
  Collector test:    True
  FIUSNReader:       ISS\gFI-USN-FS01$
  USN helper test:   True
```

---

## Result

The completed identity relationship is:

```text
Active Directory / KDS
        |
        +-- ISS-FS-01$
        |       |
        |       +-- ISS\gFI-FS01$       -> FICollector
        |       |
        |       +-- ISS\gFI-USN-FS01$   -> FIUSNReader
        |
        +-- ISS-FS-02$
                |
                +-- ISS\gFI-FS02$       -> FICollector
                |
                +-- ISS\gFI-USN-FS02$   -> FIUSNReader
```

No gMSA password is stored in FI configuration or scripts. Active Directory
manages the passwords.

---

## What this example does not configure

This example creates and installs the identities only.

It does not:

- create or configure the `FICollector` Windows service;
- create or configure the `FIUSNReader` Windows service;
- grant `Log on as a service`;
- add the helper gMSA to local Administrators;
- enable the `FICollector` service SID;
- configure FI program/config/state/spool ACLs;
- enable Windows audit policy;
- add governed-root SACLs; or
- establish final production scheduling intervals.

Those actions need to remain reviewable deployment steps rather than hidden side
effects of gMSA creation.

The Windows service runtime itself is implemented in FI. Remaining Phase 1 work
is deployment hardening, reproducibility, broader operational/failure testing,
activity validation, performance measurement, and supported-version
characterization.
