# FI gMSA Provisioning Example

This example shows how to create and install one Group Managed Service Account (gMSA) per FI collector host.

Windows Security auditing is documented separately in the [FI Windows Auditing Example](windows_auditing/README.md), including the Server 2016 audit-policy settings currently validated for FI and the example PowerShell used to enable them.

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

These files are **administrator examples and reference material**. They are not an automatic FI installer, and FI does not silently provision or modify Active Directory as part of its runtime operation.

The administrator is expected to review the configuration and scripts, adapt them to the environment, and deliberately execute the required domain-controller and collector-side steps.

FI is being developed and tested with gMSA so the collector can operate with a deliberately bounded service identity instead of Domain Admin, local Administrator, or other unnecessarily broad rights.

Testing with excessive privileges could hide real access failures and create a misleading picture of what FI can actually observe in a customer environment.

**FI's runtime collector is read-only against the systems it observes. FI is designed to run under a customer-provisioned, least-privilege service identity such as a gMSA. These example administrative scripts are provided only to assist with that configuration.**

Each configured collector host receives its own gMSA, and only that computer account is authorized to retrieve the managed password for its assigned account. No static gMSA password is stored in FI configuration or scripts.

### KDS root key

The domain-controller example may create a KDS root key when one does not already exist. This is an explicit administrator-run example action, not an FI runtime action.

The administrator should review that behavior before running the script and use the appropriate KDS procedure for the environment.

The backdated KDS method documented below is intended only for a single-domain-controller lab/test environment. Normal production environments should use the standard KDS replication process.

### Why bounded permissions matter

Running FI under bounded permissions is intentional.

Results such as `AccessDenied`, unavailable security information, or other partial observations can represent the actual access available to the collector. Those conditions should be reported rather than hidden by granting broad administrative rights simply to make collection appear complete.

This allows FI development and testing to reflect the permissions expected in a real deployment instead of producing artificially complete results because the collector was given excessive access.

## Configuration

`config\gmsa.psd1`

```powershell
@{
    Version = '1.0'

    Collectors = @(
        @{
            Host = 'ISS-FS-01'
            GMSA = 'gFI-FS01'
        },
        @{
            Host = 'AdminBox'
            GMSA = 'gFI-AdminBox'
        }
    )
}
```

Each collector host receives its own gMSA.

```text
ISS-FS-01 -> ISS\gFI-FS01$
AdminBox  -> ISS\gFI-AdminBox$
```

## 1. Prepare the KDS root key on the domain controller

Run the following from an elevated PowerShell prompt on the domain controller.

Check for an existing KDS root key:

```powershell
Get-KdsRootKey
```

If no key is returned and this is a single-domain-controller lab/test environment, create one that is immediately usable:

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

> The backdated `-10` hour method is for a single-DC lab/test environment. Production environments with multiple domain controllers should use the normal KDS replication process and allow time for the key to replicate.

## 2. Create the FI gMSAs on the domain controller

From the `examples\gmsa_provisioning\scripts` directory, run:

```powershell
.\Setup-FIGMSA-DC.ps1
```

Expected output resembles:

```text
KDS root key already exists.
Creating gMSA gFI-FS01 for ISS-FS-01...
Creating gMSA gFI-AdminBox for AdminBox...

FI gMSA domain setup complete.

  ISS-FS-01            -> ISS\gFI-FS01$
  AdminBox             -> ISS\gFI-AdminBox$
```

The script creates or updates one gMSA for each collector defined in `gmsa.psd1`.

Each computer account is authorized only to retrieve the password for its assigned gMSA.

## 3. Install the gMSA on each FI collector host

Copy the `gmsa_provisioning` folder to the collector host, or otherwise make the same configuration and scripts available.

Run the following from an elevated PowerShell prompt on each collector:

```powershell
.\Install-FIGMSA-Collector.ps1
```

The script reads the local computer name and automatically selects the matching entry from `gmsa.psd1`.

For example, on `ADMINBOX`:

```text
FI gMSA collector setup complete.
  Host:    ADMINBOX
  Account: ISS\gFI-AdminBox$
  Test:    True
```

`Test: True` confirms that the collector host can retrieve and use its assigned gMSA.

Run the same script on `ISS-FS-01`. It will automatically select `gFI-FS01`.

## Result

The completed relationship is:

```text
Active Directory / KDS
        |
        +-- ISS-FS-01$ -> ISS\gFI-FS01$
        |
        +-- AdminBox$  -> ISS\gFI-AdminBox$
```

No gMSA password is stored in the FI configuration or scripts. Active Directory manages the password.

## What this example does not configure yet

This example only creates and installs the gMSAs.

It does not yet:

- register `fi.exe` as a Windows service;
- grant `Log on as a service`;
- grant `SeSecurityPrivilege`;
- change NTFS permissions on governed roots;
- configure the FI Windows Activity History reader.

Windows audit policy and governed-root SACL examples are documented separately in [file-auditing](../windows/file-auditing/README.md).
