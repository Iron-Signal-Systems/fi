# FI gMSA Provisioning Example

This example shows how to create and install one Group Managed Service Account (gMSA) per FI collector host.

## Example layout

```text
examples\
├── config\
│   └── gmsa.psd1
└── scripts\
    ├── Setup-FIGMSA-DC.ps1
    └── Install-FIGMSA-Collector.ps1
```

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

From the `examples\scripts` directory, run:

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

Copy the `examples` folder to the collector host, or otherwise make the same configuration and scripts available.

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
- configure Windows auditing;
- configure the FI Windows Activity History reader.

Those are separate FI deployment/runtime steps.
