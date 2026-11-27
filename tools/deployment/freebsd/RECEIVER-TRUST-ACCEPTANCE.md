# FI FreeBSD Receiver Trust Acceptance

**Status:** Receiver trust accepted; source authorization pending
**Date:** 2026-10-04
**Platform:** FreeBSD 15.1-RELEASE-p3 amd64
**Host:** `fi-backend-b`
**Receiver jail:** `fi-receiver`
**Source branch:** `freebsd-backend-port-20260926`
**Accepted source commit:** `8ad1a62be68a66c8006b40254141c5681fffa132`

## Purpose

This record captures the real-host establishment and validation of the FI
receiver trust boundary on the FreeBSD backend.

The acceptance covered:

- receiver configuration custody;
- receiver private-key generation;
- receiver PKCS#10 generation;
- Windows Active Directory Certificate Services receiver-template creation;
- Windows AD CS receiver-certificate issuance;
- root and issuing-CA validation;
- CRL validation;
- receiver certificate validation;
- direct-root chain validation;
- receiver key/certificate binding;
- hostname validation;
- revocation validation;
- jail-visible read-only trust custody; and
- FI receiver trust-readiness inspection.

All receiver-side trust checks completed successfully.

Overall receiver readiness remains intentionally blocked because no real source
authorization registry entry has yet been installed.

FI must not create a fabricated source entry merely to change the readiness
result from `NOT_READY` to `READY`.

## Scope distinction: Windows work

The Windows work performed during this acceptance was operational AD CS
configuration required to issue the FreeBSD receiver TLS identity.

It did not modify:

- the FI Windows installer;
- the FI Windows sender;
- FICollector;
- FIUSNReader;
- source-side certificate enrollment code; or
- the source-side transport or batch-signing certificate contracts.

The existing source-side identities remain separate:

    FI-Transport-Client
        Client Authentication
        source transport identity

    FI-Batch-Signing
        source generation/batch signing identity

The receiver uses a separate server identity:

    FI-Receiver-TLS
        Server Authentication
        FreeBSD receiver identity

The source templates were not repurposed for receiver TLS.

## Receiver configuration authority

The authoritative receiver configuration dataset is:

    zroot/fi/config/receiver

Host mountpoint:

    /var/db/fi/config/receiver

The receiver jail receives this configuration through a host-controlled
read-only nullfs mount at:

    /usr/local/etc/fi

The receiver service identity is:

    uid=4100(fi-receiver)
    gid=4100(fi-receiver)

Trust material is owned by root and readable by the receiver service identity.

The receiver service must not be able to replace its own trust anchors,
certificate, private key, CRLs, or source authorization registry.

## Receiver private key

The receiver private key was generated on `fi-backend-b`.

Path:

    /var/db/fi/config/receiver/pki/receiver/private/fi-receiver-tls.key.pem

Accepted properties:

    algorithm: RSA
    size:      3072 bits
    owner:     root
    group:     4100 / fi-receiver
    mode:      0640

OpenSSL private-key validation completed successfully.

The jail receiver identity was proven able to read the key and unable to write
it.

The private key did not leave the FreeBSD backend.

Public-key SHA-256:

    9ce322376869f6dd07f3dd426676ca67b5837b2ce9dce32ee663b4044c0239c6

## Receiver PKCS#10 request

The receiver CSR was generated from the FreeBSD-resident private key.

CSR SHA-256:

    9c8db9cedca1224ffb85a185da8ddc36f0e28fa5a6eb99f3f188a0c345946e3e

Requested subject:

    O=Iron Signal Systems
    OU=FI Receiver Transport
    CN=fi-receiver.iss.local

Requested Subject Alternative Names:

    DNS:fi-receiver
    DNS:fi-receiver.iss.local

Requested key usage:

    Digital Signature
    Key Encipherment

Requested extended key usage:

    TLS Web Server Authentication

CSR signature:

    sha384WithRSAEncryption

The CSR self-signature validated successfully.

The CSR public-key SHA-256 matched the FreeBSD private-key public-key SHA-256:

    9ce322376869f6dd07f3dd426676ca67b5837b2ce9dce32ee663b4044c0239c6

## Windows AD CS receiver template

The existing CA did not initially publish a dedicated FI receiver TLS template.

A dedicated certificate template was created for the receiver.

Template identity:

    Template name:         FI-Receiver-TLS
    Template display name: FI Receiver TLS

Template OID:

    1.3.6.1.4.1.311.21.8.7189889.13538943.5063825.61332.13006501.227.56127184.55249700

Accepted template properties:

    schema version:       3
    minimum key size:     3072
    asymmetric algorithm: RSA
    hash algorithm:       SHA256
    provider:             Microsoft Software Key Storage Provider

    subject:
        enrollee supplies subject

    key usage:
        Digital Signature
        Key Encipherment

    extended key usage:
        Server Authentication only

    validity:
        1 year

    renewal overlap:
        6 weeks

    auto-enrollment:
        disabled

    private-key export:
        not enabled

The receiver-template enrollment ACL was deliberately separated from FI source
auto-enrollment.

Accepted receiver-template permissions:

    Allow Enroll        ISS\Domain Admins
    Allow Enroll        ISS\Enterprise Admins
    Allow Full Control  ISS\Domain Admins
    Allow Full Control  ISS\Enterprise Admins
    Allow Read          NT AUTHORITY\Authenticated Users

`ISS\ISS-FI-Certificate-Enrollment` does not have receiver-template enrollment
authority.

This prevents the FI source enrollment role from automatically gaining
authority to request FI receiver server identities.

## Receiver certificate issuance

The CA issued the receiver certificate directly from:

    CN=ISS-Root-CA, DC=iss, DC=local

Receiver subject:

    O=Iron Signal Systems
    OU=FI Receiver Transport
    CN=fi-receiver.iss.local

Receiver serial:

    2800000014D87BFBFA05351535000000000014

Validity:

    notBefore: 2026-10-04 16:28:29 GMT
    notAfter:  2027-10-04 16:28:29 GMT

Receiver certificate SHA-256 fingerprint:

    8F:E2:01:9C:25:F5:CF:35:3E:A9:5F:59:A1:E3:0E:48:52:C0:13:09:E5:8E:93:65:1C:90:06:B7:7B:27:FF:82

Issued extensions include:

    Key Usage:
        Digital Signature
        Key Encipherment

    Extended Key Usage:
        TLS Web Server Authentication

    Subject Alternative Name:
        DNS:fi-receiver
        DNS:fi-receiver.iss.local

Both receiver hostname checks passed:

    fi-receiver
    fi-receiver.iss.local

The issued certificate, original CSR, and FreeBSD private key all produced the
same public-key SHA-256:

    9ce322376869f6dd07f3dd426676ca67b5837b2ce9dce32ee663b4044c0239c6

This proves the issued receiver certificate is bound to the private key
generated and retained on the FreeBSD backend.

## Direct-root trust model

This deployment currently uses direct-root issuance.

The receiver leaf issuer is:

    DC=local, DC=iss, CN=ISS-Root-CA

The root is self-signed:

    subject=DC=local, DC=iss, CN=ISS-Root-CA
    issuer=DC=local, DC=iss, CN=ISS-Root-CA

Root serial:

    6F771E7B7AE0728A466D18DA77DB9A3A

Root validity:

    notBefore: 2026-08-22 21:03:49 GMT
    notAfter:  2031-08-22 21:13:48 GMT

Root SHA-256 fingerprint:

    83:E8:A8:58:41:ED:F4:A4:35:94:19:A3:45:2B:5C:83:09:F5:28:20:8D:4D:8D:D8:6B:EE:8D:A7:E0:D2:EF:C0

The root certificate contains:

    Basic Constraints:
        CA:TRUE

    Key Usage:
        Digital Signature
        Certificate Sign
        CRL Sign

Root Subject Key Identifier:

    0B:2C:91:E9:3A:72:17:52:F1:BD:B5:22:23:36:06:BB:86:2E:AC:69

The receiver leaf Authority Key Identifier is the same value:

    0B:2C:91:E9:3A:72:17:52:F1:BD:B5:22:23:36:06:BB:86:2E:AC:69

The root self-signature validated successfully.

The receiver leaf validated successfully to this root for the `sslserver`
purpose and hostname `fi-receiver.iss.local`.

## CRL validation

The current root CRL was obtained from the existing CA.

CRL issuer:

    DC=local, DC=iss, CN=ISS-Root-CA

CRL validity observed during acceptance:

    lastUpdate: 2026-10-03 21:04:13 GMT
    nextUpdate: 2026-10-11 09:24:13 GMT

The CRL signature validated against `ISS-Root-CA`.

The receiver leaf passed CRL-enabled certificate verification and was not
revoked.

These dates are an acceptance observation, not permanent configuration.
Operational CRL refresh must continue to provide a current, validly signed CRL.

## Installed receiver trust files

The authoritative receiver configuration contains:

    pki/trust/fi-root-ca.crt.pem
    pki/trust/fi-transport-ca.crt.pem
    pki/trust/fi-batch-signing-ca.crt.pem
    pki/trust/fi-transport-ca.crl.pem
    pki/trust/fi-batch-signing-ca.crl.pem

    pki/receiver/certs/fi-receiver-tls-fullchain.pem
    pki/receiver/private/fi-receiver-tls.key.pem

    sources/

Because this deployment uses direct-root issuance, the following duplication is
intentional:

    fi-root-ca.crt.pem
    fi-transport-ca.crt.pem
    fi-batch-signing-ca.crt.pem
        -> same ISS-Root-CA certificate

    fi-transport-ca.crl.pem
    fi-batch-signing-ca.crl.pem
        -> same ISS-Root-CA CRL

This does not imply that FI requires transport and batch identities to share an
issuer in every deployment. It records the accepted direct-root topology for
this deployment.

## Receiver fullchain

The receiver fullchain contains exactly two certificates, in this order:

    1. fi-receiver TLS leaf
    2. ISS-Root-CA

The installed fullchain contained exactly two PEM certificate blocks.

## Installed artifact hashes

Normalized root certificate PEM:

    d06899f5611b119df9ffaa5f7f30d927c0bbb12e1a33e06ad25fe5af9ee15750

Normalized root CRL PEM:

    14b5caecc8293aabdd4712303e85869b3b7f42cba8b50fffe8001ec01566b5c5

Normalized receiver leaf PEM:

    993aad8e24c932d6e1c3dbc8b91eb5a558aa11326310f607bbfc3bc14bb872e7

Installed receiver fullchain PEM:

    775c20ae4abdfdad64884dec8505e80333b8300865a8b23d6fa29d7d2e7ded81

These PEM hashes are artifact-integrity values.

They are not automatically interchangeable with FI source-registry X.509
certificate identity pins. Source-registry certificate hashes must use the
exact certificate hashing semantics defined by the FI transport-trust
implementation.

## Runtime receiver trust acceptance

The installed `fi-receiver` binary reported all of the following receiver-side
states as valid:

    Root CA                 VALID
    Transport issuing CA    VALID
    Batch signing CA        VALID
    Transport CRL           VALID
    Batch signing CRL       VALID
    Receiver certificate    VALID
    Receiver private key    VALID
    Receiver hostname       VALID
    Receiver revocation     VALID
    Trust custody           VALID

Coverage reported by the receiver included:

    Root CA coverage:
        STRUCTURE_SELF_SIGNATURE_VALIDITY

    Issuing CA coverage:
        STRUCTURE_ROOT_SIGNATURE_VALIDITY

    CRL coverage:
        ISSUER_SIGNATURE_FRESHNESS

    Receiver coverage:
        LEAF_ROLE_OU_FULLCHAIN_SERVER_AUTH_KEY_MATCH_HOSTNAME_REVOCATION

    Custody coverage:
        OWNER_GROUP_TYPE_RUNTIME_ACCESS_WRITE_PROTECTION_NO_SYMLINKS

The remaining source-registry result was:

    Source registry         INVALID
      source registry contains no entries

    Registry coverage       PARSE_FILENAME_UNIQUENESS_CA_PINS

    Trust state             NOT_READY
      source registry validation failed: source registry contains no entries

This is the accepted result.

`NOT_READY` is intentional at this stage.

The receiver must remain fail-closed until at least one real, structurally valid,
authorized source-registry entry exists.

## Accepted receiver-side state

    Receiver configuration custody       ACCEPTED
    Receiver private-key custody          ACCEPTED
    Receiver CSR/key binding              ACCEPTED
    Windows AD CS receiver template       ACCEPTED
    Receiver certificate issuance         ACCEPTED
    Root self-signature                   ACCEPTED
    Direct-root issuer relationship       ACCEPTED
    Receiver certificate chain            ACCEPTED
    Receiver hostname                     ACCEPTED
    Receiver revocation                   ACCEPTED
    CRL signature/freshness               ACCEPTED
    Receiver key/certificate match        ACCEPTED
    Jail runtime read/write protection    ACCEPTED
    Receiver trust-custody validation     ACCEPTED

    Source authorization registry         PENDING REAL SOURCE
    Overall receiver trust readiness      NOT_READY BY DESIGN

## Next acceptance boundary

The next receiver trust step must use a real Windows source identity.

The source registry must be populated from the actual issued source certificates
and accepted FI source identity, including:

    version_id
    source_id
    enabled

    transport_common_name
    transport_template_oid
    transport_issuing_ca_sha256
    transport_certificate_sha256

    batch_signing_common_name
    batch_signing_template_oid
    batch_signing_issuing_ca_sha256
    batch_signing_certificate_sha256

The registry entry filename must correspond exactly to the accepted `source_id`
as required by the FI receiver-trust implementation.

No placeholder or fabricated identity may be used to satisfy readiness.

After the first real source-registry entry is installed, `fi-receiver trust
status` must be rerun.

The expected next state is:

    Source registry         VALID
    Trust state             READY

provided all source identity and CA-pin validation succeeds.

`READY` must be the consequence of valid real source authorization, not a
relaxation of the receiver trust contract.
