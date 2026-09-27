# FI FreeBSD Jail Capability Contract

This document defines the capability boundary for the initial FI FreeBSD
production jails.

The production service jails are:

    fi-receiver
    fi-ingest
    fi-sor-db

`fi-dev` is a development environment and is not a production service jail.

## Governing principle

The host owns privileged infrastructure operations.

Production FI jails receive only the operating-system capabilities required to
run their assigned application services.

The following remain host authority:

    jail creation and destruction
    VNET interface creation and assignment
    bridge membership
    PF configuration
    filesystem mounting and unmounting
    ZFS dataset administration
    ZFS snapshots and replication
    devfs ruleset administration
    production dataset attachment
    production backup and recovery

A production FI jail must not be able to widen its own filesystem, network, or
storage authority.

## VNET

All production FI service jails use VNET.

Each jail receives its own network stack rather than inheriting the host network
stack.

The initial interface model is:

    fi-receiver
        management interface
        workload/data-plane interface

    fi-ingest
        management interface
        workload/data-plane interface

    fi-sor-db
        management interface
        workload/data-plane interface

The host creates the epair interfaces and assigns the jail-side interfaces
through `vnet.interface`.

Jails do not create or attach their own host-side VNET interfaces.

## Network role separation

The management and workload interfaces have different purposes.

The management interface is for controlled administration and deployment
traffic.

The workload interface is for FI application traffic.

The intended application paths are:

    Windows FI sources -> fi-receiver workload interface

    fi-ingest workload interface -> fi-sor-db workload interface

No PostgreSQL listener is exposed through the receiver jail.

No FI receiver listener is exposed through the ingest or database jails.

PF remains the authority for allowed inter-jail and external flows.

Exact addressing and external receiver reachability are site configuration and
must not be hard-coded into the jail template.

## Mount authority

Production FI jails are not granted `allow.mount`.

They are not granted any filesystem-specific jail mount permission, including:

    allow.mount.devfs
    allow.mount.fdescfs
    allow.mount.nullfs
    allow.mount.procfs
    allow.mount.tmpfs
    allow.mount.zfs

Filesystem mounts required by FI are performed by the host as part of jail
creation.

The supported deployment uses host-controlled `mount` or `mount.fstab`
configuration to present required host paths inside each jail.

This distinction is mandatory:

    host mounts filesystem into jail       permitted
    jail mounts/remounts filesystem        prohibited

## ZFS authority

Production FI jails are not granted `allow.mount.zfs`.

Production datasets are not delegated to service jails for ZFS administration.

The deployment does not use `zfs.dataset` to hand administrative ownership of FI
production datasets to application jails.

Jails must not be able to:

    create datasets
    destroy datasets
    change ZFS properties
    create or destroy snapshots
    rollback snapshots
    replicate datasets
    change dataset mountpoints
    change dataset readonly properties

The host remains the sole ZFS authority.

## Shared FI mounts

The host presents FI datasets according to `STORAGE-AUTHORITY.md`.

The initial application view is:

    fi-receiver
        custody/generation    RW
        recorded              RW
        ready                 RW
        receiver config       RO

    fi-ingest
        custody/generation    RO
        recorded              RO
        ready                 RW
        ingest config         RO

    fi-sor-db
        PostgreSQL data       RW

Read-only versus read/write authority is established by the host-controlled
mount configuration.

A jail must not be able to remount an RO authoritative path as RW.

## devfs

Production service jails receive a host-mounted devfs only when required by the
jail runtime.

The host controls the `devfs_ruleset`.

Jails do not receive authority to alter devfs rules or mount additional devfs
instances.

The production ruleset must expose only device nodes demonstrated to be
necessary.

Disk devices, host storage devices, packet-filter devices, and other
administrative device nodes are not exposed merely for convenience.

A dedicated FI production devfs ruleset may be derived from FreeBSD's standard
jail ruleset after actual runtime requirements are measured.

The final devfs ruleset is an acceptance-tested deployment artifact.

## Raw sockets

FI production application services do not require raw sockets as part of the
current architecture.

`allow.raw_sockets` therefore remains disabled unless a future demonstrated
runtime requirement is separately reviewed.

Diagnostic convenience such as `ping` is not sufficient reason to enlarge the
production jail capability boundary.

Normal TCP and UNIX-domain socket operation does not require raw-socket
authority.

## Additional allow.* capabilities

FI production jails do not receive optional jail capabilities merely because
they exist.

Unless a demonstrated runtime requirement is documented and accepted, the
deployment does not enable:

    allow.chflags
    allow.mlock
    allow.nfsd
    allow.quotas
    allow.read_msgbuf
    allow.socket_af
    allow.sysvipc
    allow.vmm
    allow.vmm_ppt

Any future exception must identify:

    the requesting component
    the exact operating-system capability required
    why the default jail restriction is insufficient
    security impact
    acceptance test proving the requirement
    negative test proving the grant is not broader than intended

## Child jails

Production FI jails do not create subordinate jails.

`children.max` remains zero.

Jail lifecycle is host authority.

## Filesystem visibility

`enforce_statfs` is treated separately from mount authority.

Lowering `enforce_statfs` does not by itself grant mounting rights, but it
changes filesystem visibility inside the jail.

The receiver and ingest jails should begin with the most restrictive setting
compatible with their runtime.

The PostgreSQL jail must be tested against its separately mounted PGDATA path
before the production value is finalized because PostgreSQL may legitimately
inspect filesystem capacity and mount information.

No `enforce_statfs` relaxation becomes permanent without an acceptance test.

## Service privilege

Application processes run as their dedicated jail-local service identities.

Root inside a service jail is reserved for controlled jail administration and
rc.d lifecycle operations.

FI application binaries must not run as jail root unless a separately reviewed
component demonstrates a technical requirement.

The initial expected runtime identities are:

    fi-receiver:
        fi-receiver

    fi-ingest:
        fi-ingest

    fi-sor-db:
        PostgreSQL package service identity

The shared numeric receiver/ingest filesystem identity is defined in
`SERVICE-IDENTITY.md`.

## SSH

Production FI application jails do not require sshd as part of the FI runtime.

Normal production administration is performed from the host using jail-aware
administrative mechanisms such as `jexec`.

Enabling network SSH inside a production service jail is a separate deployment
decision and is not part of the baseline FI capability contract.

The management VNET interface does not imply that sshd must be enabled.

## PF authority

PF configuration exists only on the host.

No FI production jail receives PF administrative authority or host packet-filter
device access.

The application jails cannot modify the host's inter-jail or external network
policy.

PF rules must eventually prove at minimum:

    Windows source -> receiver FI transport       allowed
    external -> PostgreSQL                       denied
    receiver -> PostgreSQL                       denied
    ingest -> PostgreSQL required path           allowed
    unauthorized jail -> PostgreSQL              denied
    workload network -> unintended external path denied

## Jail startup ordering

Required host filesystem mounts and VNET interfaces are established as part of
jail creation before FI application services start.

An FI service must fail closed when required mounted state or configuration is
absent.

Application startup must not create substitute local directories that silently
mask a missing production mount.

For example, an ingest jail missing its authoritative custody mount must not
continue by operating against a newly created empty local directory.

## Verification requirements

Deployment verification must prove:

1. every production FI jail uses VNET;
2. expected VNET interfaces are present and no unexpected interface is present;
3. no production FI jail has `allow.mount`;
4. no production FI jail has `allow.mount.zfs`;
5. no production FI jail has `allow.mount.nullfs`;
6. no production FI jail has raw-socket authority;
7. no production FI jail has ZFS administration authority;
8. no production FI jail can create child jails;
9. host-controlled RO mounts reject write attempts from the ingest jail;
10. host-controlled RW mounts permit only the intended FI service operations;
11. devfs exposes only the accepted device set;
12. receiver cannot reach PostgreSQL on an unauthorized path;
13. ingest can reach PostgreSQL only on the authorized workload path;
14. external systems cannot connect directly to PostgreSQL;
15. required mounts exist before FI services start;
16. missing required mounts cause startup or verification failure rather than
    silent local-state substitution.
