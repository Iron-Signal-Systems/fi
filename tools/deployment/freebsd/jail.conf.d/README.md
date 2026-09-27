# FI Jail Configuration Templates

Files in this directory are source templates.

They are not copied directly to `/etc/jail.conf.d` without rendering and
validation.

Deployment tooling replaces explicit `@TOKEN@` values with validated
site-specific values.

No shell evaluation or arbitrary configuration-file execution is used as a
template mechanism.

Production jail configuration must preserve the capability contract defined in
`../JAIL-CAPABILITIES.md`.

In particular, application jails do not receive `allow.mount`,
`allow.mount.zfs`, or `allow.raw_sockets`.

Per-jail filesystem mounts are supplied through host-controlled
`mount.fstab` files.

## VNET interface names

VNET interface names are explicit deployment inputs rather than incidental
`epair(4)` allocation results.

For each management and workload connection, deployment configuration defines:

    HOST_IF
        epair endpoint retained by the host and attached to the appropriate
        host bridge.

    JAIL_IF
        peer endpoint transferred into the jail with `vnet.interface`.

Deployment must fail closed when a configured interface name already exists in
an unexpected state.

The jail templates consume only the JAIL_IF values. The corresponding HOST_IF
values are used by host-side network provisioning.

## devfs ruleset

`FI_DEVFS_RULESET` is a numeric FreeBSD devfs ruleset identifier.

It remains intentionally unset until runtime acceptance establishes the
production ruleset. Template rendering must reject an empty or non-numeric
value when a production jail configuration is generated.

## VNET interface names

VNET interface names are explicit deployment inputs rather than incidental
`epair(4)` allocation results.

For each management and workload connection, deployment configuration defines:

    HOST_IF
        epair endpoint retained by the host and attached to the appropriate
        host bridge.

    JAIL_IF
        peer endpoint transferred into the jail with `vnet.interface`.

Deployment must fail closed when a configured interface name already exists in
an unexpected state.

The jail templates consume only the JAIL_IF values. The corresponding HOST_IF
values are used by host-side network provisioning.

## devfs ruleset

`FI_DEVFS_RULESET` is a numeric FreeBSD devfs ruleset identifier.

It remains intentionally unset until runtime acceptance establishes the
production ruleset. Template rendering must reject an empty or non-numeric
value when a production jail configuration is generated.
