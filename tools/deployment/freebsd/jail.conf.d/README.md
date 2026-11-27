# FI Jail Configuration Templates

Files in this directory are source templates.

They are not copied directly to `/etc/jail.conf.d` without rendering,
validation, and the reviewed host-file installation layer.

Deployment tooling replaces explicit `@TOKEN@` values with validated
site-specific values.

No shell evaluation or arbitrary configuration-file execution is used as a
template mechanism.

Production jail configuration must preserve the capability contract defined in
`../JAIL-CAPABILITIES.md`.

Application jails do not receive `allow.mount`, `allow.mount.zfs`,
`allow.mount.nullfs`, or `allow.raw_sockets`.

Per-jail filesystem mounts are supplied through host-controlled
`mount.fstab` files.

## Production VNET model

VNET interface names are explicit deployment inputs rather than incidental
`epair(4)` allocation results.

For each management and workload connection, deployment configuration defines:

    HOST_IF
        epair endpoint retained by the host and attached to the configured
        management or workload bridge.

    JAIL_IF
        peer endpoint transferred into the jail through `vnet.interface`.

The receiver external path consists of:

    FI_RECEIVER_EXTERNAL_IF
        dedicated physical interface retained by the host

    FI_RECEIVER_EXTERNAL_BRIDGE
        transient no-IP host bridge

    FI_RECEIVER_EXTERNAL_HOST_IF
        transient host epair endpoint attached to the external bridge

    FI_RECEIVER_EXTERNAL_JAIL_IF
        transient peer transferred into the receiver through `vnet.interface`

The physical external interface:

- remains in the host VNET;
- must carry no host IPv4 or IPv6 address before receiver start;
- is attached to the external bridge only while the receiver is running;
- is never transferred into the receiver jail.

Inside the receiver VNET, `FI_RECEIVER_EXTERNAL_JAIL_IF`:

- receives `FI_RECEIVER_EXTERNAL_ADDRESS`;
- provides the receiver default route through
  `FI_RECEIVER_EXTERNAL_GATEWAY`.

The external, management, and workload epairs are created by the host-side
`fi-vnet-pair` helper during `exec.prestart` and removed during
`exec.poststop`.

The receiver uses the helper's `create-receiver` path so physical-interface
state and all deterministic external topology names are validated before
runtime topology is created.

The ingest and System of Record jails use `create-dual`.

Production templates configure addresses and routes inside each jail VNET
before `/etc/rc` starts.

## Production addressing roles

The receiver uses:

    dedicated external interface
        Windows FI source traffic and receiver external reachability

    management interface
        controlled administration and deployment traffic

    workload interface
        internal FI workload network attachment

The ingest and System of Record jails use:

    management interface
        controlled administration and deployment traffic

    workload interface
        FI application traffic between ingest and PostgreSQL

The receiver default route is its configured external gateway.

The ingest and System of Record default route is the configured management
gateway.

PF remains the authority for which paths are actually permitted.

## devfs ruleset

`FI_DEVFS_RULESET` is the site-selected dedicated FI production devfs ruleset.

The value must be 100 or greater. Deployment never chooses a production
ruleset number automatically.

The rendered jail configuration uses the same accepted production ruleset for
all three FI service jails.
