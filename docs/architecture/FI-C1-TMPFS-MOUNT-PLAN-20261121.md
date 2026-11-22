# C1 Shared tmpfs mount plan — NO LIVE MUTATION

`RenderC1RAMMountPlan` produces the exact FreeBSD host/jail fstab
entries from the FI installer's **configured jail roots**, numeric
runtime UID/GID and jail fstab paths. The pure planner performs no mounts,
filesystem creation, fstab editing or SQL operations.

Example entries only, with placeholder jail roots and UID/GID:

```fstab
# HOST: explicitly mounted before both jails start; NOAUTO
tmpfs /var/run/fi-c1-handoff tmpfs rw,noauto,nosuid,noexec,size=4g,uid=4100,gid=4100,mode=0770 0 0

# fi-ingest jail fstab: writable producer
/var/run/fi-c1-handoff /ACTUAL/fi-ingest-root/var/run/fi-c1-handoff nullfs rw 0 0

# fi-sor-db jail fstab: read-only consumer
/var/run/fi-c1-handoff /ACTUAL/fi-sor-root/var/run/fi-c1-handoff nullfs ro 0 0
```

The shared tmpfs is **not** durable and must not be journaled, ZFS
snapshotted or restored. On restart, signed custody is reread and
PostgreSQL commit evidence decides which records need SQL projection.

The installer still needs a separately verified, collision-safe
mount activation operation and full two-jail acceptance. Prior to any
service enablement, run `fi-c1-host-preflight` with actual C220 paths.
Require that its mount sources/targets match the plan exactly. No
code in this planner enables a jail or canonical ingestion.

## Physical C220 reconciliation — observed 2026-11-22

Read-only host and PostgreSQL inventory established the **existing**
running jail names/roots as `fi-ingest` at
`/fast/jails/roots/fi-ingest` and **`fi-sor`** at
`/fast/jails/roots/fi-sor`; the live SoR PostgreSQL socket is
`/var/db/fi/sor/run` and its data directory is
`/var/db/fi/sor/postgres`. There was no C1 handoff tmpfs/nullfs mount
or `fi-c1-handoff` entry in the inspected host/candidate jail fstabs.
Existing signed-custody read-only nullfs mounts in fi-ingest must remain
unchanged.

**STOP:** The installer configuration names `FI_SOR_DB_ROOT` and
`FI_SOR_DB_FSTAB` are logical compatibility keys and MUST NOT be
interpreted as proof that a jail called `fi-sor-db` is deployed, or
that `/etc/fstab.fi-sor-db` is used by the running `fi-sor` jail.
Before `apply-c1-ram-fstab`, independently identify the actual
jail.conf `mount.fstab` linkage or jail-start mount mechanism and
reconcile it with the exact paths returned by the planner. Creating an
unused fstab entry does not install a working mount; changing an active
jail's fstab without that mapping can break existing services. Do not
rename, replace, or restart the current `fi-sor` jail merely to match a
development installer identifier.

Existing private SoR staging is **not empty**: the target generation
has 89 verified artifact markers, 88 source-window markers, and 88
typed-window markers summing 2,770,101 committed records. This must be
independently reconciled with original signed custody and durable SQL
state before a replay-enabled worker can start. Preserve all private
rows and recovery ledgers; do not reinstall, truncate, or reset.
Telemetry delivery last observed 2026-10-30 must be restored/verified
as a separate acceptance prerequisite. None of these read-only
observations constitutes authority to publish or enable live ingestion.

## SoR independent B verifier has four additional required read-only inputs

The real C220 `fi-sor` jail starts with **no** receiver-custody nullfs
mount and no receiver trust/source registry mounts. C1's separate B
process opens the original signed generation and recorded receipt and
calls the fixed FreeBSD `/usr/local/etc/fi` trust/registry resolver.
The two-jail RAM mount alone cannot satisfy B.

The actual C220 read-only planner
`go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_ram_mount_plan.sh`
now also outputs these four **SoR-only RO nullfs** candidates after
checking the host source directories:

- `/work/fi-c220-20261114/custody/generation` to
  `/fast/jails/roots/fi-sor/var/db/fi/custody/generation`
- `/work/fi-c220-20261114/custody/recorded` to
  `/fast/jails/roots/fi-sor/var/db/fi/custody/recorded`
- `/work/fi-c220-20261114/config/receiver/pki/trust` to
  `/fast/jails/roots/fi-sor/usr/local/etc/fi/pki/trust`
- `/work/fi-c220-20261114/config/receiver/sources` to
  `/fast/jails/roots/fi-sor/usr/local/etc/fi/sources`

Those mappings must be checked against the actual host source directories,
immutable object ownership/modes, existing jail destination directories
and any external dependencies before applying. **Do not** alter
`fi-receiver` or `fi-ingest` signed-custody mounts.
The SoR nullfs consumer views must be read-only. A writable B trust
or source root, or absent original signed custody, blocks C1.

On this host, the existing fi-ingest and fi-sor jail configuration files
are `/etc/jail.conf.d/fi-ingest.conf` and
`/etc/jail.conf.d/fi-sor.conf`, with no current `mount.fstab` binding.
A permanent C1 mount plan must explicitly reconcile and link the actual
jail.conf `mount.fstab` files. It must not assume the old
`/etc/fstab.fi-sor-db` convention or restart the running jails.

## Physical C220 live mount acceptance (without a jail restart)

The physical jail layout has been confirmed on 2026-11-22, and the
`fi-sor` service account is now installed as UID 4100 with primary GID
4100 (`fi-ingest-socket`), without changing PostgreSQL's existing group.

The **real C220-only** shell installer
`go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_live_mounts.sh` has
two distinct operator actions:

1. `--audit` checks the existing running jail identities, actual roots,
   source custody/trust directories, expected unmounted and empty target
   directories, the absence of private SQL staging, and disabled C1
   workers. It changes nothing.
2. `--apply` requires the exact
   `FI_C1_LIVE_MOUNTS_APPROVED=ONLY_C1_TMPFS_AND_FIVE_SOR_RO_VIEWS`
   environment authorization. It creates **only empty C1 mountpoints**,
   mounts one 4 GiB noexec/nosuid tmpfs on the host, presents that
   tmpfs RW to `fi-ingest` and RO to `fi-sor`, and adds the four
   original receiver generation/receipt/trust/registry paths as RO
   nullfs views **only inside fi-sor**. Existing receiver and ingest
   mounts are not changed. No jail or C1 service is restarted or enabled.

This phase deliberately does **not** edit `/etc/fstab`,
`/etc/jail.conf.d`, or an rc boot service. The live mounts are
**not boot persistent**. After successful native host `statfs`
acceptance and read-only custody accessibility checks, implement and
accept boot-order-safe persistent settings **separately**. Do not
restart or reboot these jails expecting mounts to survive before that
persistent step is complete. On a partial live mount failure, inspect
`mount -p` rather than blindly rerunning or trying a CASCADE unmount.

## Read-only installer invocation

On the FreeBSD host, with the existing validated FI backend configuration:

```sh
fi-backend-install plan-c1-ram-mounts /path/to/fi-backend.conf
```

The output contains the three exact candidate fstab entries and the
configured existing jail fstab locations. It does not mount, edit,
write, install, or activate anything. The mount files and jail roots
must be reconciled with actual host configuration before application.

## Read-only existing-fstab verification

```sh
fi-backend-install audit-c1-ram-mounts /path/to/fi-backend.conf
```

The inspection reads the host `/etc/fstab` and the two jail fstab
paths from the validated FI configuration. It reports EXACT or ABSENT;
unknown, duplicated, symlinked or conflicting destination entries fail
closed. Missing entries return a distinct nonzero status. **This audit
never modifies a file or mounts a filesystem**, and does not replace the
independent live `fi-c1-host-preflight` validation.

## Mandatory live host tmpfs proof

The FreeBSD `fi-c1-host-preflight` now requires the **actual numeric**
`--runtime-uid` and `--runtime-gid` from the installed FI configuration.
It checks that the mounted host tmpfs root is an exactly mode `0770`
directory owned by those numbers, has `noexec,nosuid`, and has a real
capacity between 2 GiB and 4 GiB. It also checks both jail nullfs
mounts and original signed custody read-only mappings. This is a
**read-only** preflight, not a mount installer or activation command.

## FreeBSD boot ordering: mandatory before mount activation

The host tmpfs fstab entry remains `noauto` so an ordinary `mount -a`
never silently starts it. The C1-specific host service `fi_c1_ram`
(`# REQUIRE: FILESYSTEMS`, `# BEFORE: jail`) is installed **disabled**
through the explicit `apply-c1-ram-host-runtime` command and checked with
`verify-c1-ram-host-runtime`. Its startup creates the volatile host
mountpoint, refuses an already mounted target, then mounts ONLY the
fstab-defined tmpfs. It does not unmount it during jail shutdown.

**Before enabling that host service**, independently review/install the
exact host and jail fstab entries, then verify the FreeBSD rcorder and
root/UID/GID mount behavior on a disposable test or maintenance window.
Never enable either fi-ingest or fi-sor C1 service until the host startup
ordering and all original signed custody RO mappings are proven. On C220,
keep the current ingress path and populated SoR unmodified until acceptance.

## Explicit offline fstab installation (does not mount or enable)

After inspecting the exact read-only `plan-c1-ram-mounts` output, the
FreeBSD host installer provides `apply-c1-ram-fstab`, guarded by
`FI_C1_RAM_FSTAB_APPROVED=EXACT_C1_MOUNT_PLAN_REVIEWED`. It preflights all
three existing fstab files, refuses symlinks and foreign/duplicate/changed
mountpoints, stages each change under its destination directory, and
atomically appends only the exact missing entry while preserving unrelated
lines and ownership/mode. **Never mount or start C1 automatically.**

If any rename fails, service enablement remains prohibited. Inspect and
re-run the idempotent operation only after resolving the conflict. The
host and jail fstab changes are individually atomic, **not** one
cross-file database transaction. Verify the exact entries with
`audit-c1-ram-mounts`, then run the actual host `fi-c1-host-preflight`
after deliberate, separately authorized mounts. Keep C220 live fi
ingestion disabled until end-to-end acceptance.

## FreeBSD C1 binary staging includes host-side acceptance

The exact development binary bundle for
`fi-backend-install apply-c1-binaries` must contain all three distinct
FreeBSD executables:

- `fi-c1-ingest-worker` (installed inside fi-ingest)
- `fi-c1-sor-worker` (installed inside fi-sor-db)
- `fi-c1-host-preflight` (installed on the FreeBSD host, NOT in a jail)

All are root-owned, mode `0555`, and installed without enabling a
service. Missing host-preflight binary rejects the entire staged plan
before changing any file. The **host** must run it after deliberate
tmpfs/nullfs mounts using the actual installer's jail roots, numeric
UID/GID and read-only original receiver custody checks. Neither
fi-ingest nor fi-sor may declare itself ready merely because its binary
exists.

The same `apply-c1-binaries` bundle also requires the
`fi-c1-private-schema` standalone **offline** PostgreSQL 18 admin tool
inside fi-sor-db. The installer only copies it as root-owned mode
`0555`; it **never executes DDL**. Its separate command requires the
`FI_C1_SCHEMA_INSTALL_APPROVED=OFFLINE_PRIVATE_STAGE_ONLY` guard, a
local administrative Unix-domain PostgreSQL connection, and an exact
absent-private-schema preflight before creating any private relations.
