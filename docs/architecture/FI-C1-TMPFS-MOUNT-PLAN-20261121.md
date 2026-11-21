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
