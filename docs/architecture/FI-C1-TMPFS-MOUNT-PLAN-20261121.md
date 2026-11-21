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
