# FI FreeBSD Real-Host Acceptance

This document defines final real-host acceptance for the FI FreeBSD backend
deployment layer.

Offline render, classification, collision, no-clobber, and lifecycle tests do
not replace this acceptance.

The real host must prove that the rendered and applied state behaves correctly
under the actual FreeBSD kernel, devfs, jail, VNET, interface, routing, and rc
environment.

## Safety boundary

The administrative interface and administrative address are outside FI
mutation authority.

For the current receiver host:

    administrative interface: vtnet0
    administrative IPv4:      192.168.1.218/24

FI must never:

- detach the administrative interface;
- rename the administrative interface;
- move it into a jail;
- add it to an FI bridge;
- remove its administrative address;
- replace its administrative route;
- use it as the receiver dedicated external interface.

The dedicated receiver physical external interface is:

    vtnet1

It remains host-owned in both stopped and running receiver states.

When the receiver jail is stopped:

- `vtnet1` must carry no FI layer-3 address;
- `vtnet1` must carry no FI route;
- `bridge30` must be absent;
- `epre0a` must be absent;
- `epre0b` must be absent.

When the receiver jail is running:

- the host retains `vtnet1`;
- `bridge30` is the no-IP external layer-2 bridge;
- `bridge30` contains only `vtnet1` and `epre0a`;
- the host retains `epre0a`;
- only `fi-receiver` receives `epre0b`;
- `epre0b` carries the receiver external address.

`fi-ingest` and `fi-sor-db` must never receive `vtnet1`, `epre0a`, or `epre0b`.

## Production topology

Host:

    vtnet0      administrative network
    vtnet1      dedicated receiver physical external interface
    bridge10    FI management bridge, 10.77.10.1/24
    bridge20    FI workload bridge, 10.77.20.1/24

Receiver-running external topology:

    bridge30    FI receiver external layer-2 bridge, no FI IP address
        vtnet1  dedicated physical member
        epre0a  host external epair member

    epre0b      receiver external jail endpoint

Production jail addresses:

    fi-receiver
        external    192.168.1.219/24
        management  10.77.10.20/24
        workload    10.77.20.20/24

    fi-ingest
        management  10.77.10.21/24
        workload    10.77.20.21/24

    fi-sor-db
        management  10.77.10.22/24
        workload    10.77.20.22/24

Receiver default route:

    192.168.1.1 through epre0b

Ingest and System-of-Record default route:

    10.77.10.1 through their management VNET interface

## Production lifecycle

FI does not own the global FreeBSD jail service policy.

FI must not change:

    jail_enable
    jail_parallel_start
    jail_list
    jail_reverse_stop

FI production lifecycle authority is:

    /usr/local/etc/rc.d/fi_pf
    /usr/local/etc/rc.d/fi_jails
    /etc/rc.conf.d/fi_pf
    /etc/rc.conf.d/fi_jails
    /etc/rc.conf.d/devfs/90-fi

FI persistent packet-filter authority is:

    /etc/pf.conf

The host startup dependency is:

    pf
        -> fi_pf
            -> fi_jails

After `fi_pf` reports ready, the production jail startup order is:

    fi-sor-db
    fi-ingest
    fi-receiver

The production shutdown order is:

    fi-receiver
    fi-ingest
    fi-sor-db

The explicit jail dependency chain is:

    fi-sor-db
        -> fi-ingest
        -> fi-receiver

## Phase 0 - administrative prerequisites

Do not begin production mutation unless:

- administrative access through `vtnet0` is stable;
- the intended host identity is confirmed;
- the production configuration has been reviewed;
- a second administrative session or console path is available;
- the current Git commit is recorded;
- the worktree used for deployment is clean;
- the real-host baseline snapshot has been captured.

A host reboot is not part of the initial apply sequence.

Reboot persistence acceptance must not be attempted unless a working console
or equivalent out-of-band recovery path is available.

## Phase 1 - baseline

Capture the host state before any production mutation.

At minimum record:

- hostname and FreeBSD version;
- administrative interface state;
- dedicated receiver interface state;
- management bridge state;
- workload bridge state;
- IPv4 routing table;
- running jails;
- global jail rc policy;
- devfs rc policy;
- in-kernel devfs ruleset list;
- existing FI production destination files.

The baseline must show that no production FI jail is running before the first
controlled deployment acceptance unless an earlier accepted deployment is
being revalidated.

## Phase 2 - preflight and deterministic render

Run the production preflight and render the exact desired state before
mutation.

Reject the deployment before mutation if any required production resource is:

- a foreign collision;
- FI-owned but drifted where replacement is not explicitly allowed;
- unknown because inspection failed;
- located on the wrong host;
- inconsistent with the reviewed configuration.

The rendered plan must contain no unresolved FI tokens.

## Phase 3 - configuration apply

Apply the implemented layers in contract order:

    1. ZFS hierarchy
    2. jail roots
    3. jail-local identities
    4. jail-local filesystem directories
    5. System-of-Record PostgreSQL policy and PGDATA authority
    6. in-kernel dedicated production devfs ruleset
    7. deterministic host files
    8. persistent FI PF policy
    9. lifecycle files

Each layer must pass its own verification before the next layer is accepted.

Lifecycle-file installation itself must not:

- start a jail;
- stop a jail;
- reload a running service;
- move an interface;
- alter a route;
- alter a bridge;
- mutate the running devfs ruleset.

The in-kernel devfs apply operation is a separate earlier layer and must
already have passed its own acceptance.

The PostgreSQL policy layer must be applied while `fi-sor-db` is stopped.
Before proceeding it must prove:

- the package-provided `postgres` UID and primary GID are exact and consistent;
- `FI_SOR_POSTGRES_HOST` is a non-symlink directory;
- PGDATA owner/group match that package identity;
- PGDATA mode is exactly `0700`;
- `/etc/rc.conf.d/postgresql` is exact FI-owned state.

## Phase 4 - post-configuration quiescent proof

Before production jail activation, capture host state again.

The comparison with the baseline must prove:

- administrative connectivity remains intact;
- `vtnet0` remains host-owned and unchanged by FI;
- `vtnet1` remains host-owned;
- `vtnet1` has not gained an FI address;
- `vtnet1` has not gained an FI route;
- `vtnet1` has not joined bridge10 or bridge20;
- `bridge30`, `epre0a`, and `epre0b` remain absent before receiver startup;
- no production FI jail was started by configuration installation;
- global jail-service policy remains site-owned;
- all five FI lifecycle resources match reviewed desired state;
- `/etc/pf.conf` matches the reviewed FI persistent PF policy;
- PF runtime has not been activated merely by persistent-policy installation;
- the dedicated production devfs ruleset is exact;
- the FI-managed PostgreSQL rc policy remains exact;
- authoritative PGDATA ownership and mode remain exact.

## Phase 5 - controlled first start

Activate the reviewed FI PF runtime policy first:

    /usr/local/etc/rc.d/fi_pf start

Before production-jail startup, `fi_pf onestatus` must report ready and the
runtime bridge-filtering state must be exact.

Then start FI through the dedicated FI jail lifecycle controller.

Do not start the three production jails independently for initial acceptance.

The jail controller must establish:

    fi-sor-db
    fi-ingest
    fi-receiver

in that order.

After startup prove:

- all three production jails exist;
- `fi-receiver` has `/var/db/fi/custody/transport` mounted read/write;
- `fi-ingest` has no transport-custody mount;
- no unexpected FI jail exists;
- the System of Record has only its intended VNET interfaces;
- ingest has only its intended VNET interfaces;
- receiver has its management, workload, and external epair interfaces;
- the host still owns `vtnet1`;
- `bridge30` exists with only `vtnet1` and `epre0a` as members;
- `bridge30` has no FI layer-3 address;
- `epre0a` remains host-owned;
- only the receiver owns `epre0b`;
- receiver external IPv4 on `epre0b` is exactly 192.168.1.219/24;
- receiver default route is exactly through 192.168.1.1 on `epre0b`;
- ingest default route uses its management path;
- System-of-Record default route uses its management path;
- the host administrative interface remains healthy;
- the host administrative route remains healthy.
- PostgreSQL started through normal jail rc;
- `fi-sor-db` has private `sysvmsg`, `sysvsem`, and `sysvshm` namespaces;
- those namespace modes are `new`, not `inherit`;
- deprecated `allow.sysvipc` is not granted;
- PostgreSQL is using `/var/db/fi/sor/postgres`;
- the mounted PGDATA source retains the accepted owner/group and mode.

## Phase 6 - controlled first stop

Stop FI through the dedicated FI lifecycle controller.

The controller must stop:

    fi-receiver
    fi-ingest
    fi-sor-db

in that order.

After shutdown prove:

- none of the three production FI jails is running;
- `bridge30` is absent;
- `epre0a` is absent;
- `epre0b` is absent;
- `vtnet1` remains present and host-owned;
- `vtnet1` carries no FI layer-3 address;
- `vtnet1` carries no FI route;
- `vtnet1` is not a member of bridge10;
- `vtnet1` is not a member of bridge20;
- `vtnet0` and 192.168.1.218/24 remain intact;
- FI PF enforcement remains active by design while the production jails are
  stopped.

Clean teardown of `bridge30`, `epre0a`, and `epre0b` together with clean
host ownership of `vtnet1` is a mandatory acceptance gate.

## Phase 7 - restart repeatability

Repeat one complete FI start and stop cycle.

The second cycle must require no repair or cleanup from the first cycle.

Accept only if:

- startup succeeds without stale epair/interface collisions;
- jail network state is identical to the first accepted start;
- shutdown succeeds without manual intervention;
- the dedicated physical interface again returns cleanly;
- no stale FI epair remains;
- administrative connectivity remains intact.
- PostgreSQL restarts without manual repair;
- the private PostgreSQL IPC namespace state remains exact.

## Phase 8 - persistence acceptance

Persistent boot acceptance is separate from first live activation.

Before a reboot:

- all previous phases must be accepted;
- a working local console or equivalent out-of-band path must exist;
- the reboot must occur in an approved maintenance window.

After reboot prove:

- `/etc/devfs.rules.fi` is loaded through the persistent devfs policy;
- the FI production ruleset is exact;
- base PF loads before `fi_pf`;
- `fi_pf` validates and activates the reviewed FI PF runtime policy;
- `fi_jails` starts only after verified `fi_pf` readiness;
- the three FI production jails start in the intended dependency order;
- the host retains `vtnet1`;
- receiver external topology is `vtnet1 -> bridge30 -> epre0a/epre0b`;
- only `epre0b` enters the receiver VNET;
- all expected network state is correct;
- administrative access remains intact;
- PostgreSQL starts through normal jail rc;
- PostgreSQL private IPC namespace state remains exact;
- authoritative PGDATA ownership and mode remain exact;
- the runtime PF filter/NAT snapshot matches the active rules.

Then perform one controlled stop/start cycle after reboot and repeat the
dedicated-interface return proof.

## Phase 9 - acceptance result

Real-host acceptance is complete only when all mandatory checks pass.

Record:

- Git commit deployed;
- configuration file used;
- host identity;
- FreeBSD version;
- acceptance date;
- pre-apply snapshot;
- post-configuration snapshot;
- running snapshot;
- stopped snapshot;
- restart snapshot;
- reboot snapshot when persistence acceptance is performed.

A failed mandatory check leaves the real-host gate open.

## Receiver trust acceptance record

Receiver trust establishment is recorded separately in
[`RECEIVER-TRUST-ACCEPTANCE.md`](RECEIVER-TRUST-ACCEPTANCE.md).

That record includes the FreeBSD private-key and trust-custody boundary, the
dedicated Windows AD CS `FI-Receiver-TLS` server-authentication template,
direct-root issuance, root/CRL validation, receiver certificate/key binding,
hostname and revocation validation, and the runtime `fi-receiver trust status`
result.

The October 4 receiver-trust record intentionally ended `NOT_READY` because
no real source-registry entry had yet been installed. That historical record
remains unchanged.

A real authorized source was subsequently installed and exercised during the
October 5 acceptance described below.

## October 5, 2026 - application runtime and live lifecycle acceptance

Host:

    fi-backend-b

Repository base HEAD at the time of acceptance:

    cb3856fef41ec31c81d2f45d85da52cf278b689b

The application-runtime implementation exercised by this acceptance was
uncommitted working-tree content on top of that base HEAD. Therefore
`cb3856f` must not be represented as containing the runtime implementation.

The accepted real source was:

    adminbox.iss.local

### End-to-end ingest path

The live path was exercised through:

    authorized Windows source
        -> receiver mTLS/source authorization
        -> transport custody
        -> generation custody
        -> recorded receipt
        -> READY publication
        -> relational ingest worker
        -> restricted PostgreSQL connection
        -> authoritative System of Record
        -> READY retirement

A real generation was accepted and committed to PostgreSQL. READY subsequently
returned to zero.

The ingest-to-PostgreSQL runtime connection used:

    fi-ingest 10.77.20.21
        -> fi-sor-db 10.77.20.22:5432

with the reviewed isolated-VNET connection string using `sslmode=disable`.
This setting is accepted only inside the FI workload network boundary enforced
by the reviewed FI PF policy. Direct external PostgreSQL access remains
prohibited.

### Managed runtime publication

The six managed receiver/ingest runtime resources were first brought under FI
runtime ownership and subsequently updated through the explicit approved-prior
managed-update path.

The managed update changed only the two rc.d service files required for
volatile runtime-directory recovery. The supervisor and runner processes were
not restarted by runtime publication.

Independent `verify-runtime` acceptance succeeded after publication.

### Volatile runtime recovery

Receiver acceptance proved that with `/var/run/fi` absent, normal rc.d startup
recreated:

    /var/run/fi
        owner 4100
        group 4100
        mode  0700

and restored the receiver supervisor and a listening receiver worker at:

    192.168.1.219:8443

Five consecutive listener observations succeeded.

Ingest acceptance proved that with the worker stopped, its released singleton
lock pathname could be removed and `/var/run/fi` made genuinely absent.
Normal rc.d startup then recreated:

    /var/run/fi
        owner 4100
        group 4100
        mode  0700

The ingest worker recreated:

    /var/run/fi/fi-ingest-worker.lock
        owner 4100
        group 4100
        mode  0600

and held the exclusive lock through an open worker file descriptor.

The ingest worker then re-established PostgreSQL connectivity and READY
returned to zero.

### Production jail lifecycle

The accepted FI lifecycle controller stopped production jails in this order:

    fi-receiver
    fi-ingest
    fi-sor-db

All three were confirmed stopped. `fi-dev` remained running and was not part of
the production lifecycle mutation.

The same controller then started production jails in this order:

    fi-sor-db
    fi-ingest
    fi-receiver

The first health sample observed the System of Record and ingest ready while
the receiver was still starting. The second sample observed all three
application paths network-ready.

Post-start acceptance proved:

    PostgreSQL
        10.77.20.22:5432 listening

    ingest
        connected to 10.77.20.22:5432

    receiver
        192.168.1.219:8443 listening

    ingest /var/run/fi
        4100:4100 mode 0700

    receiver /var/run/fi
        4100:4100 mode 0700

    ingest singleton lock
        4100:4100 mode 0600
        held by the running ingest worker

    READY
        0

    FI PF runtime policy
        ready

Both receiver and ingest supervisor identities changed across the complete jail
stop/start cycle, proving recreation through normal jail rc rather than survival
of the prior processes.

### Repository regression gate

After live acceptance:

- receiver and ingest runtime boot-directory acceptance passed;
- runtime apply acceptance passed;
- runtime adoption acceptance passed;
- runtime update acceptance passed;
- all reviewed shell files passed `sh -n`;
- `go test ./...` passed;
- `git diff --check` passed.

### Persistence boundary

This October 5 result accepts the live application runtime, volatile runtime
recovery, and complete managed production-jail stop/start lifecycle.

It does not record Phase 8 host-reboot persistence acceptance.

A full host reboot remains a separate acceptance event requiring the approved
maintenance-window and console/out-of-band prerequisites already defined in
Phase 8. Until that event is performed, no reboot snapshot is claimed.
