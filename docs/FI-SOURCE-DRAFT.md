# fi-source — FreeBSD source enrollment (development candidate)

`fi-source` is a **separate Go command** for adding a previously authorized Windows source to an existing FI FreeBSD receiver/ingest backend. It is **not the backend installer** and does **not alter Windows hosts**.

## Current prototype commands

```sh
fi-source list
fi-source status -source iss-fs-2022.iss.local
fi-source plan -config /absolute/path/iss-fs-new.example.conf
fi-source add -config /absolute/path/iss-fs-new.example.conf
# Explicit recovery only, if registration published but service refresh failed:
fi-source add -config /absolute/path/iss-fs-new.example.conf -refresh ingest
```

The input is FI's existing strict `version_id: 2.0` **`.conf`** source authorization file (not JSON). PKI and source material must already have been issued and approved. `add` requires root on the FreeBSD **host**. `plan`, `list`, and `status` are read-only.

`add` validates both registries and installed issuing CA fingerprints before creating anything. Exact existing registrations are never overwritten. New files are root-owned and group-owned according to each registry directory. Files are published without replacement, verified through jail mounts, followed by receiver trust validation. Only affected services are restarted. All failures are reported; after publication, an error is treated as **partial enrollment requiring operator intervention**, not as success. A retry with both files already present **does not claim runtime activation**. The administrator may explicitly restart the affected service with `-refresh receiver`, `-refresh ingest`, or `-refresh both` after resolving the cause. This avoids silent retry success and avoids restarting healthy services by default. If the selected service is stopped after a failed restart, recovery uses `onestart` instead of a blind `restart`.

The command does **not** create Windows certificates, change Windows services, install jails, migrate custody state, or alter PostgreSQL. Automatic PostgreSQL committed-generation verification, fully automatic recovery after partially completed restarts, signed PKI issuance, and installer packaging still need acceptance work. This revision provides a narrow explicit retry mechanism, not automatic transactional recovery. `status` and `list` report **registry consistency only**, not proven runtime activity or database acceptance.

## Safety

Do **not** install this development candidate into the operational backend until reviewed and tested on `fi-dev`, followed by a disposable three-source test topology. In particular, verify trust-status parsing, host mount behavior, service restart semantics, failure injection, and recovery on the actual FreeBSD release before invoking `add` on a production backend.
