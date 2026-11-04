# Isolated Security Field Partition Benchmark

This SQL was extracted from the successful November 4, 2026
K32/K64 isolated PostgreSQL 18.6 benchmark databases.

This is an experimental test fixture, not a production migration.

The benchmark functions ran as SECURITY DEFINER under a superuser
owner. Production promotion requires a separately tested,
least-privilege ownership and execution model.

Do not install this fixture on an authoritative FI database.
