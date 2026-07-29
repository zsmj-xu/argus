# Argus V2 control-store migrations

The Control Store schema is changed only through Alembic revisions in
`versions/`. Application startup must not call `Base.metadata.create_all()`.

Apply the current schema explicitly with:

```python
from argus.control.db import upgrade_database

upgrade_database("runs/control.db")
```

## Backup, upgrade, and rollback

Never test a migration rollback on the only copy of a Control Store.

1. Stop scan writers.
2. Run `argus control-backup --output <new-path>`; existing destinations are
   rejected.
3. Verify the reported SHA-256 and run SQLite `PRAGMA integrity_check`.
4. Apply Alembic upgrades to a copy in staging, then run the V2 migration,
   repository, recovery, Web, and verification tests.
5. Upgrade production with `upgrade_database`.

If an upgrade fails, stop writers, preserve the failed database for diagnosis,
and restore the verified backup as a new file before atomically switching the
deployment configuration. Do not overwrite the failed database in place.
Alembic downgrades are development aids, not the production recovery mechanism.

Artifact payloads are content-addressed outside SQLite. Back up `control.db` and
`runs/_data/artifacts/` as one recovery set. `argus artifact-gc` is dry-run by
default; `--apply` moves blobs to `.trash/` and never permanently deletes them.
