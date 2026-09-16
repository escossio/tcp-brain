# DEPLOYMENT

## Current state

Today there is no verified automatic deployment from GitHub `main` to production.

Merging to `main` does not imply:

- backend runtime update;
- frontend publication;
- Apache reload;
- Cloudflare change;
- detector reactivation;
- database migration.

## Authorities

### Source control

```text
GitHub main
```

GitHub stores the official source and documentation.

### Runtime

```text
/srv/migrated-debian2/app-data/tcp-brain
```

This is the active code directory used by `tcp-brain.service`.

### Publication

```text
/srv/escossio-site/public/tcp-brain
```

This is the frontend copy served by Apache to users.

### Configuration

```text
/etc/tcp-brain/
systemd
Apache
Cloudflare
```

Configuration remains machine-specific and outside Git. Secrets must stay outside this repository.

## What not to assume

- Do not assume GitHub `main` is live immediately after merge.
- Do not blindly copy repository files over runtime.
- Do not blindly sync `public/tcp-brain` over the published frontend.
- Do not overwrite detector data.
- Do not run schema creation, migrations, or backfills as part of documentation or source preservation.

## Future deployment contract

A future deployment process should provide:

- identifiable source version;
- staging or isolated validation before switch-over;
- explicit backend and frontend artifact selection;
- rollback plan;
- preservation of environment files and secrets;
- smoke test before and after deployment;
- frontend/backend consistency checks;
- no overwrite of detector snapshots or generated diagnostics;
- no unexpected database migrations;
- post-deploy health verification;
- separate freshness verification for detector snapshots.

This section is a specification for future work, not an implementation.
