# tcp-brain

`tcp-brain` is the TCP intelligence layer used to consolidate detector output, expose a small HTTP API, and serve the dashboard used in production.

## Current production topology

The current observed production path is:

```text
Internet
-> Cloudflare
-> Apache
-> /tcp-brain/ static frontend
-> /tcp-brain/api/ reverse proxy
-> 127.0.0.1:18091
-> TCP Brain
```

The active backend is managed by `tcp-brain.service` and runs from:

```text
/srv/migrated-debian2/app-data/tcp-brain
```

The frontend currently served to users is a separate published copy:

```text
/srv/escossio-site/public/tcp-brain
```

The official frontend is path-prefix aware and runs under:

```text
/tcp-brain/
```

## Source, runtime, publication, configuration

These are separate authorities:

- Source code: GitHub `main`.
- Runtime: `/srv/migrated-debian2/app-data/tcp-brain`.
- Published front: `/srv/escossio-site/public/tcp-brain`.
- Runtime config: `systemd` plus files under `/etc/tcp-brain/`.

After PR #1, GitHub `main` again represents the source code recovered from the active runtime. It does not mean production is automatically updated when `main` changes.

Machine-specific config, service files, Apache rules, Cloudflare routing, secrets, database state, detector output, and published frontend copies remain outside this repository.

## Main components

- Backend/API: `tcp_brain.py`
- Historical/event helpers: `tcp_history.py`
- Offline detector and maintenance scripts: `scripts/`
- Versioned dashboard source: `public/tcp-brain/`
- Operational documentation: `docs/`

## Main endpoints

When accessed through the current public prefix, the main routes are:

- `GET /tcp-brain/` - published dashboard frontend
- `GET /tcp-brain/api/health` - basic service health through Apache
- `GET /tcp-brain/api/stats` - runtime statistics
- `GET /tcp-brain/api/recent` - recent events
- `GET /tcp-brain/api/detection/latest` - latest detector snapshot

When accessed directly on the backend, the same API is served without the `/tcp-brain` prefix:

- `GET /api/health`
- `GET /api/stats`
- `GET /api/recent`
- `GET /api/detection/latest`
- `POST /api/tcp-explain`
- `GET /metrics`

Do not use `GET /api/tcp-explain` as a health check. The application defines the explanation endpoint as `POST`.

## Runtime configuration

The backend host, port, and detector snapshot directory are configurable:

- `TCP_BRAIN_HOST`
- `TCP_BRAIN_PORT`
- `TCP_BRAIN_DETECTION_STATUS_DIR`

The code default for `TCP_BRAIN_PORT` remains `8091` for compatibility. Current production overrides it to `18091` through runtime configuration.

The detector status path used by production is configured outside Git. The current observed detector data directory is:

```text
/srv/migrated-debian2/app-data/tcp-knowledge/detection
```

See [docs/RUNTIME_CONFIGURATION.md](docs/RUNTIME_CONFIGURATION.md) for the full environment contract.

## Detector freshness is not service health

`/api/health` returning `200` means the backend is reachable. It does not prove the detector is producing fresh snapshots.

The detector can be stale or stopped while the backend remains healthy. Check `/tcp-brain/api/detection/latest`, the snapshot timestamp, and the status file mtime before concluding that detection is current.

At the time this documentation was aligned, the detector snapshot was old relative to the current date. Treat detector freshness as a separate operational signal.

## Local run

For local development, install dependencies and run the app with an ASGI server:

```bash
pip install -r requirements.txt
uvicorn tcp_brain:app --host 127.0.0.1 --port 8091
```

For direct script execution:

```bash
TCP_BRAIN_HOST=127.0.0.1 TCP_BRAIN_PORT=8091 python3 tcp_brain.py
```

Use `.env.example` as a placeholder template only. Never copy production secrets into the repository.

## Smoke test status

`scripts/smoke_tcp_brain.py` still defaults to the older host and unprefixed asset paths. It is useful as a code reference, but it is only partially compatible with the current `/tcp-brain/` topology until a future update adjusts its default base URL and asset checks.

## Operational docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/OPERATIONS.md](docs/OPERATIONS.md)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [docs/RUNTIME_CONFIGURATION.md](docs/RUNTIME_CONFIGURATION.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

## Limitations

- Dependency versions are intentionally unpinned for now.
- There is no verified automatic deployment from GitHub `main` to production.
- The detector can run without Prometheus metrics if `prometheus_client` is unavailable, but metrics will be disabled in that case.
- Historical maintenance scripts are operational tools rather than a user-facing API.
