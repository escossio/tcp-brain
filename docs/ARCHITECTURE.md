# ARCHITECTURE

This document describes the current observed TCP Brain production architecture.

## Request path

```text
Internet
-> Cloudflare
-> Apache
-> frontend /tcp-brain/
-> API /tcp-brain/api/
-> TCP Brain :18091
-> PostgreSQL
```

Apache serves the static frontend under `/tcp-brain/` and proxies `/tcp-brain/api/` to the backend API on `127.0.0.1:18091`.

The backend itself exposes API paths without the public prefix:

```text
/api/health
/api/stats
/api/recent
/api/detection/latest
/api/tcp-explain
/metrics
```

## Detector data path

```text
detector engine
-> tcp_detection_status.json
-> TCP Brain
-> /api/detection/latest
-> frontend
```

The detector writes a status snapshot. TCP Brain reads that snapshot from the directory configured by `TCP_BRAIN_DETECTION_STATUS_DIR` and exposes it through `/api/detection/latest`.

## Component boundaries

The backend and detector are related, but they are not equivalent.

- Backend health means the API process is running and reachable.
- Detection freshness means the detector is producing current snapshots.

The backend can be healthy while the detector is stopped or stale. Always check detector timestamps separately from `/api/health`.

## Runtime locations

- Source code: GitHub `main`.
- Runtime code: `/srv/migrated-debian2/app-data/tcp-brain`.
- Published frontend: `/srv/escossio-site/public/tcp-brain`.
- Detector data: `/srv/migrated-debian2/app-data/tcp-knowledge/detection`.
- Runtime configuration: `/etc/tcp-brain/`, `systemd`, Apache, Cloudflare.

GitHub `main` is source control. It is not itself a deployment mechanism.
