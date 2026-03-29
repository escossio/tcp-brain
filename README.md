# tcp-brain

`tcp-brain` is the TCP intelligence layer used to consolidate detector output, expose a small HTTP API, and serve the dashboard used in production.

## What is included

- Backend/API in `tcp_brain.py`
- Historical/event helpers in `tcp_history.py`
- Offline detector and maintenance scripts in `scripts/`
- Published dashboard/front in `public/tcp-brain/`

## Operational architecture

Production currently runs as:

`Cloudflare Tunnel -> Apache (127.0.0.1:8080) -> static front + /api/ -> backend (127.0.0.1:8091)`

The public dashboard is served from:

- `/dashboard`
- `/css/main.css?v=20260328`
- `/js/main.js?v=20260328`

The consolidated detector status is exposed at:

- `/api/detection/latest`

## Main endpoints

- `GET /` - dashboard entry point
- `GET /dashboard` - main dashboard view
- `GET /api/health` - basic service health
- `GET /api/stats` - runtime statistics
- `GET /api/recent` - recent events
- `GET /api/detection/latest` - consolidated detector result
- `GET /api/tcp-explain` - explanation endpoint
- `GET /metrics` - Prometheus metrics, when enabled

## Repository structure

```text
/srv/tcp-brain
├── tcp_brain.py
├── tcp_history.py
├── requirements.txt
├── public/
│   └── tcp-brain/
├── scripts/
└── .gitignore
```

## Front and backend relationship

The front is a static dashboard that consumes the backend API. In production the same repository also contains the front source under `public/tcp-brain/`, which keeps the published assets and the backend in one place.

The live site also uses a production copy at `/srv/escossio-site/public/tcp-brain`, which is the directory currently exposed by Apache.

## Local run

Install the Python dependencies and run the app with your preferred ASGI server:

```bash
pip install -r requirements.txt
uvicorn tcp_brain:app --host 0.0.0.0 --port 8091
```

Environment variables used by the backend include:

- `TCP_BRAIN_DB_DSN`
- `TCP_BRAIN_DB_HOST`
- `TCP_BRAIN_DB_PORT`
- `TCP_BRAIN_DB_NAME`
- `TCP_BRAIN_DB_USER`
- `TCP_BRAIN_DB_PASSWORD` or `TCP_BRAIN_DB_PASS`
- `OPENAI_API_KEY`
- `TCP_BRAIN_UPSTREAM_URL`
- `TCP_BRAIN_UPSTREAM_MODEL`
- `TCP_BRAIN_COST_PER_IA_CALL_BRL`

## Status and notes

- The detector is designed to operate with a consolidated latest-result endpoint instead of requiring manual digging through historical artifacts.
- `GET /api/detection/latest` is the canonical public entry point for the latest detector snapshot.
- The repository is organized for production use, but it still depends on the surrounding Apache and Cloudflare Tunnel setup for the public domain.
- The front is versioned in the repository, but the live publication path remains separate from the repo root for operational continuity.

## Limitations

- Dependency versions are intentionally unpinned for now.
- The detector can run without Prometheus metrics if `prometheus_client` is unavailable, but metrics will be disabled in that case.
- Historical maintenance scripts are included, but they are operational tools rather than a user-facing API.
