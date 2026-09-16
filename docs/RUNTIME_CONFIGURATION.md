# RUNTIME CONFIGURATION

This document describes the environment contract for TCP Brain. It intentionally does not include production secret values.

## Backend listener

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `TCP_BRAIN_HOST` | Host/interface used when running `tcp_brain.py` directly. | Optional | `127.0.0.1` | No |
| `TCP_BRAIN_PORT` | Port used when running `tcp_brain.py` directly. | Optional | `8091` | No |

Current production overrides the port to `18091` through runtime configuration. The code default remains `8091` for compatibility.

## Database

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `TCP_BRAIN_DB_DSN` | Full PostgreSQL DSN. When set, it is used instead of individual host/db/user fields. | Optional | empty | Yes if it contains credentials |
| `TCP_BRAIN_DB_HOST` | PostgreSQL host when DSN is not used. | Optional | `127.0.0.1` | No |
| `TCP_BRAIN_DB_PORT` | PostgreSQL port when DSN is not used. | Optional | `5432` | No |
| `TCP_BRAIN_DB_NAME` | PostgreSQL database name when DSN is not used. | Optional | `tcp_brain` | No |
| `TCP_BRAIN_DB_USER` | PostgreSQL user when DSN is not used. | Optional | `tcp_brain` | Sometimes |
| `TCP_BRAIN_DB_PASSWORD` | PostgreSQL password. Preferred password variable. | Optional by code, required for password-protected DBs | empty | Yes |
| `TCP_BRAIN_DB_PASS` | Legacy fallback password variable. | Optional | empty | Yes |

Do not commit real DSNs, passwords, or environment files.

## Upstream AI

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `OPENAI_API_KEY` | API key used by `/api/tcp-explain` when an upstream call is required. | Optional by code, required for paid upstream use | empty | Yes |
| `TCP_BRAIN_UPSTREAM_URL` | Chat completions-compatible upstream endpoint. | Optional | `https://api.openai.com/v1/chat/completions` | No |
| `TCP_BRAIN_UPSTREAM_MODEL` | Upstream model name. | Optional | `gpt-4.1-mini-2025-04-14` | No |
| `TCP_BRAIN_COST_PER_IA_CALL_BRL` | Accounting estimate for AI calls. | Optional | `0.01` | No |

Do not use `/api/tcp-explain` as a smoke-test endpoint unless the test is explicitly allowed to perform upstream calls.

## Detector

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `TCP_BRAIN_DETECTION_STATUS_DIR` | Directory containing `tcp_detection_status.json`. | Optional | `/srv/tcp/knowledge/detection` | No |

Current production uses a migrated detector data path through runtime configuration:

```text
/srv/migrated-debian2/app-data/tcp-knowledge/detection
```

The default remains a legacy compatibility fallback.

## History helpers

These variables are used by `tcp_history.py` and maintenance scripts:

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `TCP_BRAIN_HISTORY_DIR` | Base directory for event history. | Optional | `/srv/tcp/knowledge/events` | No |
| `TCP_BRAIN_HISTORY_RETENTION_DIR` | Directory for retained history archives. | Optional | `/srv/tcp/knowledge/retention` | No |
| `TCP_BRAIN_HISTORY_FILE` | Explicit history file path. | Optional | derived from `TCP_BRAIN_HISTORY_DIR` | No |
| `TCP_BRAIN_HISTORY_EXCERPT_CHARS` | Maximum excerpt length. | Optional | `240` | No |
| `TCP_BRAIN_HISTORY_CANONICAL_CHARS` | Maximum canonical text length. | Optional | `360` | No |
| `TCP_BRAIN_HISTORY_QUEUE_SIZE` | In-memory history queue size. | Optional | `2000` | No |
| `TCP_BRAIN_HISTORY_MAX_BYTES` | History file rotation threshold. | Optional | `5242880` | No |
| `TCP_BRAIN_HISTORY_RETENTION_KEEP` | Number of retained files. | Optional | `20` | No |

## Smoke test

| Variable | Purpose | Required | Default | Sensitive |
| --- | --- | --- | --- | --- |
| `TCP_BRAIN_SMOKE_BASE_URL` | Base URL used by `scripts/smoke_tcp_brain.py`. | Optional | `https://tcp.escossio.dev.br` | No |
| `TCP_BRAIN_SMOKE_TIMEOUT` | Smoke-test timeout in seconds. | Optional | `15` | No |

The smoke-test defaults are not fully aligned with the current `/tcp-brain/` public topology.
