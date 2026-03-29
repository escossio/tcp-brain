#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit, unquote_plus

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import backfill_patterns as common  # type: ignore


ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>[^"]+) HTTP/(?P<httpver>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

API_PREFIX = "/api/"
PAYLOAD_QUERY_KEYS = ("snippet", "text", "payload", "body", "raw", "message", "input")


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_apache_timestamp(value: str) -> Optional[dt.datetime]:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_request_target(target: str) -> Tuple[str, str, Optional[str]]:
    split = urlsplit(target)
    path = split.path or "/"
    query = split.query or ""
    payload = None
    if query:
        params = parse_qs(query, keep_blank_values=True)
        for key in PAYLOAD_QUERY_KEYS:
            values = params.get(key)
            if not values:
                continue
            for value in values:
                cleaned = unquote_plus(value).strip()
                if cleaned:
                    payload = cleaned
                    break
            if payload:
                break
    return path, query, payload


def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
    match = ACCESS_LOG_RE.match(line.rstrip("\n"))
    if not match:
        return None

    groups = match.groupdict()
    path, query, payload = parse_request_target(groups["target"])
    if not path.startswith(API_PREFIX):
        return None

    status = int(groups["status"])
    bytes_sent = groups["bytes"]
    referer = groups["referer"].strip()
    user_agent = groups["ua"].strip()
    timestamp = parse_apache_timestamp(groups["ts"])

    endpoint = path
    if query:
        endpoint = f"{path}?{query}"

    snippet = payload if payload else f"{groups['method']} {endpoint}"
    explanation = (
        f"Apache access log: {groups['method']} {path} "
        f"status={status} bytes={bytes_sent} referer={referer or '-'}"
    )
    tags = [
        "source=apache-access",
        f"method={groups['method']}",
        f"endpoint={path}",
        f"status={status}",
        f"status_class={status // 100}xx",
    ]
    if payload:
        tags.append("payload_source=query")
    if user_agent:
        tags.append("ua=present")

    return {
        "timestamp": timestamp.isoformat() if timestamp else "",
        "severity": "low" if status < 400 else ("medium" if status < 500 else "high"),
        "source": "apache-access",
        "tags": tags,
        "snippet": snippet,
        "explanation": explanation,
    }


def iter_access_events(path: Path, start_line: int) -> Iterator[Tuple[int, Dict[str, Any]]]:
    with open_text(path) as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            if line_no < start_line:
                continue
            parsed = parse_access_line(raw_line)
            if parsed:
                yield line_no, parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill de padrões TCP a partir de Apache access logs históricos.")
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--start-line", type=int, default=1)
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--no-ai", action="store_true", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--dedup-strict", action="store_true", default=True)
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--dsn", default=None)
    parser.add_argument("--db-host", default=None)
    parser.add_argument("--db-port", default=None)
    parser.add_argument("--db-name", default=None)
    parser.add_argument("--db-user", default=None)
    parser.add_argument("--db-password", default=None)
    parser.add_argument("--commit-every", type=int, default=50)
    return parser


def load_checkpoint(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_checkpoint(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = build_parser().parse_args()
    common.load_env_file(common.DEFAULT_BRAIN_ENV)

    source_file = Path(args.source_file)
    if not source_file.exists():
        print(f"[erro] arquivo de origem não encontrado: {source_file}", file=sys.stderr)
        return 2

    log_handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        log_path = Path(args.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=log_handlers)
    log = logging.getLogger("tcp-access-backfill")

    checkpoint_path = Path(args.checkpoint) if args.checkpoint else None
    checkpoint = load_checkpoint(checkpoint_path)
    start_line = max(args.start_line, int(checkpoint.get("next_line", args.start_line)))

    conn = common.make_db_conn(args)
    conn.autocommit = False
    table_columns = common.get_table_columns(conn, "tcp_patterns")

    metrics = {
        "source": str(source_file),
        "source_kind": "apache-access",
        "start_line": start_line,
        "dry_run": bool(args.dry_run),
        "no_ai": True,
        "dedup_strict": bool(args.dedup_strict),
        "lines_read": 0,
        "events_seen": 0,
        "api_events_seen": 0,
        "eligible_events": 0,
        "processed_candidates": 0,
        "known_patterns": 0,
        "new_patterns": 0,
        "ai_calls": 0,
        "skipped_non_api": 0,
        "parse_errors": 0,
        "write_errors": 0,
        "commits": 0,
        "payload_hits": 0,
    }

    next_line = start_line
    pending_since_commit = 0
    t0 = dt.datetime.now(dt.timezone.utc)

    try:
        for line_no, event in iter_access_events(source_file, start_line):
            next_line = line_no + 1
            metrics["events_seen"] += 1
            metrics["api_events_seen"] += 1
            metrics["lines_read"] = line_no

            snippet = str(event.get("snippet", "")).strip()
            if not snippet:
                metrics["skipped_non_api"] += 1
                continue

            explanation = str(event.get("explanation", "")).strip()
            if not explanation:
                metrics["skipped_non_api"] += 1
                continue

            severity = str(event.get("severity") or "unknown").strip() or "unknown"
            tags = event.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            tags = [str(tag) for tag in tags if str(tag).strip()]

            if "payload_source=query" in tags:
                metrics["payload_hits"] += 1

            metrics["eligible_events"] += 1

            canon = common.canonicalize_snippet(snippet)
            pattern_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()

            if args.dedup_strict and common.read_existing_hashes(conn, pattern_hash):
                metrics["known_patterns"] += 1
                metrics["processed_candidates"] += 1
                if metrics["processed_candidates"] >= args.limit:
                    break
                continue

            if args.dry_run:
                metrics["new_patterns"] += 1
                metrics["processed_candidates"] += 1
                if metrics["processed_candidates"] >= args.limit:
                    break
                continue

            try:
                inserted = common.insert_pattern(
                    conn=conn,
                    table_columns=table_columns,
                    pattern_hash=pattern_hash,
                    snippet=canon,
                    explanation=explanation,
                    severity=severity,
                    tags=tags,
                    seen_at=common.parse_iso_timestamp(str(event.get("timestamp"))) or dt.datetime.now(dt.timezone.utc),
                )
                if inserted:
                    metrics["new_patterns"] += 1
                else:
                    metrics["known_patterns"] += 1
                metrics["processed_candidates"] += 1
                pending_since_commit += 1
                if pending_since_commit >= max(1, args.commit_every):
                    conn.commit()
                    metrics["commits"] += 1
                    pending_since_commit = 0
                if metrics["processed_candidates"] >= args.limit:
                    break
            except Exception as exc:
                conn.rollback()
                metrics["write_errors"] += 1
                log.error("Falha ao gravar pattern_hash=%s: %s", pattern_hash, exc)
                continue

        if not args.dry_run and pending_since_commit > 0:
            conn.commit()
            metrics["commits"] += 1

    except Exception as exc:
        conn.rollback()
        log.exception("Falha geral no backfill de access logs: %s", exc)
        return 1
    finally:
        conn.close()

    metrics["elapsed_seconds"] = round((dt.datetime.now(dt.timezone.utc) - t0).total_seconds(), 3)
    metrics["next_line"] = next_line

    if checkpoint_path:
        save_checkpoint(
            checkpoint_path,
            {
                "source": str(source_file),
                "source_kind": "apache-access",
                "next_line": next_line,
                "metrics": metrics,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
        )

    log.info("Resumo final: %s", json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
