#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import psycopg2
from psycopg2 import sql


DEFAULT_EVENTS_FILE = "/var/log/tcp-sentinel-events.log"
DEFAULT_ALERTS_FILE = "/var/log/tcp-sentinel-alerts.log"
DEFAULT_BRAIN_ENV = "/etc/tcp-brain.env"


def load_env_file(path: str) -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def canonicalize_snippet(text: str) -> str:
    text = re.sub(r"(\d{1,3}(?:\.\d{1,3}){3})[\.:](\d{1,5})", r"<host>.<port>", text)
    text = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "<host>", text)
    text = re.sub(r"\b\d{5,}\b", "<id>", text)
    return text.strip()


def parse_iso_timestamp(value: str | None) -> Optional[dt.datetime]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def extract_structured_explanation(text: str) -> Tuple[str, Optional[str], List[str]]:
    raw = (text or "").strip()
    if not raw:
        return "", None, []

    if raw.startswith("```"):
        inner = raw.strip("`")
        # Tenta remover um prefixo de linguagem tipo "json\n"
        if "\n" in inner:
            first_line, rest = inner.split("\n", 1)
            if first_line.lower() in {"json", "javascript", "js"}:
                inner = rest
        inner = inner.strip()
        if inner.startswith("{") and inner.endswith("}"):
            try:
                data = json.loads(inner)
                exp = str(data.get("explanation", raw)).strip()
                sev = data.get("severity")
                tags = data.get("tags") or []
                if isinstance(tags, list):
                    tags = [str(tag) for tag in tags if str(tag).strip()]
                else:
                    tags = []
                return exp, str(sev).strip() if sev is not None else None, tags
            except Exception:
                pass

    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            exp = str(data.get("explanation", raw)).strip()
            sev = data.get("severity")
            tags = data.get("tags") or []
            if isinstance(tags, list):
                tags = [str(tag) for tag in tags if str(tag).strip()]
            else:
                tags = []
            return exp, str(sev).strip() if sev is not None else None, tags
    except Exception:
        pass

    return raw, None, []


def make_db_conn(args: argparse.Namespace):
    dsn = args.dsn or os.getenv("TCP_BRAIN_DB_DSN", "").strip()
    db_pass = (
        args.db_password
        or os.getenv("TCP_BRAIN_DB_PASSWORD", os.getenv("TCP_BRAIN_DB_PASS", ""))
    ).strip().strip("'\"")

    if dsn:
        if db_pass:
            return psycopg2.connect(dsn, password=db_pass, connect_timeout=3)
        return psycopg2.connect(dsn, connect_timeout=3)

    return psycopg2.connect(
        host=args.db_host or os.getenv("TCP_BRAIN_DB_HOST", "127.0.0.1"),
        port=int(args.db_port or os.getenv("TCP_BRAIN_DB_PORT", "5432")),
        dbname=args.db_name or os.getenv("TCP_BRAIN_DB_NAME", "tcp_brain"),
        user=args.db_user or os.getenv("TCP_BRAIN_DB_USER", "tcp_brain"),
        password=db_pass,
        connect_timeout=3,
    )


def get_table_columns(conn, table: str) -> List[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        return [row[0] for row in cur.fetchall()]


def iter_event_blocks(path: Path, start_line: int) -> Iterator[Tuple[int, Dict[str, Any]]]:
    block: List[str] = []
    line_no = 0
    in_block = False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line_no += 1
            if line_no < start_line:
                continue
            line = raw_line.rstrip("\n")
            if not in_block:
                if line.strip() == "{":
                    in_block = True
                    block = [line]
                continue
            block.append(line)
            if line.strip() == "}":
                try:
                    yield line_no, json.loads("\n".join(block))
                except Exception as exc:
                    raise ValueError(f"Falha ao parsear bloco JSON em {path}:{line_no}: {exc}") from exc
                block = []
                in_block = False


def iter_alert_blocks(path: Path, start_line: int) -> Iterator[Tuple[int, Dict[str, Any]]]:
    block_lines: List[str] = []
    line_no = 0
    seen_separator = False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line_no += 1
            if line_no < start_line:
                continue
            line = raw_line.rstrip("\n")
            if line.startswith("==="):
                if block_lines:
                    parsed = parse_alert_block(block_lines)
                    if parsed:
                        yield line_no, parsed
                    block_lines = []
                seen_separator = True
                continue
            if seen_separator or block_lines:
                block_lines.append(line)
        if block_lines:
            parsed = parse_alert_block(block_lines)
            if parsed:
                yield line_no, parsed


def parse_alert_block(lines: List[str]) -> Optional[Dict[str, Any]]:
    severity = ""
    source = ""
    timestamp = ""
    snippet = ""
    explanation_lines: List[str] = []
    mode = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Data:"):
            timestamp = stripped.split("Data:", 1)[1].strip()
            continue
        if stripped.startswith("Severidade:"):
            severity = stripped.split("Severidade:", 1)[1].strip()
            continue
        if stripped.startswith("Fonte:"):
            source = stripped.split("Fonte:", 1)[1].strip()
            continue
        if stripped == "Trecho analisado:":
            mode = "snippet"
            continue
        if stripped == "Explicação:":
            mode = "explanation"
            continue
        if mode == "snippet":
            if stripped:
                snippet = stripped
                mode = None
            continue
        if mode == "explanation":
            explanation_lines.append(line)
    if not snippet:
        return None
    explanation = "\n".join(explanation_lines).strip()
    return {
        "timestamp": timestamp,
        "severity": severity or "unknown",
        "source": source or "unknown",
        "tags": [],
        "snippet": snippet,
        "explanation": explanation,
    }


def parse_source(path: Path, source_kind: str, start_line: int) -> Iterator[Tuple[int, Dict[str, Any]]]:
    if source_kind == "events":
        yield from iter_event_blocks(path, start_line)
        return
    if source_kind == "alerts":
        yield from iter_alert_blocks(path, start_line)
        return
    raise ValueError(f"source_kind inválido: {source_kind}")


def choose_columns(existing: List[str]) -> List[str]:
    wanted = [
        "pattern_hash",
        "snippet",
        "explanation",
        "severity",
        "tags",
        "hit_count",
        "first_seen_at",
        "last_seen_at",
        "last_seen",
        "created_at",
        "upstream_calls",
        "cost_brl",
    ]
    return [col for col in wanted if col in existing]


def insert_pattern(
    conn,
    table_columns: List[str],
    pattern_hash: str,
    snippet: str,
    explanation: str,
    severity: str,
    tags: List[str],
    seen_at: Optional[dt.datetime],
) -> bool:
    values: Dict[str, Any] = {
        "pattern_hash": pattern_hash,
        "snippet": snippet,
        "explanation": explanation,
        "severity": severity,
        "tags": tags,
        "hit_count": 1,
        "first_seen_at": seen_at,
        "last_seen_at": seen_at,
        "last_seen": seen_at,
        "created_at": seen_at,
        "upstream_calls": 0,
        "cost_brl": 0,
    }
    cols = choose_columns(table_columns)
    insert_cols = [col for col in cols if col in values]
    placeholders = [sql.Placeholder() for _ in insert_cols]
    statement = sql.SQL("INSERT INTO tcp_patterns ({cols}) VALUES ({vals}) ON CONFLICT (pattern_hash) DO NOTHING").format(
        cols=sql.SQL(", ").join(sql.Identifier(col) for col in insert_cols),
        vals=sql.SQL(", ").join(placeholders),
    )
    params = [values[col] for col in insert_cols]
    with conn.cursor() as cur:
        cur.execute(statement, params)
        return cur.rowcount == 1


def read_existing_hashes(conn, pattern_hash: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM tcp_patterns WHERE pattern_hash = %s", (pattern_hash,))
        return cur.fetchone() is not None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill seguro e deduplicado de padrões TCP a partir de logs históricos.")
    parser.add_argument("--source", choices=["events", "alerts"], default="events")
    parser.add_argument("--source-file", default=None)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--start-line", type=int, default=1)
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-ai", action="store_true", help="Não chama IA para entradas sem explicação útil.")
    parser.add_argument("--dedup-strict", action="store_true", default=True)
    parser.add_argument("--allow-local", action="store_true", help="Inclui eventos source=local.")
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--dsn", default=None)
    parser.add_argument("--db-host", default=None)
    parser.add_argument("--db-port", default=None)
    parser.add_argument("--db-name", default=None)
    parser.add_argument("--db-user", default=None)
    parser.add_argument("--db-password", default=None)
    parser.add_argument("--commit-every", type=int, default=50)
    return parser


def load_checkpoint(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_checkpoint(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = build_parser().parse_args()
    load_env_file(DEFAULT_BRAIN_ENV)
    source_file = Path(args.source_file or (DEFAULT_EVENTS_FILE if args.source == "events" else DEFAULT_ALERTS_FILE))
    if not source_file.exists():
        print(f"[erro] arquivo de origem não encontrado: {source_file}", file=sys.stderr)
        return 2

    log_handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        log_path = Path(args.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=log_handlers)
    log = logging.getLogger("tcp-backfill")

    checkpoint_path = Path(args.checkpoint) if args.checkpoint else None
    checkpoint = load_checkpoint(checkpoint_path) if checkpoint_path else {}
    start_line = max(args.start_line, int(checkpoint.get("next_line", args.start_line)))

    conn = make_db_conn(args)
    conn.autocommit = False
    table_columns = get_table_columns(conn, "tcp_patterns")

    metrics = {
        "source": str(source_file),
        "source_kind": args.source,
        "start_line": start_line,
        "dry_run": bool(args.dry_run),
        "no_ai": bool(args.no_ai),
        "dedup_strict": bool(args.dedup_strict),
        "events_seen": 0,
        "lines_read": 0,
        "blocks_parsed": 0,
        "eligible_events": 0,
        "processed_candidates": 0,
        "known_patterns": 0,
        "new_patterns": 0,
        "ai_calls": 0,
        "skipped_non_eligible": 0,
        "parse_errors": 0,
        "write_errors": 0,
        "commits": 0,
    }

    next_line = start_line
    pending_since_commit = 0
    t0 = dt.datetime.now(dt.timezone.utc)

    try:
        for line_no, event in parse_source(source_file, args.source, start_line):
            next_line = line_no + 1
            metrics["events_seen"] += 1
            metrics["blocks_parsed"] += 1
            metrics["lines_read"] = max(metrics["lines_read"], line_no)

            source = str(event.get("source", "unknown")).strip().lower()
            if source == "local" and not args.allow_local:
                metrics["skipped_non_eligible"] += 1
                continue

            snippet = str(event.get("snippet", "")).strip()
            if not snippet:
                metrics["skipped_non_eligible"] += 1
                continue

            explanation_raw = str(event.get("explanation", "")).strip()
            explanation, parsed_severity, parsed_tags = extract_structured_explanation(explanation_raw)
            severity = str(event.get("severity") or parsed_severity or "unknown").strip() or "unknown"
            tags = event.get("tags") or parsed_tags or []
            if not isinstance(tags, list):
                tags = []
            tags = [str(tag) for tag in tags if str(tag).strip()]

            # Remove entrada sem valor semântico se não houver IA permitida.
            if not explanation or explanation == "Sem upstream no momento.":
                metrics["skipped_non_eligible"] += 1
                continue

            metrics["eligible_events"] += 1

            canon = canonicalize_snippet(snippet)
            pattern_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()

            if args.dedup_strict and read_existing_hashes(conn, pattern_hash):
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
                inserted = insert_pattern(
                    conn=conn,
                    table_columns=table_columns,
                    pattern_hash=pattern_hash,
                    snippet=canon,
                    explanation=explanation,
                    severity=severity,
                    tags=tags,
                    seen_at=parse_iso_timestamp(str(event.get("timestamp"))) or dt.datetime.now(dt.timezone.utc),
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
        log.exception("Falha geral no backfill: %s", exc)
        return 1
    finally:
        conn.close()

    elapsed = (dt.datetime.now(dt.timezone.utc) - t0).total_seconds()
    metrics["elapsed_seconds"] = round(elapsed, 3)
    metrics["next_line"] = next_line

    if checkpoint_path:
        save_checkpoint(
            checkpoint_path,
            {
                "source": str(source_file),
                "source_kind": args.source,
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
