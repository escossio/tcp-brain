#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


DEFAULT_SOURCE_FILE = Path("/srv/tcp/knowledge/events/tcp_brain_history.jsonl")
DEFAULT_RETENTION_DIR = Path("/srv/tcp/knowledge/retention")
CSV_FIELDS = [
    "ts",
    "source",
    "endpoint",
    "method",
    "response_mode",
    "cache_hit",
    "used_ai",
    "created_new_pattern",
    "severity",
    "pattern_hash",
    "existing_pattern_id",
    "http_status",
    "raw_input_length",
    "raw_input_present",
]


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"valor booleano inválido: {value!r}")


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"timestamp inválido: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def open_text_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def discover_sources(source_file: Path, include_rotated: bool) -> List[Path]:
    files = [source_file]
    if not include_rotated:
        return files
    if source_file.name == "tcp_brain_history.jsonl":
        rotated_dir = DEFAULT_RETENTION_DIR
    elif source_file.suffix == ".gz" and source_file.parent.name == "retention":
        rotated_dir = source_file.parent
    else:
        rotated_dir = source_file.parent / "retention"
    if rotated_dir.exists():
        for candidate in sorted(rotated_dir.glob("tcp_brain_history-*.jsonl.gz")):
            if candidate not in files:
                files.append(candidate)
    return files


def iter_events_from_file(path: Path) -> Iterator[Dict[str, Any]]:
    with open_text_file(path) as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def iter_events(paths: Sequence[Path]) -> Iterator[Dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
        yield from iter_events_from_file(path)


def in_window(event: Dict[str, Any], since: Optional[datetime], until: Optional[datetime]) -> bool:
    if since is None and until is None:
        return True
    ts = event.get("ts")
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if since and dt < since:
        return False
    if until and dt > until:
        return False
    return True


def matches_filters(
    event: Dict[str, Any],
    *,
    source: Optional[str],
    response_mode: Optional[str],
    severity: Optional[str],
    used_ai: Optional[bool],
    created_new_pattern: Optional[bool],
    cache_hit: Optional[bool],
    since: Optional[datetime],
    until: Optional[datetime],
) -> bool:
    if source is not None and event.get("source") != source:
        return False
    if response_mode is not None and event.get("response_mode") != response_mode:
        return False
    if severity is not None and event.get("severity") != severity:
        return False
    if used_ai is not None and bool(event.get("used_ai")) != used_ai:
        return False
    if created_new_pattern is not None and bool(event.get("created_new_pattern")) != created_new_pattern:
        return False
    if cache_hit is not None and bool(event.get("cache_hit")) != cache_hit:
        return False
    return in_window(event, since, until)


def summarize_events(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    response_modes = Counter()
    severities = Counter()
    endpoints = Counter()
    pattern_hashes = Counter()
    canonical_snippets = Counter()
    total = 0
    ai_calls = 0
    cache_hits = 0
    new_patterns = 0
    first_ts = None
    last_ts = None
    for event in events:
        total += 1
        response_modes[event.get("response_mode") or "unknown"] += 1
        severities[event.get("severity") or "unknown"] += 1
        endpoints[event.get("endpoint") or "unknown"] += 1
        if event.get("pattern_hash"):
            pattern_hashes[event["pattern_hash"]] += 1
        if event.get("canonical_snippet"):
            canonical_snippets[event["canonical_snippet"]] += 1
        if event.get("used_ai"):
            ai_calls += 1
        if event.get("cache_hit"):
            cache_hits += 1
        if event.get("created_new_pattern"):
            new_patterns += 1
        ts = event.get("ts")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if first_ts is None or dt < first_ts:
                    first_ts = dt
                if last_ts is None or dt > last_ts:
                    last_ts = dt
            except ValueError:
                pass
    return {
        "total_events": total,
        "cache_hits": cache_hits,
        "used_ai": ai_calls,
        "created_new_pattern": new_patterns,
        "response_modes": dict(response_modes),
        "severity_counts": dict(severities),
        "endpoint_counts": dict(endpoints),
        "top_pattern_hashes": pattern_hashes.most_common(20),
        "top_canonical_snippets": canonical_snippets.most_common(20),
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "cache_hit_rate": (cache_hits / total) if total else 0.0,
        "ai_rate": (ai_calls / total) if total else 0.0,
        "new_pattern_rate": (new_patterns / total) if total else 0.0,
    }


def export_events(events: Sequence[Dict[str, Any]], fmt: str, output: Optional[Path], summary_only: bool) -> None:
    summary = summarize_events(events)
    if summary_only:
        text = json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True)
        if output:
            output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return

    if fmt == "jsonl":
        handle = output.open("w", encoding="utf-8") if output else sys.stdout
        try:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        finally:
            if output:
                handle.close()
        return

    if fmt == "csv":
        handle = output.open("w", newline="", encoding="utf-8") if output else sys.stdout
        try:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for event in events:
                writer.writerow({field: event.get(field, "") for field in CSV_FIELDS})
        finally:
            if output:
                handle.close()
        return

    payload = {"summary": summary, "events": list(events)}
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    if output:
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Exporta subconjuntos do histórico estruturado do tcp-brain.")
    parser.add_argument("--source-file", type=Path, default=DEFAULT_SOURCE_FILE)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument("--since", type=parse_dt)
    parser.add_argument("--until", type=parse_dt)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--filter-used-ai", type=parse_bool)
    parser.add_argument("--filter-created-new-pattern", type=parse_bool)
    parser.add_argument("--filter-cache-hit", type=parse_bool)
    parser.add_argument("--filter-response-mode")
    parser.add_argument("--filter-severity")
    parser.add_argument("--filter-source")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=["jsonl", "json", "csv"], default="json")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    paths = discover_sources(args.source_file, args.include_rotated)
    filtered: List[Dict[str, Any]] = []
    for event in iter_events(paths):
        if not matches_filters(
            event,
            source=args.filter_source,
            response_mode=args.filter_response_mode,
            severity=args.filter_severity,
            used_ai=args.filter_used_ai,
            created_new_pattern=args.filter_created_new_pattern,
            cache_hit=args.filter_cache_hit,
            since=args.since,
            until=args.until,
        ):
            continue
        filtered.append(event)
        if args.limit and len(filtered) >= args.limit:
            break

    export_events(filtered, args.format, args.output, args.summary_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
