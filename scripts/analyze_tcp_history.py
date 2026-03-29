#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence


DEFAULT_SOURCE_FILE = Path("/srv/tcp/knowledge/events/tcp_brain_history.jsonl")
DEFAULT_RETENTION_DIR = Path("/srv/tcp/knowledge/retention")


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


def iter_events(paths: Sequence[Path]) -> Iterator[Dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
        with open_text_file(path) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue


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


def collect(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    response_modes = Counter()
    severities = Counter()
    patterns = Counter()
    snippets = Counter()
    endpoints = Counter()
    hourly = Counter()
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
            patterns[event["pattern_hash"]] += 1
        if event.get("canonical_snippet"):
            snippets[event["canonical_snippet"]] += 1
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
                hour = dt.strftime("%Y-%m-%d %H:00")
                hourly[hour] += 1
                if first_ts is None or dt < first_ts:
                    first_ts = dt
                if last_ts is None or dt > last_ts:
                    last_ts = dt
            except ValueError:
                pass

    rare_events = [item for item in patterns.items() if item[1] <= 2]
    rare_events.sort(key=lambda item: (item[1], item[0]))

    return {
        "total_events": total,
        "cache_hits": cache_hits,
        "used_ai": ai_calls,
        "created_new_pattern": new_patterns,
        "response_modes": dict(response_modes),
        "severity_counts": dict(severities),
        "endpoint_counts": dict(endpoints),
        "top_pattern_hashes": patterns.most_common(20),
        "top_canonical_snippets": snippets.most_common(20),
        "rare_pattern_hashes": rare_events[:20],
        "hourly_counts": dict(sorted(hourly.items())),
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "cache_hit_rate": (cache_hits / total) if total else 0.0,
        "ai_rate": (ai_calls / total) if total else 0.0,
        "new_pattern_rate": (new_patterns / total) if total else 0.0,
    }


def render_markdown(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("# tcp_history_analysis")
    lines.append("")
    lines.append("## Resumo")
    lines.append(f"- total_events: {summary['total_events']}")
    lines.append(f"- cache_hits: {summary['cache_hits']}")
    lines.append(f"- used_ai: {summary['used_ai']}")
    lines.append(f"- created_new_pattern: {summary['created_new_pattern']}")
    lines.append(f"- cache_hit_rate: {summary['cache_hit_rate']:.4f}")
    lines.append(f"- ai_rate: {summary['ai_rate']:.4f}")
    lines.append(f"- new_pattern_rate: {summary['new_pattern_rate']:.4f}")
    lines.append("")
    lines.append("## Response modes")
    for key, value in sorted(summary["response_modes"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Severidades")
    for key, value in sorted(summary["severity_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Top pattern_hash")
    for key, value in summary["top_pattern_hashes"]:
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Top canonical_snippet")
    for key, value in summary["top_canonical_snippets"]:
        short = key[:140].replace("\n", " ")
        lines.append(f"- {value} | {short}")
    lines.append("")
    lines.append("## Eventos raros")
    for key, value in summary["rare_pattern_hashes"]:
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Janela temporal")
    lines.append(f"- first_ts: {summary['first_ts']}")
    lines.append(f"- last_ts: {summary['last_ts']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analisa o histórico estruturado do tcp-brain.")
    parser.add_argument("--source-file", type=Path, default=DEFAULT_SOURCE_FILE)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument("--since", type=parse_dt)
    parser.add_argument("--until", type=parse_dt)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    args = parser.parse_args()

    paths = discover_sources(args.source_file, args.include_rotated)
    events: List[Dict[str, Any]] = []
    for event in iter_events(paths):
        if not in_window(event, args.since, args.until):
            continue
        events.append(event)
        if args.limit and len(events) >= args.limit:
            break

    summary = collect(events)

    if args.format == "json":
        payload = json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload)
        return 0

    if args.format == "csv":
        import csv

        rows = [
            ("metric", "value"),
            ("total_events", summary["total_events"]),
            ("cache_hits", summary["cache_hits"]),
            ("used_ai", summary["used_ai"]),
            ("created_new_pattern", summary["created_new_pattern"]),
            ("cache_hit_rate", summary["cache_hit_rate"]),
            ("ai_rate", summary["ai_rate"]),
            ("new_pattern_rate", summary["new_pattern_rate"]),
        ]
        handle = args.output.open("w", newline="", encoding="utf-8") if args.output else sys.stdout
        try:
            writer = csv.writer(handle)
            for row in rows:
                writer.writerow(row)
        finally:
            if args.output:
                handle.close()
        return 0

    text = render_markdown(summary)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
