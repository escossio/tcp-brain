#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


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


def family_signature(canonical_snippet: str) -> str:
    """Agrupa variantes da mesma forma operacional usando uma assinatura legível.

    A ideia é simples: manter o esqueleto do pacote, mas reduzir a variação de números
    e campos voláteis como checksum, seq/ack, timestamp e length.
    """
    s = canonical_snippet
    s = re.sub(r"cksum 0x[0-9a-f]+ \(incorrect -> 0x[0-9a-f]+\)", "cksum <cksum>", s)
    s = re.sub(r"seq [^, ]+(?::[^, ]+)?", "seq <seq>", s)
    s = re.sub(r"ack [^, ]+", "ack <ack>", s)
    s = re.sub(r"win \d+", "win <win>", s)
    s = re.sub(r"TS val \d+ ecr \d+", "TS val <ts> ecr <ts>", s)
    s = re.sub(r"length \d+", "length <len>", s)
    return s.strip()


def severity_rank(severity: str) -> int:
    order = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
    return order.get((severity or "unknown").lower(), 0)


@dataclass
class GapItem:
    gap_type: str
    priority: str
    score: float
    key: str
    kind: str
    total: int
    ai_count: int
    cache_count: int
    upstream_count: int
    new_count: int
    severity_max: str
    family_size: int
    notes: str
    sample_snippet: str
    sample_pattern_hash: str
    sample_endpoint: str


def priority_for_score(score: float) -> str:
    if score >= 80:
        return "alta"
    if score >= 40:
        return "média"
    return "baixa"


def score_ai_recurrent(total: int, ai_count: int, upstream_count: int, family_size: int) -> float:
    if total == 0:
        return 0.0
    ai_rate = ai_count / total
    return (ai_rate * 50.0) + min(total, 50) * 0.8 + min(upstream_count, 50) * 0.4 + min(family_size, 50) * 0.2


def score_new_pattern_hot(total: int, new_count: int, ai_count: int, family_size: int) -> float:
    if total == 0:
        return 0.0
    new_rate = new_count / total
    return (new_rate * 50.0) + min(total, 50) * 0.7 + min(ai_count, 50) * 0.3 + min(family_size, 50) * 0.2


def score_rare_event(total: int, severity_max: str) -> float:
    base = 100.0 / max(total, 1)
    return base + severity_rank(severity_max) * 2.0


def score_cache_gap(total: int, upstream_count: int, cache_count: int, ai_count: int, family_size: int) -> float:
    if total == 0:
        return 0.0
    imbalance = max(upstream_count - cache_count, 0) / total
    return (imbalance * 60.0) + min(upstream_count, 50) * 0.4 + min(ai_count, 50) * 0.2 + min(family_size, 50) * 0.2


def score_severity_attention(total: int, severity_max: str, ai_count: int, upstream_count: int) -> float:
    if total == 0:
        return 0.0
    return severity_rank(severity_max) * 18.0 + min(total, 50) * 0.4 + min(ai_count, 50) * 0.2 + min(upstream_count, 50) * 0.2


def summarize_events(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    response_modes = Counter()
    severities = Counter()
    endpoints = Counter()
    patterns = Counter()
    families = Counter()
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
        fam = family_signature(str(event.get("canonical_snippet") or ""))
        families[fam] += 1
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

    family_data = build_family_data(events)
    summary = {
        "total_events": total,
        "cache_hits": cache_hits,
        "used_ai": ai_calls,
        "created_new_pattern": new_patterns,
        "response_modes": dict(response_modes),
        "severity_counts": dict(severities),
        "endpoint_counts": dict(endpoints),
        "top_pattern_hashes": patterns.most_common(20),
        "top_families": sorted(
            (
                {
                    "family_signature": sig,
                    "total": data["total"],
                    "ai_count": data["ai_count"],
                    "cache_count": data["cache_count"],
                    "upstream_count": data["upstream_count"],
                    "new_count": data["new_count"],
                    "severity_max": max(
                        data["severity_counts"].items(),
                        key=lambda kv: (kv[1], severity_rank(kv[0])),
                    )[0] if data["severity_counts"] else "unknown",
                    "distinct_patterns": len(data["patterns"]),
                    "distinct_canonical": len(data["canonical_snippets"]),
                }
                for sig, data in family_data.items()
            ),
            key=lambda item: (-item["total"], -item["ai_count"], -item["new_count"], item["family_signature"]),
        )[:30],
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "cache_hit_rate": (cache_hits / total) if total else 0.0,
        "ai_rate": (ai_calls / total) if total else 0.0,
        "new_pattern_rate": (new_patterns / total) if total else 0.0,
        "unique_pattern_hashes": len(patterns),
        "unique_families": len(family_data),
    }
    return summary


def build_family_data(events: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    families: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total": 0,
        "ai_count": 0,
        "cache_count": 0,
        "upstream_count": 0,
        "new_count": 0,
        "severity_counts": Counter(),
        "severity_max": "unknown",
        "patterns": Counter(),
        "canonical_snippets": Counter(),
        "endpoints": Counter(),
        "sample": None,
        "ts_first": None,
        "ts_last": None,
    })
    for event in events:
        sig = family_signature(str(event.get("canonical_snippet") or ""))
        data = families[sig]
        data["total"] += 1
        data["ai_count"] += int(bool(event.get("used_ai")))
        data["cache_count"] += int(bool(event.get("cache_hit")))
        data["upstream_count"] += int((event.get("response_mode") or "") == "upstream")
        data["new_count"] += int(bool(event.get("created_new_pattern")))
        sev = str(event.get("severity") or "unknown")
        data["severity_counts"][sev] += 1
        if severity_rank(sev) > severity_rank(data["severity_max"]):
            data["severity_max"] = sev
        if event.get("pattern_hash"):
            data["patterns"][event["pattern_hash"]] += 1
        canon = str(event.get("canonical_snippet") or "")
        if canon:
            data["canonical_snippets"][canon] += 1
        ep = str(event.get("endpoint") or "unknown")
        data["endpoints"][ep] += 1
        if data["sample"] is None:
            data["sample"] = event
        ts = event.get("ts")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if data["ts_first"] is None or dt < data["ts_first"]:
                    data["ts_first"] = dt
                if data["ts_last"] is None or dt > data["ts_last"]:
                    data["ts_last"] = dt
            except ValueError:
                pass
    return families


def build_pattern_data(events: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    patterns: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total": 0,
        "ai_count": 0,
        "cache_count": 0,
        "upstream_count": 0,
        "new_count": 0,
        "severity_counts": Counter(),
        "canonical_snippets": Counter(),
        "endpoints": Counter(),
        "sample": None,
        "ts_first": None,
        "ts_last": None,
    })
    for event in events:
        key = str(event.get("pattern_hash") or "")
        if not key:
            continue
        data = patterns[key]
        data["total"] += 1
        data["ai_count"] += int(bool(event.get("used_ai")))
        data["cache_count"] += int(bool(event.get("cache_hit")))
        data["upstream_count"] += int((event.get("response_mode") or "") == "upstream")
        data["new_count"] += int(bool(event.get("created_new_pattern")))
        sev = str(event.get("severity") or "unknown")
        data["severity_counts"][sev] += 1
        canon = str(event.get("canonical_snippet") or "")
        if canon:
            data["canonical_snippets"][canon] += 1
        ep = str(event.get("endpoint") or "unknown")
        data["endpoints"][ep] += 1
        if data["sample"] is None:
            data["sample"] = event
        ts = event.get("ts")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if data["ts_first"] is None or dt < data["ts_first"]:
                    data["ts_first"] = dt
                if data["ts_last"] is None or dt > data["ts_last"]:
                    data["ts_last"] = dt
            except ValueError:
                pass
    return patterns


def json_ready_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(summary)
    payload["top_families"] = list(summary["top_families"])
    return payload


def analyze_gap_patterns(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    pattern_data = build_pattern_data(events)
    family_data = build_family_data(events)

    ai_candidates: List[GapItem] = []
    new_pattern_candidates: List[GapItem] = []
    rare_candidates: List[GapItem] = []
    cache_gap_candidates: List[GapItem] = []
    severity_candidates: List[GapItem] = []

    # Pattern-level signals
    for pattern_hash, data in pattern_data.items():
        total = data["total"]
        ai_count = data["ai_count"]
        cache_count = data["cache_count"]
        upstream_count = data["upstream_count"]
        new_count = data["new_count"]
        sev_counts = data["severity_counts"]
        severity_max = max(sev_counts.items(), key=lambda kv: (kv[1], severity_rank(kv[0])))[0] if sev_counts else "unknown"
        sample = data["sample"] or {}
        sample_snippet = str(sample.get("canonical_snippet") or pattern_hash)
        sample_endpoint = str(sample.get("endpoint") or "unknown")
        sample_pattern_hash = pattern_hash

        if total >= 2 and ai_count >= 1:
            score = score_ai_recurrent(total, ai_count, upstream_count, len(data["canonical_snippets"]))
            ai_candidates.append(GapItem(
                gap_type="ai_recurrent",
                priority=priority_for_score(score),
                score=score,
                key=pattern_hash,
                kind="pattern_hash",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["canonical_snippets"]),
                notes="pattern_hash já voltou após criação e ainda depende de IA",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 2 and new_count >= 1:
            score = score_new_pattern_hot(total, new_count, ai_count, len(data["canonical_snippets"]))
            new_pattern_candidates.append(GapItem(
                gap_type="new_pattern_hot",
                priority=priority_for_score(score),
                score=score,
                key=pattern_hash,
                kind="pattern_hash",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["canonical_snippets"]),
                notes="padrão novo com recorrência após a primeira criação",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total <= 2:
            score = score_rare_event(total, severity_max)
            rare_candidates.append(GapItem(
                gap_type="rare_event",
                priority=priority_for_score(score),
                score=score,
                key=pattern_hash,
                kind="pattern_hash",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["canonical_snippets"]),
                notes="assinatura rara ou de baixa repetição",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 5 and upstream_count > cache_count:
            score = score_cache_gap(total, upstream_count, cache_count, ai_count, len(data["canonical_snippets"]))
            cache_gap_candidates.append(GapItem(
                gap_type="cache_gap",
                priority=priority_for_score(score),
                score=score,
                key=pattern_hash,
                kind="pattern_hash",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["canonical_snippets"]),
                notes="assinatura aparece mais em upstream do que em cache",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 3 and severity_max in {"medium", "high"}:
            score = score_severity_attention(total, severity_max, ai_count, upstream_count)
            severity_candidates.append(GapItem(
                gap_type="severity_attention",
                priority=priority_for_score(score),
                score=score,
                key=pattern_hash,
                kind="pattern_hash",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["canonical_snippets"]),
                notes="padrão com severidade relevante e recorrência suficiente para revisão",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

    # Family-level signals to expose bigger operational gaps.
    for family_sig, data in family_data.items():
        total = data["total"]
        ai_count = data["ai_count"]
        cache_count = data["cache_count"]
        upstream_count = data["upstream_count"]
        new_count = data["new_count"]
        severity_max = max(data["severity_counts"].items(), key=lambda kv: (kv[1], severity_rank(kv[0])))[0] if data["severity_counts"] else "unknown"
        sample = data["sample"] or {}
        sample_snippet = str(sample.get("canonical_snippet") or family_sig)
        sample_pattern_hash = str(sample.get("pattern_hash") or "")
        sample_endpoint = str(sample.get("endpoint") or "unknown")

        if total >= 8 and ai_count / total >= 0.25:
            score = score_ai_recurrent(total, ai_count, upstream_count, len(data["patterns"]))
            ai_candidates.append(GapItem(
                gap_type="ai_recurrent",
                priority=priority_for_score(score),
                score=score,
                key=family_sig,
                kind="family",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["patterns"]),
                notes="família operacional com recorrência de IA acima do limiar",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 8 and new_count / total >= 0.25:
            score = score_new_pattern_hot(total, new_count, ai_count, len(data["patterns"]))
            new_pattern_candidates.append(GapItem(
                gap_type="new_pattern_hot",
                priority=priority_for_score(score),
                score=score,
                key=family_sig,
                kind="family",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["patterns"]),
                notes="família com padrões novos recorrentes",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total <= 2:
            score = score_rare_event(total, severity_max)
            rare_candidates.append(GapItem(
                gap_type="rare_event",
                priority=priority_for_score(score),
                score=score,
                key=family_sig,
                kind="family",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["patterns"]),
                notes="família muito rara ou de borda",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 8 and upstream_count > cache_count:
            score = score_cache_gap(total, upstream_count, cache_count, ai_count, len(data["patterns"]))
            cache_gap_candidates.append(GapItem(
                gap_type="cache_gap",
                priority=priority_for_score(score),
                score=score,
                key=family_sig,
                kind="family",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["patterns"]),
                notes="família ainda mais dependente de upstream do que de cache",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

        if total >= 8 and severity_max in {"medium", "high"}:
            score = score_severity_attention(total, severity_max, ai_count, upstream_count)
            severity_candidates.append(GapItem(
                gap_type="severity_attention",
                priority=priority_for_score(score),
                score=score,
                key=family_sig,
                kind="family",
                total=total,
                ai_count=ai_count,
                cache_count=cache_count,
                upstream_count=upstream_count,
                new_count=new_count,
                severity_max=severity_max,
                family_size=len(data["patterns"]),
                notes="família com severidade relevante e volume suficiente para tratamento",
                sample_snippet=sample_snippet,
                sample_pattern_hash=sample_pattern_hash,
                sample_endpoint=sample_endpoint,
            ))

    ranked = sorted(
        ai_candidates + new_pattern_candidates + rare_candidates + cache_gap_candidates + severity_candidates,
        key=lambda item: (-item.score, item.gap_type, item.kind, item.key),
    )
    return {
        "ai_dependency_gaps": sorted(ai_candidates, key=lambda item: (-item.score, item.kind, item.key)),
        "new_pattern_gaps": sorted(new_pattern_candidates, key=lambda item: (-item.score, item.kind, item.key)),
        "rare_event_gaps": sorted(rare_candidates, key=lambda item: (-item.score, item.kind, item.key)),
        "cache_gap_candidates": sorted(cache_gap_candidates, key=lambda item: (-item.score, item.kind, item.key)),
        "severity_attention_gaps": sorted(severity_candidates, key=lambda item: (-item.score, item.kind, item.key)),
        "ranked": ranked,
    }


def top_by_priority(items: Sequence[GapItem], limit: int) -> List[GapItem]:
    return list(items[:limit])


def gap_items_to_dicts(items: Sequence[GapItem]) -> List[Dict[str, Any]]:
    return [asdict(item) for item in items]


def write_markdown_summary(summary: Dict[str, Any], gaps: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# gap_summary")
    lines.append("")
    lines.append("## Resumo")
    lines.append(f"- total_events: {summary['total_events']}")
    lines.append(f"- cache_hits: {summary['cache_hits']}")
    lines.append(f"- used_ai: {summary['used_ai']}")
    lines.append(f"- created_new_pattern: {summary['created_new_pattern']}")
    lines.append(f"- unique_pattern_hashes: {summary['unique_pattern_hashes']}")
    lines.append(f"- unique_families: {summary['unique_families']}")
    lines.append(f"- cache_hit_rate: {summary['cache_hit_rate']:.4f}")
    lines.append(f"- ai_rate: {summary['ai_rate']:.4f}")
    lines.append(f"- new_pattern_rate: {summary['new_pattern_rate']:.4f}")
    lines.append("")
    lines.append("## Prioridade alta")
    for item in gaps["ranked"][:12]:
        if item.priority != "alta":
            continue
        lines.append(
            f"- {item.gap_type} | {item.kind} | score={item.score:.1f} | total={item.total} | ai={item.ai_count} | cache={item.cache_count} | new={item.new_count}"
        )
        lines.append(f"  - sample: {item.sample_snippet[:160]}")
    if not any(item.priority == "alta" for item in gaps["ranked"]):
        lines.append("- nenhum gap na faixa alta acima do limiar")
    lines.append("")
    lines.append("## Prioridade média")
    for item in gaps["ranked"][:20]:
        if item.priority != "média":
            continue
        lines.append(
            f"- {item.gap_type} | {item.kind} | score={item.score:.1f} | total={item.total} | ai={item.ai_count} | cache={item.cache_count} | new={item.new_count}"
        )
        lines.append(f"  - sample: {item.sample_snippet[:160]}")
    lines.append("")
    lines.append("## Prioridade baixa")
    low_count = sum(1 for item in gaps["ranked"] if item.priority == "baixa")
    lines.append(f"- itens classificados como baixa prioridade: {low_count}")
    return "\n".join(lines) + "\n"


def write_gap_section(title: str, items: Sequence[GapItem], field_name: str) -> str:
    lines = [f"# {title}", ""]
    for item in items:
        lines.append(
            f"- {item.gap_type} | {item.kind} | score={item.score:.1f} | priority={item.priority} | total={item.total} | ai={item.ai_count} | cache={item.cache_count} | upstream={item.upstream_count} | new={item.new_count} | severity={item.severity_max}"
        )
        lines.append(f"  - sample: {item.sample_snippet[:180]}")
        lines.append(f"  - key: {item.key}")
    if not items:
        lines.append("- nenhum item encontrado")
    return "\n".join(lines) + "\n"


def write_priority_report(gaps: Dict[str, Any]) -> str:
    lines = ["# tcp_gap_prioritization", ""]
    buckets = {
        "alta": [],
        "média": [],
        "baixa": [],
    }
    for item in gaps["ranked"]:
        buckets[item.priority].append(item)
    for priority in ["alta", "média", "baixa"]:
        lines.append(f"## Prioridade {priority}")
        if not buckets[priority]:
            lines.append("- vazio")
        for item in buckets[priority][:20]:
            lines.append(
                f"- {item.gap_type} | {item.kind} | score={item.score:.1f} | total={item.total} | ai={item.ai_count} | cache={item.cache_count} | new={item.new_count} | severity={item.severity_max}"
            )
            lines.append(f"  - sample: {item.sample_snippet[:160]}")
        lines.append("")
    return "\n".join(lines)


def write_actions_report(gaps: Dict[str, Any]) -> str:
    lines = ["# tcp_gap_actions", ""]
    lines.append("## Ações por categoria")
    lines.append("- ai_recurrent: criar normalização local, revisar canonização e validar se o padrão pode virar regra de cache.")
    lines.append("- new_pattern_hot: considerar backfill incremental e/ou regra local quando a família repetir com frequência.")
    lines.append("- rare_event: manter monitoramento, usar para triagem, e só enriquecer se vier com severidade relevante.")
    lines.append("- cache_gap: priorizar melhoria de cache ou consolidação de padrões recorrentes que ainda caem no upstream.")
    lines.append("- severity_attention: revisão manual, porque a recorrência vem junto com severidade relevante.")
    lines.append("")
    lines.append("## Próxima iteração sugerida")
    lines.append("- atacar primeiro as famílias com `cache_gap` alto e `ai_recurrent` alto.")
    lines.append("- depois, tratar `new_pattern_hot` para reduzir futuro custo de IA.")
    lines.append("- por último, revisar `rare_event` apenas se houver severidade média/alta.")
    return "\n".join(lines) + "\n"


def write_outputs(output_dir: Path, summary: Dict[str, Any], gaps: Dict[str, Any], fmt: str, summary_only: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_payload = {
        "summary": summary,
        "gap_ranked": gap_items_to_dicts(gaps["ranked"]),
        "ai_dependency_gaps": gap_items_to_dicts(gaps["ai_dependency_gaps"]),
        "new_pattern_gaps": gap_items_to_dicts(gaps["new_pattern_gaps"]),
        "rare_event_gaps": gap_items_to_dicts(gaps["rare_event_gaps"]),
        "cache_gap_candidates": gap_items_to_dicts(gaps["cache_gap_candidates"]),
        "severity_attention_gaps": gap_items_to_dicts(gaps["severity_attention_gaps"]),
    }

    (output_dir / "gap_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "gap_ranked.json").write_text(json.dumps(gap_items_to_dicts(gaps["ranked"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "ai_gap_candidates.json").write_text(json.dumps(gap_items_to_dicts(gaps["ai_dependency_gaps"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "new_pattern_gaps.json").write_text(json.dumps(gap_items_to_dicts(gaps["new_pattern_gaps"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "rare_events.json").write_text(json.dumps(gap_items_to_dicts(gaps["rare_event_gaps"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "cache_gap_candidates.json").write_text(json.dumps(gap_items_to_dicts(gaps["cache_gap_candidates"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "severity_attention_gaps.json").write_text(json.dumps(gap_items_to_dicts(gaps["severity_attention_gaps"]), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    if fmt == "json":
        if summary_only:
            sys.stdout.write(json.dumps(json_payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
        else:
            sys.stdout.write(json.dumps(json_payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
        return

    if fmt == "csv":
        with (output_dir / "gap_ranked.csv").open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(asdict(gaps["ranked"][0]).keys()) if gaps["ranked"] else ["gap_type"])
            writer.writeheader()
            for item in gaps["ranked"]:
                writer.writerow(asdict(item))
        return

    # markdown outputs
    (output_dir / "gap_summary.md").write_text(write_markdown_summary(summary, gaps), encoding="utf-8")
    (output_dir / "ai_dependency_gaps.md").write_text(write_gap_section("ai_dependency_gaps", gaps["ai_dependency_gaps"], "ai_dependency"), encoding="utf-8")
    (output_dir / "new_pattern_gaps.md").write_text(write_gap_section("new_pattern_gaps", gaps["new_pattern_gaps"], "new_pattern"), encoding="utf-8")
    (output_dir / "rare_event_gaps.md").write_text(write_gap_section("rare_event_gaps", gaps["rare_event_gaps"], "rare"), encoding="utf-8")
    (output_dir / "cache_gap_analysis.md").write_text(write_gap_section("cache_gap_analysis", gaps["cache_gap_candidates"], "cache"), encoding="utf-8")
    (output_dir / "tcp_gap_prioritization.md").write_text(write_priority_report(gaps), encoding="utf-8")
    (output_dir / "tcp_gap_actions.md").write_text(write_actions_report(gaps), encoding="utf-8")

    # Lightweight CSV feed for dashboard/automation.
    with (output_dir / "gap_ranked.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(gaps["ranked"][0]).keys()) if gaps["ranked"] else ["gap_type"])
        writer.writeheader()
        for item in gaps["ranked"]:
            writer.writerow(asdict(item))


def main() -> int:
    parser = argparse.ArgumentParser(description="Gap engine do tcp-brain.")
    parser.add_argument("--source-file", type=Path, default=DEFAULT_SOURCE_FILE)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument("--since", type=parse_dt)
    parser.add_argument("--until", type=parse_dt)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--min-frequency", type=int, default=2)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--format", choices=["json", "md", "csv"], default="md")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    paths = discover_sources(args.source_file, args.include_rotated)
    events: List[Dict[str, Any]] = []
    for event in iter_events(paths):
        if not in_window(event, args.since, args.until):
            continue
        events.append(event)
        if args.limit and len(events) >= args.limit:
            break

    summary = summarize_events(events)
    gaps = analyze_gap_patterns(events)

    # Filter by min frequency and top N for the primary outputs.
    gaps["ai_dependency_gaps"] = [g for g in gaps["ai_dependency_gaps"] if g.total >= args.min_frequency][: args.top]
    gaps["new_pattern_gaps"] = [g for g in gaps["new_pattern_gaps"] if g.total >= args.min_frequency][: args.top]
    gaps["rare_event_gaps"] = [g for g in gaps["rare_event_gaps"] if g.total < args.min_frequency][: args.top]
    gaps["cache_gap_candidates"] = [g for g in gaps["cache_gap_candidates"] if g.total >= args.min_frequency][: args.top]
    gaps["severity_attention_gaps"] = [g for g in gaps["severity_attention_gaps"] if g.total >= args.min_frequency][: args.top]
    gaps["ranked"] = [g for g in gaps["ranked"] if g.total >= 1][: args.top * 5]

    write_outputs(args.output_dir, summary, gaps, args.format, args.summary_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
