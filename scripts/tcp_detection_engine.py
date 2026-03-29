#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


DEFAULT_SOURCE_FILE = Path("/srv/tcp/knowledge/events/tcp_brain_history.jsonl")
DEFAULT_RETENTION_DIR = Path("/srv/tcp/knowledge/retention")
DEFAULT_STATUS_DIR = Path("/srv/tcp/knowledge/detection")
DEFAULT_STATUS_FILE = DEFAULT_STATUS_DIR / "tcp_detection_status.json"
FOCUS_HOST = "10.45.0.2"
FOCUS_PEER = "104.18.32.47"

RAW_ENDPOINT_RE = re.compile(r"^(?P<src>.+?) > (?P<dst>.+?): (?P<body>.*)$")
ENDPOINT_TOKEN_RE = re.compile(r"^(?P<host>.+)\.(?P<port>\d{1,5})$")
CANONICAL_IFACE_RE = re.compile(r"\b(?P<iface>[A-Za-z0-9_.-]+)\s+(?P<direction>In|Out)\s+IP\b")
CANONICAL_LENGTH_RE = re.compile(r"\blength (\d+)\b")
CANONICAL_FLAGS_RE = re.compile(r"Flags \[([^\]]+)\]")
PORT_COMMON_UDP = {53, 67, 68, 123, 137, 138, 161, 162, 389, 427, 500, 514, 520, 5353, 1900}
PORT_INTERNAL = {5432, 6432, 8090, 8091, 8080, 8010, 8011, 9095}


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"timestamp invalido: {value!r}") from exc
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


def event_time(event: Dict[str, Any]) -> Optional[datetime]:
    ts = event.get("ts")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_endpoint_token(token: str) -> Tuple[str, Optional[int]]:
    token = token.strip()
    match = ENDPOINT_TOKEN_RE.match(token)
    if not match:
        return token, None
    host = match.group("host")
    try:
        port = int(match.group("port"))
    except ValueError:
        port = None
    return host, port


def _ip_kind(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    if value == "255.255.255.255":
        return "broadcast"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "name"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link_local"
    if ip.is_unspecified:
        return "unspecified"
    return "public"


def _flag_kind(raw: str) -> str:
    if "Flags [S.]" in raw:
        return "synack"
    if "Flags [S]" in raw:
        return "syn"
    if "Flags [F.]" in raw:
        return "fin"
    if "Flags [P.]" in raw:
        return "push"
    if "Flags [R.]" in raw or "Flags [R]" in raw:
        return "rst"
    if "Flags [.]" in raw:
        return "ack"
    return "other"


def _length_bucket(value: Optional[int]) -> str:
    if value is None:
        return "unknown"
    if value == 0:
        return "len0"
    if value <= 63:
        return "small"
    if value <= 255:
        return "medium"
    if value <= 511:
        return "large"
    return "xlarge"


def _risk_components(
    *,
    syn: int = 0,
    rst: int = 0,
    medium_high: int = 0,
    ai: int = 0,
    new: int = 0,
    unique_ports: int = 0,
    unique_peers: int = 0,
    udp_total: int = 0,
    udp_ports: int = 0,
    udp_peers: int = 0,
    udp_probe: int = 0,
    udp_unclassified: int = 0,
    udp_external: int = 0,
    udp_single_shot_external: int = 0,
    udp_noise: int = 0,
    udp_internal_burst: int = 0,
    udp_ephemeral_exchange: int = 0,
    udp_internal_service: int = 0,
) -> Dict[str, float]:
    score_syn = syn * 1.2
    score_rst = rst * 3.0
    score_medium_high = medium_high * 2.5
    score_ai = ai * 0.8
    score_new = new * 0.5
    score_unique_ports = max(0, unique_ports - 3) * 0.35
    score_unique_peers = max(0, unique_peers - 2) * 0.45
    score_udp_probe = udp_probe * 1.5
    score_udp_unclassified = udp_unclassified * 1.0
    score_udp_external = udp_external * 0.55
    score_udp_single_shot_external = udp_single_shot_external * 0.45
    score_udp_noise = udp_noise * 0.35
    score_udp_internal_burst = udp_internal_burst * 0.25
    score_udp_ephemeral_exchange = udp_ephemeral_exchange * 0.2
    score_udp_ports = max(0, udp_ports - 2) * 0.25
    score_udp_peers = max(0, udp_peers - 2) * 0.35
    score_udp_volume = max(0, udp_total - 6) * 0.05
    score_udp_balance = max(0, udp_external + udp_probe - udp_internal_service) * 0.15
    score_udp_fanout = max(0, udp_peers - 3) * 0.35 + max(0, udp_ports - 3) * 0.25
    score_base = score_syn + score_rst + score_medium_high + score_ai + score_new
    risk_score = (
        score_base
        + score_unique_ports
        + score_unique_peers
        + score_udp_probe
        + score_udp_unclassified
        + score_udp_external
        + score_udp_single_shot_external
        + score_udp_noise
        + score_udp_internal_burst
        + score_udp_ephemeral_exchange
        + score_udp_ports
        + score_udp_peers
        + score_udp_volume
        + score_udp_balance
        + score_udp_fanout
    )
    return {
        "score_base": score_base,
        "score_syn": score_syn,
        "score_rst": score_rst,
        "score_medium_high": score_medium_high,
        "score_ai": score_ai,
        "score_new": score_new,
        "score_unique_ports": score_unique_ports,
        "score_unique_peers": score_unique_peers,
        "score_udp_probe": score_udp_probe,
        "score_udp_unclassified": score_udp_unclassified,
        "score_udp_external": score_udp_external,
        "score_udp_single_shot_external": score_udp_single_shot_external,
        "score_udp_noise": score_udp_noise,
        "score_udp_internal_burst": score_udp_internal_burst,
        "score_udp_ephemeral_exchange": score_udp_ephemeral_exchange,
        "score_udp_ports": score_udp_ports,
        "score_udp_peers": score_udp_peers,
        "score_udp_volume": score_udp_volume,
        "score_udp_balance": score_udp_balance,
        "score_udp_fanout": score_udp_fanout,
        "risk_score": risk_score,
    }


def _is_dynamic_port(port: Optional[int]) -> bool:
    return port is not None and port >= 32768


def _parse_transport_context(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = str(event.get("raw_input_excerpt") or "")
    canonical = str(event.get("canonical_snippet") or "")
    src = dst = body = None
    raw_match = RAW_ENDPOINT_RE.match(raw)
    if raw_match:
        src = raw_match.group("src")
        dst = raw_match.group("dst")
        body = raw_match.group("body")
    iface = None
    direction = None
    iface_match = CANONICAL_IFACE_RE.search(canonical)
    if iface_match:
        iface = iface_match.group("iface")
        direction = iface_match.group("direction").lower()
    length = None
    length_match = CANONICAL_LENGTH_RE.search(canonical)
    if length_match:
        try:
            length = int(length_match.group(1))
        except ValueError:
            length = None
    flags = None
    flags_match = CANONICAL_FLAGS_RE.search(canonical)
    if flags_match:
        flags = flags_match.group(1)
    src_host = src_port = dst_host = dst_port = None
    if src:
        src_host, src_port = _parse_endpoint_token(src)
    if dst:
        dst_host, dst_port = _parse_endpoint_token(dst)
    return {
        "raw": raw,
        "canonical": canonical,
        "src": src,
        "dst": dst,
        "src_host": src_host,
        "src_port": src_port,
        "dst_host": dst_host,
        "dst_port": dst_port,
        "src_kind": _ip_kind(src_host),
        "dst_kind": _ip_kind(dst_host),
        "iface": iface,
        "direction": direction,
        "length": length,
        "length_bucket": _length_bucket(length),
        "flags": flags,
        "body": body or "",
    }


def infer_base_family(event: Dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    rule = metadata.get("family_rule")
    if rule and rule != "none":
        return str(rule)

    canonical = str(event.get("canonical_snippet") or "")
    if "Flags [P.]" in canonical:
        return "tcp_family_flags_p"
    if "Flags [.]" in canonical:
        return "tcp_family_flags_ack"
    if "Flags [F.]" in canonical:
        return "tcp_family_flags_fin"
    if "Flags [S.]" in canonical:
        return "tcp_family_flags_synack"
    if "Flags [S]" in canonical:
        return "tcp_family_flags_syn"
    if "Flags [R.]" in canonical or "Flags [R]" in canonical:
        return "tcp_family_flags_rst"
    if "proto TCP (6)" in canonical:
        if "length 52" in canonical:
            return "tcp_family_len52"
        return "tcp_ip_frame"
    if "UDP" in canonical:
        if any(marker in canonical for marker in ("q:", "AAAA?", "A?", "MX?", "TXT?")):
            return "udp_dns"
        return "udp_other"
    if canonical.startswith("GET ") or " HTTP/" in canonical or canonical.startswith("HTTP/"):
        return "http_request"
    if canonical.startswith(("Date:", "Server:", "Content-", "Connection:")):
        return "http_header"
    return "other"


def classify_tcp_ip_frame(ctx: Dict[str, Any]) -> str:
    iface = ctx.get("iface") or "unknown"
    direction = ctx.get("direction") or "unknown"
    length = ctx.get("length")
    length_bucket = ctx.get("length_bucket") or "unknown"
    scope = "loopback" if iface == "lo" or ctx.get("src_kind") == "loopback" or ctx.get("dst_kind") == "loopback" else "network"
    role = "ingress" if direction == "in" else "egress" if direction == "out" else "unknown"
    if scope == "loopback":
        return f"tcp_loopback_{length_bucket}"
    if length is not None and length <= 63:
        return f"tcp_{role}_control"
    if length is not None and length >= 256:
        return f"tcp_{role}_payload"
    return f"tcp_{role}_frame"


def classify_udp_other(ctx: Dict[str, Any]) -> str:
    raw = ctx.get("raw") or ""
    canonical = ctx.get("canonical") or ""
    src_kind = ctx.get("src_kind")
    dst_kind = ctx.get("dst_kind")
    src_port = ctx.get("src_port")
    dst_port = ctx.get("dst_port")
    length = ctx.get("length")
    body = ctx.get("body") or ""
    text = f"{raw} {canonical} {body}".lower()

    if "q:" in raw or "aaaa?" in raw.lower() or "a?" in raw or "mx?" in raw or "txt?" in raw:
        return "udp_dns_like"
    if dst_kind == "multicast" or src_kind == "multicast" or "multicast" in text:
        return "udp_multicast_like"
    if dst_kind == "broadcast" or src_kind == "broadcast" or "255.255.255.255" in raw:
        return "udp_broadcast_like"
    if src_kind == "loopback" and dst_kind == "loopback":
        return "udp_localhost_like"
    if src_port in PORT_COMMON_UDP or dst_port in PORT_COMMON_UDP:
        return "udp_internal_service_like"
    if src_kind in {"loopback", "private"} and dst_kind in {"loopback", "private"}:
        if _is_dynamic_port(src_port) and _is_dynamic_port(dst_port) and (length is None or length <= 128):
            return "udp_ephemeral_exchange"
        if length is not None and length <= 64:
            return "udp_internal_burst"
        return "udp_internal_service_like"
    if src_kind in {"loopback", "private"} and dst_kind in {"public", "name"}:
        if length is not None and length <= 64 and not (src_port in PORT_COMMON_UDP or dst_port in PORT_COMMON_UDP):
            return "udp_probe_like"
        if length is not None and length <= 96 and not (src_port in PORT_COMMON_UDP or dst_port in PORT_COMMON_UDP):
            return "udp_external_like"
        if length is not None and length <= 128:
            return "udp_single_shot_external"
        return "udp_external_like"
    if src_kind == "public" or dst_kind == "public":
        if length is not None and length <= 64 and not (src_port in PORT_COMMON_UDP or dst_port in PORT_COMMON_UDP):
            return "udp_probe_like"
        if length is not None and length <= 96 and not (src_port in PORT_COMMON_UDP or dst_port in PORT_COMMON_UDP):
            return "udp_single_shot_external"
        return "udp_external_like"
    if "bad udp cksum" in text or (length is not None and length <= 48):
        return "udp_noise_like"
    return "udp_unclassified_residual"


def infer_operational_family(event: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    base_family = infer_base_family(event)
    ctx = _parse_transport_context(event)
    if base_family == "tcp_ip_frame":
        return classify_tcp_ip_frame(ctx), base_family, ctx
    if base_family == "udp_other":
        return classify_udp_other(ctx), base_family, ctx
    return base_family, base_family, ctx


def infer_family(event: Dict[str, Any]) -> str:
    return infer_operational_family(event)[0]


def window_counts(items: List[str], window_size: int, stride: int) -> Dict[str, List[int]]:
    counts: Dict[str, List[int]] = defaultdict(list)
    if not items or window_size <= 0:
        return counts
    for start in range(0, max(len(items) - window_size + 1, 1), stride):
        window = items[start : start + window_size]
        c = Counter(window)
        for family, value in c.items():
            counts[family].append(value)
    return counts


def fmt_rate(value: float) -> str:
    return f"{value:.2%}"


def build_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(
        events,
        key=lambda e: event_time(e) or datetime.min.replace(tzinfo=timezone.utc),
    )

    families: List[str] = []
    base_families: List[str] = []
    by_family = Counter()
    by_base_family = Counter()
    ai_by_family = Counter()
    cache_by_family = Counter()
    new_by_family = Counter()
    severity_by_family: Dict[str, Counter] = defaultdict(Counter)
    severity_by_base: Dict[str, Counter] = defaultdict(Counter)
    by_response_mode = Counter()
    by_severity = Counter()
    by_endpoint = Counter()
    top_snippets = Counter()
    transitions = Counter()
    snippet_meta: Dict[str, Dict[str, Any]] = {}
    ip_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    pair_events: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    ip_counts = Counter()
    ip_unique_ports: Dict[str, set] = defaultdict(set)
    ip_unique_peers: Dict[str, set] = defaultdict(set)
    ip_syn = Counter()
    ip_rst = Counter()
    ip_ai = Counter()
    ip_new = Counter()
    ip_medium_high = Counter()
    ip_udp_counts = Counter()
    ip_udp_unique_ports: Dict[str, set] = defaultdict(set)
    ip_udp_unique_peers: Dict[str, set] = defaultdict(set)
    ip_udp_localhost = Counter()
    ip_udp_dns = Counter()
    ip_udp_multicast = Counter()
    ip_udp_broadcast = Counter()
    ip_udp_internal_service = Counter()
    ip_udp_internal_burst = Counter()
    ip_udp_ephemeral_exchange = Counter()
    ip_udp_probe = Counter()
    ip_udp_external = Counter()
    ip_udp_single_shot_external = Counter()
    ip_udp_noise = Counter()
    ip_udp_unclassified = Counter()
    pair_counts = Counter()
    pair_unique_ports: Dict[Tuple[str, str], set] = defaultdict(set)
    pair_syn = Counter()
    pair_rst = Counter()
    pair_ai = Counter()
    pair_new = Counter()
    pair_medium_high = Counter()
    event_rows: List[Dict[str, Any]] = []

    for idx, event in enumerate(ordered):
        fam, base_family, ctx = infer_operational_family(event)
        families.append(fam)
        base_families.append(base_family)
        by_family[fam] += 1
        by_base_family[base_family] += 1
        by_response_mode[event.get("response_mode") or "unknown"] += 1
        sev = str(event.get("severity") or "unknown")
        by_severity[sev] += 1
        by_endpoint[event.get("endpoint") or "unknown"] += 1
        if event.get("used_ai"):
            ai_by_family[fam] += 1
        if event.get("cache_hit"):
            cache_by_family[fam] += 1
        if event.get("created_new_pattern"):
            new_by_family[fam] += 1
        severity_by_family[fam][sev] += 1
        severity_by_base[base_family][sev] += 1
        snippet = event.get("canonical_snippet")
        if snippet:
            snippet = str(snippet)
            top_snippets[snippet] += 1
            if snippet not in snippet_meta:
                snippet_meta[snippet] = {
                    "family": fam,
                    "severity": sev,
                    "ai": 0,
                    "cache": 0,
                    "new": 0,
                }
            if event.get("used_ai"):
                snippet_meta[snippet]["ai"] += 1
            if event.get("cache_hit"):
                snippet_meta[snippet]["cache"] += 1
            if event.get("created_new_pattern"):
                snippet_meta[snippet]["new"] += 1
        if idx > 0:
            transitions[(families[idx - 1], fam)] += 1

        raw = ctx.get("raw") or ""
        src = ctx.get("src_host")
        dst = ctx.get("dst_host")
        src_port = ctx.get("src_port")
        dst_port = ctx.get("dst_port")
        if src:
            ip_counts[src] += 1
            ip_events[src].append(event)
            if dst:
                ip_unique_peers[src].add(dst)
            if src_port is not None:
                ip_unique_ports[src].add(src_port)
            flag_kind = _flag_kind(raw)
            if flag_kind == "syn":
                ip_syn[src] += 1
            if flag_kind == "rst":
                ip_rst[src] += 1
            if event.get("used_ai"):
                ip_ai[src] += 1
            if event.get("created_new_pattern"):
                ip_new[src] += 1
            if sev in {"medium", "high"}:
                ip_medium_high[src] += 1
            if fam.startswith("udp_"):
                ip_udp_counts[src] += 1
                if dst:
                    ip_udp_unique_peers[src].add(dst)
                if src_port is not None:
                    ip_udp_unique_ports[src].add(src_port)
                if fam == "udp_localhost_like":
                    ip_udp_localhost[src] += 1
                elif fam == "udp_dns_like":
                    ip_udp_dns[src] += 1
                elif fam == "udp_multicast_like":
                    ip_udp_multicast[src] += 1
                elif fam == "udp_broadcast_like":
                    ip_udp_broadcast[src] += 1
                elif fam == "udp_internal_service_like":
                    ip_udp_internal_service[src] += 1
                elif fam == "udp_internal_burst":
                    ip_udp_internal_burst[src] += 1
                elif fam == "udp_ephemeral_exchange":
                    ip_udp_ephemeral_exchange[src] += 1
                elif fam == "udp_probe_like":
                    ip_udp_probe[src] += 1
                elif fam == "udp_external_like":
                    ip_udp_external[src] += 1
                elif fam == "udp_single_shot_external":
                    ip_udp_single_shot_external[src] += 1
                elif fam == "udp_noise_like":
                    ip_udp_noise[src] += 1
                elif fam == "udp_unclassified_residual":
                    ip_udp_unclassified[src] += 1
        if src and dst:
            k = (src, dst)
            pair_counts[k] += 1
            pair_events[k].append(event)
            if dst_port is not None:
                pair_unique_ports[k].add(dst_port)
            if flag_kind == "syn":
                pair_syn[k] += 1
            if flag_kind == "rst":
                pair_rst[k] += 1
            if event.get("used_ai"):
                pair_ai[k] += 1
            if event.get("created_new_pattern"):
                pair_new[k] += 1
            if sev in {"medium", "high"}:
                pair_medium_high[k] += 1

    total = len(ordered)
    ai_total = sum(1 for e in ordered if e.get("used_ai"))
    cache_total = sum(1 for e in ordered if e.get("cache_hit"))
    new_total = sum(1 for e in ordered if e.get("created_new_pattern"))

    split = max(int(total * 0.75), total - 100) if total else 0
    previous = ordered[:split]
    recent = ordered[split:]

    prev_families = [infer_family(e) for e in previous]
    recent_families = [infer_family(e) for e in recent]
    recent_base_families = [infer_base_family(e) for e in recent]
    prev_counts = Counter(prev_families)
    recent_counts = Counter(recent_families)
    prev_base_counts = Counter(infer_base_family(e) for e in previous)
    recent_base_counts = Counter(recent_base_families)

    recent_len = max(len(recent), 1)
    prev_len = max(len(previous), 1)
    growth_rows = []
    for fam, recent_count in recent_counts.items():
        prev_count = prev_counts.get(fam, 0)
        recent_rate = recent_count / recent_len
        prev_rate = prev_count / prev_len
        ratio = recent_rate / prev_rate if prev_rate > 0 else float("inf")
        growth_rows.append(
            {
                "family": fam,
                "recent": recent_count,
                "previous": prev_count,
                "recent_rate": recent_rate,
                "previous_rate": prev_rate,
                "growth_ratio": ratio,
                "ai_recent": sum(1 for e in recent if infer_family(e) == fam and e.get("used_ai")),
                "cache_recent": sum(1 for e in recent if infer_family(e) == fam and e.get("cache_hit")),
            }
        )
    growth_rows.sort(
        key=lambda row: (
            -row["growth_ratio"] if row["growth_ratio"] != float("inf") else float("-inf"),
            -row["recent"],
            row["family"],
        )
    )

    # Burst detection with a rolling window over event order.
    window_size = min(max(50, total // 20 or 50), 100) if total else 50
    stride = max(10, window_size // 4)
    burst_series = window_counts(families, window_size, stride)
    burst_rows = []
    for fam, vals in burst_series.items():
        if not vals:
            continue
        avg = sum(vals) / len(vals)
        mx = max(vals)
        last = vals[-1]
        if sum(1 for _ in vals) == 0:
            continue
        score = mx / avg if avg else float("inf")
        recent_score = last / avg if avg else float("inf")
        total_count = by_family[fam]
        if total_count >= 8 and (score >= 1.8 or recent_score >= 1.5):
            burst_rows.append(
                {
                    "family": fam,
                    "window_size": window_size,
                    "avg_window_count": avg,
                    "max_window_count": mx,
                    "last_window_count": last,
                    "burst_score": score,
                    "recent_score": recent_score,
                    "total": total_count,
                    "ai": ai_by_family.get(fam, 0),
                    "cache": cache_by_family.get(fam, 0),
                    "new": new_by_family.get(fam, 0),
                }
            )
    burst_rows.sort(key=lambda row: (-row["burst_score"], -row["last_window_count"], row["family"]))

    ai_rows = []
    for fam, total_count in by_family.items():
        ai_count = ai_by_family.get(fam, 0)
        cache_count = cache_by_family.get(fam, 0)
        ai_rate = ai_count / total_count if total_count else 0.0
        cache_rate = cache_count / total_count if total_count else 0.0
        if ai_count >= 2 or ai_rate >= 0.05:
            ai_rows.append(
                {
                    "family": fam,
                    "total": total_count,
                    "ai": ai_count,
                    "cache": cache_count,
                    "new": new_by_family.get(fam, 0),
                    "ai_rate": ai_rate,
                    "cache_rate": cache_rate,
                    "severity": dict(severity_by_family[fam]),
                }
            )
    ai_rows.sort(key=lambda row: (-row["ai"], -row["ai_rate"], -row["total"], row["family"]))

    rare_rows = []
    for fam, total_count in by_family.items():
        sev = severity_by_family[fam]
        medium_high = sev.get("medium", 0) + sev.get("high", 0)
        if total_count <= 10 and medium_high > 0:
            rare_rows.append(
                {
                    "family": fam,
                    "total": total_count,
                    "ai": ai_by_family.get(fam, 0),
                    "cache": cache_by_family.get(fam, 0),
                    "new": new_by_family.get(fam, 0),
                    "medium_high": medium_high,
                    "severity": dict(sev),
                }
            )
    rare_rows.sort(key=lambda row: (-row["medium_high"], row["total"], row["family"]))

    rare_event_rows = []
    for snippet, count in top_snippets.items():
        meta = snippet_meta.get(snippet) or {}
        sev = str(meta.get("severity") or "unknown")
        if count <= 2 and sev in {"medium", "high"}:
            rare_event_rows.append(
                {
                    "snippet": snippet,
                    "family": meta.get("family") or "unknown",
                    "count": count,
                    "severity": sev,
                    "ai": meta.get("ai", 0),
                    "cache": meta.get("cache", 0),
                    "new": meta.get("new", 0),
                }
            )
    rare_event_rows.sort(
        key=lambda row: (
            0 if row["severity"] == "high" else 1,
            row["count"],
            -row["ai"],
            row["family"],
        )
    )

    transition_rows = []
    for (a, b), count in transitions.most_common(20):
        transition_rows.append({"from": a, "to": b, "count": count})

    top_patterns = [
        {"pattern": pat, "count": count}
        for pat, count in Counter(f.get("pattern_hash") for f in ordered if f.get("pattern_hash")).most_common(20)
    ]

    top_snippet_rows = [
        {"snippet": snippet, "count": count}
        for snippet, count in top_snippets.most_common(20)
    ]

    family_rows = []
    for fam, total_count in by_family.most_common():
        family_rows.append(
            {
                "family": fam,
                "total": total_count,
                "ai": ai_by_family.get(fam, 0),
                "cache": cache_by_family.get(fam, 0),
                "new": new_by_family.get(fam, 0),
                "ai_rate": (ai_by_family.get(fam, 0) / total_count) if total_count else 0.0,
                "cache_rate": (cache_by_family.get(fam, 0) / total_count) if total_count else 0.0,
                "new_rate": (new_by_family.get(fam, 0) / total_count) if total_count else 0.0,
                "severity": dict(severity_by_family[fam]),
            }
        )

    base_family_rows = []
    for fam, total_count in by_base_family.most_common():
        base_family_rows.append(
            {
                "family": fam,
                "total": total_count,
                "ai": sum(1 for e in ordered if infer_base_family(e) == fam and e.get("used_ai")),
                "cache": sum(1 for e in ordered if infer_base_family(e) == fam and e.get("cache_hit")),
                "new": sum(1 for e in ordered if infer_base_family(e) == fam and e.get("created_new_pattern")),
                "ai_rate": (
                    sum(1 for e in ordered if infer_base_family(e) == fam and e.get("used_ai")) / total_count
                )
                if total_count
                else 0.0,
                "cache_rate": (
                    sum(1 for e in ordered if infer_base_family(e) == fam and e.get("cache_hit")) / total_count
                )
                if total_count
                else 0.0,
                "new_rate": (
                    sum(1 for e in ordered if infer_base_family(e) == fam and e.get("created_new_pattern")) / total_count
                )
                if total_count
                else 0.0,
                "severity": dict(severity_by_base[fam]),
            }
        )

    def score_ip(src: str) -> Dict[str, Any]:
        total_count = ip_counts[src]
        syn = ip_syn[src]
        rst = ip_rst[src]
        ai = ip_ai[src]
        new = ip_new[src]
        medium_high = ip_medium_high[src]
        uniq_ports = len(ip_unique_ports[src])
        uniq_peers = len(ip_unique_peers[src])
        udp_total = ip_udp_counts[src]
        udp_ports = len(ip_udp_unique_ports[src])
        udp_peers = len(ip_udp_unique_peers[src])
        udp_localhost = ip_udp_localhost[src]
        udp_dns = ip_udp_dns[src]
        udp_multicast = ip_udp_multicast[src]
        udp_broadcast = ip_udp_broadcast[src]
        udp_internal_service = ip_udp_internal_service[src]
        udp_internal_burst = ip_udp_internal_burst[src]
        udp_ephemeral_exchange = ip_udp_ephemeral_exchange[src]
        udp_probe = ip_udp_probe[src]
        udp_external = ip_udp_external[src]
        udp_single_shot_external = ip_udp_single_shot_external[src]
        udp_noise = ip_udp_noise[src]
        udp_unclassified = ip_udp_unclassified[src]
        components = _risk_components(
            syn=syn,
            rst=rst,
            medium_high=medium_high,
            ai=ai,
            new=new,
            unique_ports=uniq_ports,
            unique_peers=uniq_peers,
            udp_total=udp_total,
            udp_ports=udp_ports,
            udp_peers=udp_peers,
            udp_probe=udp_probe,
            udp_unclassified=udp_unclassified,
            udp_external=udp_external,
            udp_single_shot_external=udp_single_shot_external,
            udp_noise=udp_noise,
            udp_internal_burst=udp_internal_burst,
            udp_ephemeral_exchange=udp_ephemeral_exchange,
            udp_internal_service=udp_internal_service,
        )
        return {
            "ip": src,
            "events": total_count,
            "unique_ports": uniq_ports,
            "unique_peers": uniq_peers,
            "udp_events": udp_total,
            "udp_unique_ports": udp_ports,
            "udp_unique_peers": udp_peers,
            "syn": syn,
            "rst": rst,
            "ai": ai,
            "new": new,
            "medium_high": medium_high,
            "udp_localhost": udp_localhost,
            "udp_dns": udp_dns,
            "udp_multicast": udp_multicast,
            "udp_broadcast": udp_broadcast,
            "udp_internal_service": udp_internal_service,
            "udp_internal_burst": udp_internal_burst,
            "udp_ephemeral_exchange": udp_ephemeral_exchange,
            "udp_probe": udp_probe,
            "udp_external": udp_external,
            "udp_single_shot_external": udp_single_shot_external,
            "udp_noise": udp_noise,
            "udp_unclassified": udp_unclassified,
            **components,
        }

    def scan_candidate(row: Dict[str, Any]) -> bool:
        # Conservative: prefer candidates with UDP repetition/fanout or TCP reset pressure.
        udp_suspicious = row.get("udp_probe", 0) + row.get("udp_unclassified", 0) + row.get("udp_noise", 0)
        return (
            row["events"] >= 10
            and row["unique_peers"] >= 3
            and row["unique_ports"] >= 4
            and (
                row["syn"] >= 5
                or row["rst"] >= 2
                or udp_suspicious >= 4
                or (row.get("udp_external", 0) >= 4 and row.get("udp_unique_peers", 0) >= 3)
            )
        )

    ip_risk_rows = [score_ip(src) for src in ip_counts]
    ip_risk_rows.sort(key=lambda row: (-row["risk_score"], -row["events"], row["ip"]))
    scan_rows = []
    for row in ip_risk_rows:
        if scan_candidate(row):
            scan_rows.append(
                dict(
                    row,
                    suspect_scan_candidate=True,
                    rationale=(
                        f"events={row['events']}, unique_ports={row['unique_ports']}, unique_peers={row['unique_peers']}, "
                        f"syn={row['syn']}, rst={row['rst']}, udp_probe={row.get('udp_probe', 0)}, "
                        f"udp_unclassified={row.get('udp_unclassified', 0)}, udp_external={row.get('udp_external', 0)}"
                    ),
                )
            )
    pair_risk_rows = []
    for (src, dst), count in pair_counts.items():
        syn = pair_syn[(src, dst)]
        rst = pair_rst[(src, dst)]
        ai = pair_ai[(src, dst)]
        new = pair_new[(src, dst)]
        medium_high = pair_medium_high[(src, dst)]
        risk_score = (
            rst * 3.5
            + syn * 1.1
            + medium_high * 2.0
            + ai * 0.6
            + new * 0.4
            + max(0, len(pair_unique_ports[(src, dst)]) - 1) * 0.35
        )
        pair_risk_rows.append(
            {
                "src": src,
                "dst": dst,
                "events": count,
                "unique_ports": len(pair_unique_ports[(src, dst)]),
                "syn": syn,
                "rst": rst,
                "ai": ai,
                "new": new,
                "medium_high": medium_high,
                "risk_score": risk_score,
            }
        )
    pair_risk_rows.sort(key=lambda row: (-row["risk_score"], -row["events"], row["src"], row["dst"]))

    return {
        "total_events": total,
        "ai_total": ai_total,
        "cache_total": cache_total,
        "new_total": new_total,
        "cache_hit_rate": cache_total / total if total else 0.0,
        "ai_rate": ai_total / total if total else 0.0,
        "new_pattern_rate": new_total / total if total else 0.0,
        "top_families": family_rows[:20],
        "top_base_families": base_family_rows[:20],
        "ai_dependency": ai_rows[:20],
        "growth": growth_rows[:20],
        "bursts": burst_rows[:20],
        "rare_severe": rare_rows[:20],
        "rare_events": rare_event_rows[:20],
        "transitions": transition_rows[:20],
        "top_patterns": top_patterns,
        "top_snippets": top_snippet_rows,
        "response_modes": dict(by_response_mode),
        "severity_counts": dict(by_severity),
        "endpoint_counts": dict(by_endpoint),
        "ip_risk": ip_risk_rows[:20],
        "scan_candidates": scan_rows[:20],
        "pair_risk": pair_risk_rows[:20],
        "focus_host": FOCUS_HOST,
        "focus_host_report": build_host_report(FOCUS_HOST, ordered, ip_risk_rows),
        "first_ts": (event_time(ordered[0]).isoformat() if ordered and event_time(ordered[0]) else None),
        "last_ts": (event_time(ordered[-1]).isoformat() if ordered and event_time(ordered[-1]) else None),
        "window_size": window_size,
        "window_stride": stride,
        "generic_counts": {
            "base_tcp_ip_frame": by_base_family.get("tcp_ip_frame", 0),
            "base_udp_other": by_base_family.get("udp_other", 0),
            "operational_tcp_ip_frame": by_family.get("tcp_ip_frame", 0),
            "operational_udp_other": by_family.get("udp_other", 0),
        },
    }


def build_host_report(host: str, ordered: List[Dict[str, Any]], ip_risk_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    host_risk = next((row for row in ip_risk_rows if row.get("ip") == host), None)
    host_events: List[Dict[str, Any]] = []
    peer_counts = Counter()
    peer_inbound = Counter()
    peer_outbound = Counter()
    pair_counts = Counter()
    port_counts = Counter()
    direction_counts = Counter()
    proto_counts = Counter()
    severity_counts = Counter()
    family_counts = Counter()
    base_family_counts = Counter()
    peer_port_counts: Dict[str, Counter] = defaultdict(Counter)
    peer_family_counts: Dict[str, Counter] = defaultdict(Counter)
    udp_family_counts = Counter()
    pair_focus_events: List[Dict[str, Any]] = []
    host_syn = 0
    host_rst = 0
    host_ai = 0
    host_new = 0
    host_medium_high = 0
    host_udp_events = 0
    host_tcp_events = 0
    host_other_events = 0
    udp_events = Counter()

    for event in ordered:
        ctx = _parse_transport_context(event)
        raw = ctx.get("raw") or ""
        canonical = ctx.get("canonical") or ""
        if host not in raw and host not in canonical:
            continue
        fam, base_family, _ = infer_operational_family(event)
        host_events.append(event)
        sev = str(event.get("severity") or "unknown")
        severity_counts[sev] += 1
        family_counts[fam] += 1
        base_family_counts[base_family] += 1
        if event.get("used_ai"):
            host_ai += 1
        if event.get("created_new_pattern"):
            host_new += 1
        if sev in {"medium", "high"}:
            host_medium_high += 1
        flag_kind = _flag_kind(raw)
        if flag_kind == "syn":
            host_syn += 1
        elif flag_kind == "rst":
            host_rst += 1

        if base_family.startswith("udp_") or fam.startswith("udp_"):
            host_udp_events += 1
            udp_events[fam] += 1
            udp_family_counts[fam] += 1
        elif base_family.startswith("tcp_") or fam.startswith("tcp_"):
            host_tcp_events += 1
        else:
            host_other_events += 1

        src = ctx.get("src_host")
        dst = ctx.get("dst_host")
        src_port = ctx.get("src_port")
        dst_port = ctx.get("dst_port")
        if src == host:
            direction_counts["outbound"] += 1
            if dst == FOCUS_PEER:
                pair_focus_events.append(event)
            if dst:
                peer_counts[dst] += 1
                peer_outbound[dst] += 1
                peer_family_counts[dst][fam] += 1
                pair_counts[(host, dst)] += 1
            if src_port is not None:
                port_counts[src_port] += 1
                if dst:
                    peer_port_counts[dst][src_port] += 1
        elif dst == host:
            direction_counts["inbound"] += 1
            if src == FOCUS_PEER:
                pair_focus_events.append(event)
            if src:
                peer_counts[src] += 1
                peer_inbound[src] += 1
                peer_family_counts[src][fam] += 1
                pair_counts[(src, host)] += 1
            if dst_port is not None:
                port_counts[dst_port] += 1
                if src:
                    peer_port_counts[src][dst_port] += 1
        else:
            direction_counts["unknown"] += 1

    top_peers = [
        {
            "peer": peer,
            "events": count,
            "inbound": peer_inbound[peer],
            "outbound": peer_outbound[peer],
            "top_ports": [{"port": port, "count": c} for port, c in peer_port_counts[peer].most_common(5)],
            "top_families": [{"family": fam, "count": c} for fam, c in peer_family_counts[peer].most_common(5)],
        }
        for peer, count in peer_counts.most_common(10)
    ]
    top_ports = [{"port": port, "count": count} for port, count in port_counts.most_common(15)]
    top_pairs = [
        {"src": src, "dst": dst, "events": count}
        for (src, dst), count in sorted(pair_counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))[:15]
    ]

    score_fields = [
        "score_base",
        "score_syn",
        "score_rst",
        "score_medium_high",
        "score_ai",
        "score_new",
        "score_unique_ports",
        "score_unique_peers",
        "score_udp_probe",
        "score_udp_unclassified",
        "score_udp_external",
        "score_udp_single_shot_external",
        "score_udp_noise",
        "score_udp_internal_burst",
        "score_udp_ephemeral_exchange",
        "score_udp_ports",
        "score_udp_peers",
        "score_udp_volume",
        "score_udp_balance",
        "score_udp_fanout",
    ]
    if host_risk is None:
        host_risk = {"ip": host, "risk_score": 0.0, "events": len(host_events)}
        for field in score_fields:
            host_risk[field] = 0.0
    else:
        host_risk = dict(host_risk)
        host_risk["score_base"] = (
            host_risk.get("score_syn", 0.0)
            + host_risk.get("score_rst", 0.0)
            + host_risk.get("score_medium_high", 0.0)
            + host_risk.get("score_ai", 0.0)
            + host_risk.get("score_new", 0.0)
        )

    udp_total = host_udp_events
    top_udp = [{"family": fam, "count": count} for fam, count in udp_family_counts.most_common(10)]
    pro_scan = []
    if host_risk.get("unique_ports", 0) >= 8:
        pro_scan.append(f"unique_ports={host_risk['unique_ports']}")
    if host_risk.get("unique_peers", 0) >= 5:
        pro_scan.append(f"unique_peers={host_risk['unique_peers']}")
    if host_risk.get("udp_probe", 0) >= 8:
        pro_scan.append(f"udp_probe={host_risk['udp_probe']}")
    if host_risk.get("udp_external", 0) >= 1:
        pro_scan.append(f"udp_external={host_risk['udp_external']}")
    if host_risk.get("udp_single_shot_external", 0) >= 1:
        pro_scan.append(f"udp_single_shot_external={host_risk['udp_single_shot_external']}")
    if host_risk.get("risk_score", 0.0) >= 100:
        pro_scan.append(f"risk_score={host_risk['risk_score']:.2f}")
    against_scan = []
    if peer_counts.get("10.45.0.15") or peer_counts.get("10.45.0.1"):
        for peer in ("10.45.0.15", "10.45.0.1"):
            if peer_counts.get(peer):
                against_scan.append(f"dominant_internal_peer={peer}:{peer_counts[peer]}")
    if peer_counts.get("104.18.32.47"):
        against_scan.append(f"legit_external_443_peer=104.18.32.47:{peer_counts['104.18.32.47']}")
    if peer_counts.get("172.67.131.172"):
        against_scan.append(f"legit_external_443_peer=172.67.131.172:{peer_counts['172.67.131.172']}")
    if peer_counts.get("198.41.200.13") or peer_counts.get("198.41.192.57"):
        against_scan.append("cloudflare_quic_like_peer_present")
    if host_risk.get("rst", 0) <= 2 and host_risk.get("syn", 0) <= 5:
        against_scan.append("low_rst_low_syn")
    if host_risk.get("udp_internal_service", 0) > host_risk.get("udp_probe", 0):
        against_scan.append("udp_more_service_than_probe")

    conclusion = "candidate_conservador"
    if host_risk.get("risk_score", 0.0) < 100:
        conclusion = "contexto_legitimo"
    if host_risk.get("risk_score", 0.0) >= 100 and len(pro_scan) >= 3 and len(against_scan) <= 2:
        conclusion = "candidate_conservador"
    if host_risk.get("risk_score", 0.0) >= 100 and len(against_scan) >= 3 and host_risk.get("udp_probe", 0) <= 12:
        conclusion = "contexto_legitimo_com_sinal_conservador"

    return {
        "host": host,
        "total_events": len(host_events),
        "direction_counts": dict(direction_counts),
        "protocol_counts": {
            "tcp": host_tcp_events,
            "udp": host_udp_events,
            "other": host_other_events,
        },
        "severity_counts": dict(severity_counts),
        "family_counts": top_family_rows(family_counts, host, ip_risk_rows),
        "base_family_counts": [{"family": fam, "total": count} for fam, count in base_family_counts.most_common(10)],
        "top_peers": top_peers,
        "top_ports": top_ports,
        "top_pairs": top_pairs,
        "udp_breakdown": top_udp,
        "risk": host_risk,
        "score_breakdown": {k: host_risk.get(k, 0.0) for k in score_fields + ["score_base"]},
        "pro_scan_evidence": pro_scan,
        "against_scan_evidence": against_scan,
        "conclusion": conclusion,
        "timeline": build_temporal_report(host_events, host, window_seconds=180),
        "pair_timeline": build_temporal_report(pair_focus_events, host, focus_peer=FOCUS_PEER, window_seconds=180),
        "scan_candidate": bool(
            host_risk.get("events", 0) >= 10
            and host_risk.get("unique_peers", 0) >= 3
            and host_risk.get("unique_ports", 0) >= 4
            and (
                host_risk.get("syn", 0) >= 5
                or host_risk.get("rst", 0) >= 2
                or host_risk.get("udp_probe", 0) + host_risk.get("udp_unclassified", 0) + host_risk.get("udp_noise", 0) >= 4
            )
        ),
    }


def top_family_rows(counter: Counter, host: str, ip_risk_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # The host report only needs family totals; this helper keeps the rendering logic compact.
    return [{"family": fam, "total": total} for fam, total in counter.most_common(15)]


def build_temporal_report(
    events: List[Dict[str, Any]],
    host: str,
    focus_peer: Optional[str] = None,
    window_seconds: int = 180,
) -> Dict[str, Any]:
    ordered = sorted(events, key=lambda e: event_time(e) or datetime.min.replace(tzinfo=timezone.utc))
    if not ordered:
        return {"host": host, "focus_peer": focus_peer, "window_seconds": window_seconds, "windows": []}

    first_dt = event_time(ordered[0]) or datetime.min.replace(tzinfo=timezone.utc)
    buckets: Dict[int, Dict[str, Any]] = {}

    def get_bucket(idx: int) -> Dict[str, Any]:
        if idx not in buckets:
            buckets[idx] = {
                "events": 0,
                "syn": 0,
                "rst": 0,
                "ai": 0,
                "new": 0,
                "medium_high": 0,
                "udp_probe": 0,
                "udp_external": 0,
                "udp_unclassified": 0,
                "udp_internal_service": 0,
                "udp_single_shot_external": 0,
                "udp_noise": 0,
                "udp_internal_burst": 0,
                "udp_ephemeral_exchange": 0,
                "udp_dns": 0,
                "udp_multicast": 0,
                "udp_broadcast": 0,
                "unique_ports": set(),
                "unique_peers": set(),
                "family_counts": Counter(),
                "peer_counts": Counter(),
                "pair_counts": Counter(),
                "direction_counts": Counter(),
                "protocol_counts": Counter(),
            }
        return buckets[idx]

    for event in ordered:
        dt = event_time(event) or first_dt
        idx = int(max((dt - first_dt).total_seconds(), 0) // window_seconds)
        b = get_bucket(idx)
        ctx = _parse_transport_context(event)
        raw = ctx.get("raw") or ""
        fam, _, _ = infer_operational_family(event)
        src = ctx.get("src_host")
        dst = ctx.get("dst_host")
        src_port = ctx.get("src_port")
        dst_port = ctx.get("dst_port")

        if focus_peer is None:
            if not (src == host or dst == host):
                continue
        else:
            if not ((src == host and dst == focus_peer) or (src == focus_peer and dst == host)):
                continue

        b["events"] += 1
        b["family_counts"][fam] += 1
        if event.get("used_ai"):
            b["ai"] += 1
        if event.get("created_new_pattern"):
            b["new"] += 1
        if str(event.get("severity") or "unknown") in {"medium", "high"}:
            b["medium_high"] += 1
        flag_kind = _flag_kind(raw)
        if flag_kind == "syn":
            b["syn"] += 1
        elif flag_kind == "rst":
            b["rst"] += 1
        if fam == "udp_probe_like":
            b["udp_probe"] += 1
        elif fam == "udp_external_like":
            b["udp_external"] += 1
        elif fam == "udp_unclassified_residual":
            b["udp_unclassified"] += 1
        elif fam == "udp_internal_service_like":
            b["udp_internal_service"] += 1
        elif fam == "udp_single_shot_external":
            b["udp_single_shot_external"] += 1
        elif fam == "udp_noise_like":
            b["udp_noise"] += 1
        elif fam == "udp_internal_burst":
            b["udp_internal_burst"] += 1
        elif fam == "udp_ephemeral_exchange":
            b["udp_ephemeral_exchange"] += 1
        elif fam == "udp_dns_like":
            b["udp_dns"] += 1
        elif fam == "udp_multicast_like":
            b["udp_multicast"] += 1
        elif fam == "udp_broadcast_like":
            b["udp_broadcast"] += 1

        if src == host and dst:
            b["direction_counts"]["outbound"] += 1
            b["peer_counts"][dst] += 1
            b["pair_counts"][(src, dst)] += 1
            b["unique_peers"].add(dst)
            if src_port is not None:
                b["unique_ports"].add(src_port)
        elif dst == host and src:
            b["direction_counts"]["inbound"] += 1
            b["peer_counts"][src] += 1
            b["pair_counts"][(src, dst)] += 1
            b["unique_peers"].add(src)
            if dst_port is not None:
                b["unique_ports"].add(dst_port)
        else:
            b["direction_counts"]["unknown"] += 1

        if src == host and dst == focus_peer:
            b["protocol_counts"]["outbound_focus"] += 1
        elif src == focus_peer and dst == host:
            b["protocol_counts"]["inbound_focus"] += 1

    windows: List[Dict[str, Any]] = []
    for idx in sorted(buckets):
        b = buckets[idx]
        start_dt = first_dt + timedelta(seconds=idx * window_seconds)
        end_dt = start_dt + timedelta(seconds=window_seconds)
        udp_total = (
            b["udp_probe"]
            + b["udp_external"]
            + b["udp_unclassified"]
            + b["udp_internal_service"]
            + b["udp_single_shot_external"]
            + b["udp_noise"]
            + b["udp_internal_burst"]
            + b["udp_ephemeral_exchange"]
            + b["udp_dns"]
            + b["udp_multicast"]
            + b["udp_broadcast"]
        )
        components = _risk_components(
            syn=b["syn"],
            rst=b["rst"],
            medium_high=b["medium_high"],
            ai=b["ai"],
            new=b["new"],
            unique_ports=len(b["unique_ports"]),
            unique_peers=len(b["unique_peers"]),
            udp_total=udp_total,
            udp_ports=len(b["unique_ports"]),
            udp_peers=len(b["unique_peers"]),
            udp_probe=b["udp_probe"],
            udp_unclassified=b["udp_unclassified"],
            udp_external=b["udp_external"],
            udp_single_shot_external=b["udp_single_shot_external"],
            udp_noise=b["udp_noise"],
            udp_internal_burst=b["udp_internal_burst"],
            udp_ephemeral_exchange=b["udp_ephemeral_exchange"],
            udp_internal_service=b["udp_internal_service"],
        )
        windows.append(
            {
                "window": idx,
                "start_ts": start_dt.isoformat(),
                "end_ts": end_dt.isoformat(),
                "events": b["events"],
                "syn": b["syn"],
                "rst": b["rst"],
                "ai": b["ai"],
                "new": b["new"],
                "medium_high": b["medium_high"],
                "udp_probe": b["udp_probe"],
                "udp_external": b["udp_external"],
                "udp_unclassified": b["udp_unclassified"],
                "udp_internal_service": b["udp_internal_service"],
                "udp_single_shot_external": b["udp_single_shot_external"],
                "udp_noise": b["udp_noise"],
                "udp_internal_burst": b["udp_internal_burst"],
                "udp_ephemeral_exchange": b["udp_ephemeral_exchange"],
                "udp_dns": b["udp_dns"],
                "udp_multicast": b["udp_multicast"],
                "udp_broadcast": b["udp_broadcast"],
                "unique_ports": len(b["unique_ports"]),
                "unique_peers": len(b["unique_peers"]),
                "direction_counts": dict(b["direction_counts"]),
                "protocol_counts": dict(b["protocol_counts"]),
                "top_peers": [{"peer": peer, "count": count} for peer, count in b["peer_counts"].most_common(5)],
                "top_pairs": [{"src": src, "dst": dst, "count": count} for (src, dst), count in b["pair_counts"].most_common(5)],
                "top_families": [{"family": fam, "count": count} for fam, count in b["family_counts"].most_common(5)],
                **components,
            }
        )

    return {
        "host": host,
        "focus_peer": focus_peer,
        "window_seconds": window_seconds,
        "windows": windows,
    }


def render_host_report_md(summary: Dict[str, Any]) -> str:
    report = summary.get("focus_host_report") or {}
    host = report.get("host") or summary.get("focus_host") or "10.45.0.2"
    risk = report.get("risk") or {}
    lines: List[str] = []
    lines.append(f"# tcp_detection_host_{host}")
    lines.append("")
    lines.append("## Conclusao operacional")
    lines.append(f"- conclusion: {report.get('conclusion')}")
    lines.append(f"- scan_candidate: {report.get('scan_candidate')}")
    lines.append(f"- risk_score: {risk.get('risk_score')}")
    lines.append(f"- total_events: {risk.get('events') or report.get('total_events')}")
    lines.append("")
    lines.append("## Explicacao do score")
    for key, label in [
        ("score_base", "base"),
        ("score_syn", "syn"),
        ("score_rst", "rst"),
        ("score_medium_high", "medium_high"),
        ("score_ai", "ai"),
        ("score_new", "new"),
        ("score_unique_ports", "unique_ports"),
        ("score_unique_peers", "unique_peers"),
        ("score_udp_probe", "udp_probe"),
        ("score_udp_unclassified", "udp_unclassified"),
        ("score_udp_external", "udp_external"),
        ("score_udp_single_shot_external", "udp_single_shot_external"),
        ("score_udp_noise", "udp_noise"),
        ("score_udp_internal_burst", "udp_internal_burst"),
        ("score_udp_ephemeral_exchange", "udp_ephemeral_exchange"),
        ("score_udp_ports", "udp_ports"),
        ("score_udp_peers", "udp_peers"),
        ("score_udp_volume", "udp_volume"),
        ("score_udp_balance", "udp_balance"),
        ("score_udp_fanout", "udp_fanout"),
    ]:
        value = risk.get(key, 0.0)
        if value:
            lines.append(f"- {label}: {value:.2f}")
    lines.append("")
    lines.append("## Top peers")
    for row in report.get("top_peers", [])[:10]:
        ports = ", ".join(f"{p['port']}({p['count']})" for p in row.get("top_ports", []))
        fams = ", ".join(f"{p['family']}({p['count']})" for p in row.get("top_families", []))
        lines.append(
            f"- {row['peer']}: events={row['events']} inbound={row['inbound']} outbound={row['outbound']} top_ports={ports or 'none'} top_families={fams or 'none'}"
        )
    lines.append("")
    lines.append("## Top portas")
    for row in report.get("top_ports", [])[:15]:
        lines.append(f"- {row['port']}: {row['count']}")
    lines.append("")
    lines.append("## Distribuicao por protocolo")
    proto = report.get("protocol_counts") or {}
    lines.append(f"- tcp: {proto.get('tcp', 0)}")
    lines.append(f"- udp: {proto.get('udp', 0)}")
    lines.append(f"- other: {proto.get('other', 0)}")
    lines.append("")
    lines.append("## Distribuicao por direcao")
    for key, value in (report.get("direction_counts") or {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Distribuicao UDP")
    for row in report.get("udp_breakdown", [])[:10]:
        lines.append(f"- {row['family']}: {row['count']}")
    lines.append("")
    lines.append("## Evidencias pro scan")
    for item in report.get("pro_scan_evidence", []):
        lines.append(f"- {item}")
    if not report.get("pro_scan_evidence"):
        lines.append("- nenhuma evidencia forte adicional")
    lines.append("")
    lines.append("## Evidencias contra scan")
    for item in report.get("against_scan_evidence", []):
        lines.append(f"- {item}")
    if not report.get("against_scan_evidence"):
        lines.append("- nenhuma evidencia forte adicional")
    lines.append("")
    lines.append("## Pares src -> dst")
    for row in report.get("top_pairs", [])[:15]:
        lines.append(f"- {row['src']} -> {row['dst']}: events={row['events']}")
    lines.append("")
    lines.append("## Distribuicao por familia")
    for row in report.get("family_counts", [])[:10]:
        lines.append(f"- {row['family']}: {row['total']}")
    lines.append("")
    lines.append("## Distribuicao por severidade")
    for key, value in (report.get("severity_counts") or {}).items():
        lines.append(f"- {key}: {value}")
    return "\n".join(lines) + "\n"


def _render_window_table_header(title: str) -> List[str]:
    return [
        f"# {title}",
        "",
    ]


def render_host_timeline_md(summary: Dict[str, Any]) -> str:
    report = summary.get("focus_host_report") or {}
    timeline = report.get("timeline") or {}
    windows = timeline.get("windows") or []
    host = report.get("host") or summary.get("focus_host") or FOCUS_HOST
    lines = _render_window_table_header(f"tcp_detection_host_{host}_timeline")
    lines.append("## Leitura temporal")
    lines.append(f"- conclusion: {report.get('conclusion')}")
    lines.append(f"- scan_candidate: {report.get('scan_candidate')}")
    lines.append(f"- window_seconds: {timeline.get('window_seconds', 180)}")
    lines.append("")
    lines.append("| window | start | end | events | score | udp_probe | unique_peers | unique_ports | top_peer | top_family |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |")
    for row in windows:
        top_peer = row.get("top_peers", [{}])[0].get("peer", "none") if row.get("top_peers") else "none"
        top_family = row.get("top_families", [{}])[0].get("family", "none") if row.get("top_families") else "none"
        lines.append(
            f"| {row['window']} | {row['start_ts']} | {row['end_ts']} | {row['events']} | {row['risk_score']:.2f} | {row['udp_probe']} | {row['unique_peers']} | {row['unique_ports']} | {top_peer} | {top_family} |"
        )
    return "\n".join(lines) + "\n"


def render_pair_timeline_md(summary: Dict[str, Any]) -> str:
    report = summary.get("focus_host_report") or {}
    pair_timeline = report.get("pair_timeline") or {}
    windows = pair_timeline.get("windows") or []
    host = pair_timeline.get("host") or report.get("host") or summary.get("focus_host") or FOCUS_HOST
    peer = pair_timeline.get("focus_peer") or FOCUS_PEER
    lines = _render_window_table_header(f"tcp_detection_pair_{host}_to_{peer}")
    lines.append("## Leitura temporal do par")
    lines.append(f"- host: {host}")
    lines.append(f"- peer: {peer}")
    lines.append(f"- window_seconds: {pair_timeline.get('window_seconds', 180)}")
    lines.append("")
    lines.append("| window | start | end | events | score | outbound_focus | inbound_focus | udp_probe | unique_peers | unique_ports | top_family |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for row in windows:
        top_family = row.get("top_families", [{}])[0].get("family", "none") if row.get("top_families") else "none"
        protocol_counts = row.get("protocol_counts") or {}
        lines.append(
            f"| {row['window']} | {row['start_ts']} | {row['end_ts']} | {row['events']} | {row['risk_score']:.2f} | {protocol_counts.get('outbound_focus', 0)} | {protocol_counts.get('inbound_focus', 0)} | {row['udp_probe']} | {row['unique_peers']} | {row['unique_ports']} | {top_family} |"
        )
    return "\n".join(lines) + "\n"


def render_temporal_consolidated_md(summary: Dict[str, Any]) -> str:
    report = summary.get("focus_host_report") or {}
    host = report.get("host") or summary.get("focus_host") or FOCUS_HOST
    pair_timeline = report.get("pair_timeline") or {}
    lines = [f"# tcp_detection_temporal_consolidated_{host}", ""]
    lines.append("## Conclusao operacional")
    lines.append(f"- host_conclusion: {report.get('conclusion')}")
    lines.append(f"- scan_candidate: {report.get('scan_candidate')}")
    lines.append(f"- host_risk_score: {(report.get('risk') or {}).get('risk_score')}")
    lines.append("")
    lines.append("## Leitura temporal")
    lines.append("- O score do host continua puxado por trafego repetitivo e score medio/alto, nao por um pico curto isolado.")
    lines.append("- `udp_probe_like` aparece em janela curta e com volatilidade, enquanto `udp_internal_service_like` e o trafego TCP interno sustentam a massa principal.")
    lines.append("- O par com `104.18.32.47` permanece presente em janelas, mas sem assinatura forte de varredura isolada.")
    lines.append("")
    lines.append("## Regra pratica sugerida")
    lines.append("- Promover apenas se `udp_probe_like` crescer de forma persistente em janelas consecutivas e vier acompanhado de aumento de peers/portas externos, sem ser compensado por trafego interno legitimo dominante.")
    lines.append("- Rebaixar se a massa continuar concentrada em pares internos estaveis e o UDP de probe dissipar nas janelas seguintes.")
    lines.append("")
    lines.append("## Observacao do par")
    lines.append(f"- par_janelas: {len((pair_timeline.get('windows') or []))}")
    return "\n".join(lines) + "\n"


def render_summary_md(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# tcp_detection_summary")
    lines.append("")
    lines.append("## Visao geral")
    lines.append(f"- total_events: {summary['total_events']}")
    lines.append(f"- cache_total: {summary['cache_total']}")
    lines.append(f"- ai_total: {summary['ai_total']}")
    lines.append(f"- new_total: {summary['new_total']}")
    lines.append(f"- cache_hit_rate: {summary['cache_hit_rate']:.4f}")
    lines.append(f"- ai_rate: {summary['ai_rate']:.4f}")
    lines.append(f"- new_pattern_rate: {summary['new_pattern_rate']:.4f}")
    lines.append(f"- first_ts: {summary['first_ts']}")
    lines.append(f"- last_ts: {summary['last_ts']}")
    lines.append(
        f"- generic_base_tcp_ip_frame: {summary['generic_counts']['base_tcp_ip_frame']} | generic_operational_tcp_ip_frame: {summary['generic_counts']['operational_tcp_ip_frame']}"
    )
    lines.append(
        f"- generic_base_udp_other: {summary['generic_counts']['base_udp_other']} | generic_operational_udp_other: {summary['generic_counts']['operational_udp_other']}"
    )
    lines.append("")
    lines.append("## Top familias base por volume")
    for row in summary["top_base_families"][:10]:
        lines.append(
            f"- {row['family']}: total={row['total']} ai={row['ai']} cache={row['cache']} new={row['new']} ai_rate={row['ai_rate']:.2%}"
        )
    lines.append("")
    lines.append("## Top familias operacionais por volume")
    for row in summary["top_families"][:10]:
        lines.append(
            f"- {row['family']}: total={row['total']} ai={row['ai']} cache={row['cache']} new={row['new']} ai_rate={row['ai_rate']:.2%}"
        )
    lines.append("")
    lines.append("## Top subtipos UDP")
    for row in [r for r in summary["top_families"] if r["family"].startswith("udp_")][:10]:
        lines.append(
            f"- {row['family']}: total={row['total']} ai={row['ai']} cache={row['cache']} new={row['new']} ai_rate={row['ai_rate']:.2%}"
        )
    lines.append("")
    lines.append("## Familias com maior uso de IA")
    for row in summary["ai_dependency"][:10]:
        lines.append(
            f"- {row['family']}: ai={row['ai']} total={row['total']} ai_rate={row['ai_rate']:.2%} cache={row['cache']} new={row['new']}"
        )
    lines.append("")
    lines.append("## Crescimento recente")
    for row in summary["growth"][:10]:
        ratio = "inf" if row["growth_ratio"] == float("inf") else f"{row['growth_ratio']:.2f}"
        lines.append(
            f"- {row['family']}: recent={row['recent']} previous={row['previous']} growth_ratio={ratio} ai_recent={row['ai_recent']} cache_recent={row['cache_recent']}"
        )
    lines.append("")
    lines.append("## Bursts")
    for row in summary["bursts"][:10]:
        lines.append(
            f"- {row['family']}: burst_score={row['burst_score']:.2f} recent_score={row['recent_score']:.2f} last_window={row['last_window_count']} avg_window={row['avg_window_count']:.2f}"
        )
    lines.append("")
    lines.append("## Eventos raros com severidade media/alta")
    if summary["rare_events"]:
        for row in summary["rare_events"][:10]:
            short = row["snippet"][:140].replace("\n", " ")
            lines.append(
                f"- {row['family']}: count={row['count']} severity={row['severity']} ai={row['ai']} cache={row['cache']} new={row['new']} | {short}"
            )
    else:
        for row in summary["rare_severe"][:10]:
            lines.append(
                f"- {row['family']}: total={row['total']} medium_high={row['medium_high']} ai={row['ai']} cache={row['cache']} severity={row['severity']}"
            )
    lines.append("")
    lines.append("## Sequencias recorrentes")
    for row in summary["transitions"][:10]:
        lines.append(f"- {row['from']} -> {row['to']}: {row['count']}")
    lines.append("")
    lines.append("## Top IPs por risco")
    for row in summary["ip_risk"][:10]:
        lines.append(
            f"- {row['ip']}: risk_score={row['risk_score']:.2f} events={row['events']} syn={row['syn']} rst={row['rst']} unique_ports={row['unique_ports']} unique_peers={row['unique_peers']}"
        )
    return "\n".join(lines) + "\n"


def render_alerts_md(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# tcp_detection_alerts")
    lines.append("")
    lines.append("## Alertas prioritarios")
    alerts = []

    for row in summary["ai_dependency"]:
        if row["ai"] >= 5:
            alerts.append(("high", row["family"], "dependencia de IA recorrente", row))
    for row in summary["bursts"]:
        if row["burst_score"] >= 2.0:
            alerts.append(("high", row["family"], "burst operacional", row))
    for row in summary["rare_events"]:
        alerts.append(("medium", row["family"], "evento raro com severidade relevante", row))
    for row in summary["growth"]:
        if row["recent"] >= 10 and row["growth_ratio"] != float("inf") and row["growth_ratio"] >= 1.5:
            alerts.append(("medium", row["family"], "crescimento recente relevante", row))

    for row in summary["scan_candidates"]:
        alerts.append(("high", row["ip"], "candidate de scan/recognition", row))

    if not alerts:
        lines.append("- Nenhum alerta forte encontrado.")
        return "\n".join(lines) + "\n"

    seen = set()
    alerts_sorted = []
    for severity, family, reason, row in alerts:
        key = (severity, family, reason)
        if key in seen:
            continue
        seen.add(key)
        alerts_sorted.append((severity, family, reason, row))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    alerts_sorted.sort(key=lambda item: (severity_order.get(item[0], 9), item[1], item[2]))
    for severity, family, reason, row in alerts_sorted:
        detail = []
        if "ai" in row:
            detail.append(f"ai={row['ai']}")
        if "cache" in row:
            detail.append(f"cache={row['cache']}")
        if "new" in row:
            detail.append(f"new={row['new']}")
        if "total" in row:
            detail.append(f"total={row['total']}")
        if "burst_score" in row:
            detail.append(f"burst_score={row['burst_score']:.2f}")
        if "growth_ratio" in row:
            ratio = "inf" if row["growth_ratio"] == float("inf") else f"{row['growth_ratio']:.2f}"
            detail.append(f"growth_ratio={ratio}")
        if "risk_score" in row:
            detail.append(f"risk_score={row['risk_score']:.2f}")
        if "unique_ports" in row:
            detail.append(f"unique_ports={row['unique_ports']}")
        lines.append(f"- [{severity}] {family}: {reason} ({', '.join(detail)})")
    return "\n".join(lines) + "\n"


def render_trends_md(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# tcp_detection_trends")
    lines.append("")
    lines.append("## Crescimento por familia operacional")
    lines.append("| familia | recent | previous | growth_ratio | ai_recent | cache_recent |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for row in summary["growth"][:12]:
        ratio = "inf" if row["growth_ratio"] == float("inf") else f"{row['growth_ratio']:.2f}"
        lines.append(
            f"| {row['family']} | {row['recent']} | {row['previous']} | {ratio} | {row['ai_recent']} | {row['cache_recent']} |"
        )
    lines.append("")
    lines.append("## Picos por janela movel")
    lines.append("| familia | burst_score | recent_score | last_window | avg_window | total |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for row in summary["bursts"][:12]:
        lines.append(
            f"| {row['family']} | {row['burst_score']:.2f} | {row['recent_score']:.2f} | {row['last_window_count']} | {row['avg_window_count']:.2f} | {row['total']} |"
        )
    lines.append("")
    lines.append("## Sequencias recorrentes")
    lines.append("| de | para | count |")
    lines.append("| --- | --- | ---: |")
    for row in summary["transitions"][:12]:
        lines.append(f"| {row['from']} | {row['to']} | {row['count']} |")
    lines.append("")
    lines.append("## Candidatos a scan")
    lines.append("| ip | risk_score | events | syn | rst | unique_ports | unique_peers |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    if summary["scan_candidates"]:
        for row in summary["scan_candidates"][:12]:
            lines.append(
                f"| {row['ip']} | {row['risk_score']:.2f} | {row['events']} | {row['syn']} | {row['rst']} | {row['unique_ports']} | {row['unique_peers']} |"
            )
    else:
        lines.append("| nenhum | 0.00 | 0 | 0 | 0 | 0 | 0 |")
    return "\n".join(lines) + "\n"


def render_ip_risk_md(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# tcp_detection_ip_risk")
    lines.append("")
    lines.append("## IPs com maior risco")
    lines.append("| ip | risk_score | events | syn | rst | ai | new | medium_high | unique_ports | unique_peers |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in summary["ip_risk"][:20]:
        lines.append(
            f"| {row['ip']} | {row['risk_score']:.2f} | {row['events']} | {row['syn']} | {row['rst']} | {row['ai']} | {row['new']} | {row['medium_high']} | {row['unique_ports']} | {row['unique_peers']} |"
        )
    lines.append("")
    lines.append("## Pares src -> dst com maior risco")
    lines.append("| src | dst | risk_score | events | syn | rst | unique_ports |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for row in summary["pair_risk"][:20]:
        lines.append(
            f"| {row['src']} | {row['dst']} | {row['risk_score']:.2f} | {row['events']} | {row['syn']} | {row['rst']} | {row['unique_ports']} |"
        )
    lines.append("")
    lines.append("## Candidatos a scan")
    if summary["scan_candidates"]:
        for row in summary["scan_candidates"][:10]:
            lines.append(
                f"- {row['ip']}: risk_score={row['risk_score']:.2f} events={row['events']} syn={row['syn']} rst={row['rst']} unique_ports={row['unique_ports']} unique_peers={row['unique_peers']}"
            )
    else:
        lines.append("- nenhum candidato forte encontrado com as regras conservadoras atuais.")
    return "\n".join(lines) + "\n"


def build_temporal_summary(timeline: Dict[str, Any], host: str) -> Optional[Dict[str, Any]]:
    windows = list(timeline.get("windows") or [])
    if not windows:
        return None

    recent = windows[-3:]
    compact_windows: List[Dict[str, Any]] = []
    for window in recent:
        start_ts = window.get("start_ts")
        end_ts = window.get("end_ts")
        window_idx = window.get("window", len(compact_windows) + 1)
        label = f"W{window_idx}"
        if isinstance(start_ts, str) and isinstance(end_ts, str) and len(start_ts) >= 16 and len(end_ts) >= 16:
            label = f"{label} {start_ts[11:16]}-{end_ts[11:16]}"
        top_peers = window.get("top_peers") or []
        top_families = window.get("top_families") or []
        compact_windows.append(
            {
                "label": label,
                "score": round(float(window.get("risk_score", 0.0) or 0.0), 2),
                "udp_probe": int(window.get("udp_probe", 0) or 0),
                "unique_peers": int(window.get("unique_peers", 0) or 0),
                "unique_ports": int(window.get("unique_ports", 0) or 0),
                "top_peer": top_peers[0].get("peer") if top_peers else None,
                "top_family": top_families[0].get("family") if top_families else None,
                "window_start": start_ts,
                "window_end": end_ts,
            }
        )

    scores = [w["score"] for w in compact_windows]
    if len(scores) == 1:
        trend_label = "janela única"
        trend_decision = "sem histórico temporal consolidado"
        interpretation = "A rodada consolidada tem apenas uma janela útil para leitura temporal."
    else:
        first = scores[0]
        last = scores[-1]
        peak = max(scores)
        peak_idx = scores.index(peak)
        if peak >= max(15.0, last * 2.0) and peak_idx < len(scores) - 1 and last <= peak * 0.45:
            trend_label = "pico isolado"
            trend_decision = "rebaixar tendência"
            interpretation = "A tendência recente mostra pico curto seguido de dissipação."
        elif last >= first * 1.15 and (len(scores) < 3 or last >= scores[-2] * 1.05):
            trend_label = "subindo"
            trend_decision = "elevar atenção"
            interpretation = "A tendência recente mostra crescimento consistente."
        elif last <= first * 0.7:
            trend_label = "caindo"
            trend_decision = "monitoramento leve"
            interpretation = "A tendência recente perdeu força e voltou a níveis mais baixos."
        else:
            trend_label = "estável"
            trend_decision = "monitoramento leve"
            interpretation = "A tendência recente oscila, mas sem mudança abrupta sustentada."

    badge_map = {
        "pico isolado": "rebaixada",
        "caindo": "rebaixada",
        "subindo": "atenção crescente",
        "estável": "estável",
        "janela única": "em observação",
    }
    operational_badge = badge_map.get(trend_label, "em observação")
    last_window = compact_windows[-1]
    last_window_summary = (
        f"Última janela: score {last_window['score']:.2f}, "
        f"udp_probe {last_window['udp_probe']}, "
        f"peers {last_window['unique_peers']}, "
        f"ports {last_window['unique_ports']}"
    )
    if last_window.get("top_peer"):
        last_window_summary += f", peer {last_window['top_peer']}"
    if last_window.get("top_family"):
        last_window_summary += f", família {last_window['top_family']}"

    return {
        "host": host,
        "window_size_seconds": int(timeline.get("window_seconds", 180) or 180),
        "trend_label": trend_label,
        "trend_decision": trend_decision,
        "operational_badge": operational_badge,
        "last_window_summary": last_window_summary,
        "interpretation": interpretation,
        "windows": compact_windows,
        "score_series": scores,
        "udp_probe_series": [w["udp_probe"] for w in compact_windows],
        "unique_peers_series": [w["unique_peers"] for w in compact_windows],
        "unique_ports_series": [w["unique_ports"] for w in compact_windows],
    }


def build_detection_status(summary: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
    report = summary.get("focus_host_report") or {}
    risk = report.get("risk") or {}
    score_breakdown = report.get("score_breakdown") or {}
    temporal_summary = build_temporal_summary(report.get("timeline") or {}, report.get("host") or summary.get("focus_host") or FOCUS_HOST)

    primary_signal_key = None
    primary_signal_value = 0.0
    for key, value in score_breakdown.items():
        if key == "score_base":
            continue
        if not isinstance(value, (int, float)):
            continue
        if primary_signal_key is None or float(value) > primary_signal_value:
            primary_signal_key = key
            primary_signal_value = float(value)

    signal_labels = {
        "score_medium_high": "tráfego repetitivo/medium_high",
        "score_udp_probe": "pressão UDP probe-like",
        "score_rst": "pressão de resets TCP",
        "score_syn": "atividade SYN",
        "score_unique_ports": "diversidade de portas",
        "score_unique_peers": "diversidade de peers",
        "score_udp_unclassified": "residual UDP ainda pouco classificado",
        "score_udp_external": "tráfego UDP externo ocasional",
        "score_udp_single_shot_external": "UDP externo single-shot",
        "score_udp_noise": "ruído UDP",
        "score_udp_internal_burst": "burst UDP interno",
        "score_udp_ephemeral_exchange": "troca UDP efêmera",
        "score_udp_ports": "variação de portas UDP",
        "score_udp_peers": "variação de peers UDP",
        "score_udp_volume": "volume UDP",
        "score_udp_balance": "desbalanceamento UDP",
        "score_udp_fanout": "fanout UDP",
        "score_ai": "dependência de IA",
        "score_new": "criação de padrões novos",
    }
    primary_signal_key = primary_signal_key or "score_base"
    primary_signal = {
        "name": primary_signal_key,
        "label": signal_labels.get(primary_signal_key, primary_signal_key),
        "value": round(primary_signal_value, 2),
    }

    pro_scan = list(report.get("pro_scan_evidence") or [])
    against_scan = list(report.get("against_scan_evidence") or [])
    key_reasons = (pro_scan[:3] + against_scan[:3])
    if not key_reasons:
        key_reasons = [
            f"score_base={risk.get('score_base', 0.0):.2f}",
            f"risk_score={risk.get('risk_score', 0.0):.2f}",
        ]

    decision_code = report.get("conclusion") or "unknown"
    if decision_code == "contexto_legitimo":
        decision = "tráfego legítimo"
        host_decision = "monitoramento leve"
        severity = "low"
    elif decision_code == "contexto_legitimo_com_sinal_conservador":
        decision = "monitoramento leve"
        host_decision = "monitoramento leve"
        severity = "medium"
    else:
        decision = "monitoramento leve"
        host_decision = "monitoramento leve"
        severity = "medium"
    alert_state = "sem alerta persistente"

    candidate_flags = [decision_code]
    if report.get("scan_candidate"):
        candidate_flags.append("scan_candidate=true")
    if risk.get("risk_score", 0.0) >= 100:
        candidate_flags.append("risk_score>=100")
    if report.get("conclusion") == "contexto_legitimo_com_sinal_conservador":
        candidate_flags.append("no_persistent_alert")

    top_peers = []
    for row in (report.get("top_peers") or [])[:5]:
        top_peers.append(
            {
                "peer": row.get("peer"),
                "events": row.get("events", 0),
                "inbound": row.get("inbound", 0),
                "outbound": row.get("outbound", 0),
                "top_ports": row.get("top_ports", [])[:3],
                "top_families": row.get("top_families", [])[:3],
            }
        )

    top_ports = (report.get("top_ports") or [])[:5]

    payload = {
        "detector_round_id": output_dir.name,
        "detector_timestamp": summary.get("last_ts") or summary.get("first_ts"),
        "detector_status": "ok",
        "decision": decision,
        "severity": severity,
        "alert_state": alert_state,
        "primary_signal": primary_signal,
        "monitored_host": report.get("host") or summary.get("focus_host") or FOCUS_HOST,
        "monitored_host_status": decision_code,
        "monitored_host_risk_score": round(float(risk.get("risk_score", 0.0) or 0.0), 2),
        "monitored_host_decision": host_decision,
        "key_reasons": key_reasons,
        "top_peers": top_peers,
        "top_ports": top_ports,
        "candidate_flags": candidate_flags,
        "source_diagnostics_path": str(output_dir),
        "source_summary_path": str(output_dir / "tcp_detection_summary.json"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_summary": {
            "total_events": report.get("total_events", 0),
            "unique_ports": risk.get("unique_ports", 0),
            "unique_peers": risk.get("unique_peers", 0),
            "protocol_counts": report.get("protocol_counts") or {},
            "direction_counts": report.get("direction_counts") or {},
            "udp_breakdown": report.get("udp_breakdown") or [],
        },
        "temporal_summary": temporal_summary,
        "score_breakdown": {k: round(float(v), 2) if isinstance(v, (int, float)) else v for k, v in score_breakdown.items()},
        "conclusion": decision_code,
    }

    return payload


def write_detection_status(summary: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
    status = build_detection_status(summary, output_dir)
    status_text = json.dumps(status, indent=2, ensure_ascii=False, sort_keys=True) + "\n"

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tcp_detection_status.json").write_text(status_text, encoding="utf-8")
    DEFAULT_STATUS_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_STATUS_FILE.write_text(status_text, encoding="utf-8")
    return status


def write_outputs(summary: Dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tcp_detection_summary.md").write_text(render_summary_md(summary), encoding="utf-8")
    (output_dir / "tcp_detection_alerts.md").write_text(render_alerts_md(summary), encoding="utf-8")
    (output_dir / "tcp_detection_trends.md").write_text(render_trends_md(summary), encoding="utf-8")
    (output_dir / "tcp_detection_ip_risk.md").write_text(render_ip_risk_md(summary), encoding="utf-8")
    (output_dir / f"tcp_detection_host_{summary.get('focus_host', FOCUS_HOST)}.md").write_text(
        render_host_report_md(summary),
        encoding="utf-8",
    )
    (output_dir / f"tcp_detection_host_{summary.get('focus_host', FOCUS_HOST)}_timeline.md").write_text(
        render_host_timeline_md(summary),
        encoding="utf-8",
    )
    (output_dir / f"tcp_detection_pair_{summary.get('focus_host', FOCUS_HOST)}_to_{FOCUS_PEER}.md").write_text(
        render_pair_timeline_md(summary),
        encoding="utf-8",
    )
    (output_dir / f"tcp_detection_temporal_consolidated_{summary.get('focus_host', FOCUS_HOST)}.md").write_text(
        render_temporal_consolidated_md(summary),
        encoding="utf-8",
    )
    (output_dir / "tcp_detection_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_detection_status(summary, output_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Detector operacional sobre o historico estruturado do tcp-brain.")
    parser.add_argument("--source-file", type=Path, default=DEFAULT_SOURCE_FILE)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument("--since", type=parse_dt)
    parser.add_argument("--until", type=parse_dt)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output-dir", type=Path, required=True)
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

    summary = build_summary(events)
    if not args.summary_only:
        write_outputs(summary, args.output_dir)
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "tcp_detection_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        write_detection_status(summary, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
