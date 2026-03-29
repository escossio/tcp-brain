#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, json, time, hashlib, logging, psycopg2, requests
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from psycopg2.extras import RealDictCursor, Json
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from tcp_history import HISTORY_WRITER, build_history_event

try:
    from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
    PROM_ENABLED = True
except:
    PROM_ENABLED = False

# Config
DB_DSN = os.getenv("TCP_BRAIN_DB_DSN", "")
DB_PASS = os.getenv("TCP_BRAIN_DB_PASSWORD", os.getenv("TCP_BRAIN_DB_PASS", "")).strip().strip("'\"")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip().strip("'\"")
UPSTREAM_URL = os.getenv("TCP_BRAIN_UPSTREAM_URL", "https://api.openai.com/v1/chat/completions" )
UPSTREAM_MODEL = os.getenv("TCP_BRAIN_UPSTREAM_MODEL", "gpt-4.1-mini-2025-04-14")
COST_PER_CALL = float(os.getenv("TCP_BRAIN_COST_PER_IA_CALL_BRL", "0.01"))

app = FastAPI(title="TCP Brain")
log = logging.getLogger("tcp-brain")
logging.basicConfig(level=logging.INFO)

FRONTEND_CANDIDATES = [
    Path(__file__).resolve().parent / "public" / "tcp-brain",
    Path("/srv/escossio-site/public/tcp-brain"),
    Path("/var/www/html/tcp-brain"),
    Path("/srv/tcp/public/explainer"),
    Path("/srv/tcp/explainer"),
]

DETECTION_STATUS_DIR = Path("/srv/tcp/knowledge/detection")
DETECTION_STATUS_FILE = DETECTION_STATUS_DIR / "tcp_detection_status.json"
DETECTION_DIAGNOSTICS_ROOT = Path("/codex/diagnostics")


def resolve_frontend_dir() -> Optional[Path]:
    for candidate in FRONTEND_CANDIDATES:
        if (candidate / "index.html").exists():
            return candidate
    return None


FRONTEND_DIR = resolve_frontend_dir()

# Habilita CORS para o frontend modular
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def db_conn():
    if DB_DSN:
        if DB_PASS: return psycopg2.connect(DB_DSN, password=DB_PASS, connect_timeout=3)
        return psycopg2.connect(DB_DSN, connect_timeout=3)
    return psycopg2.connect(
        host=os.getenv("TCP_BRAIN_DB_HOST", "127.0.0.1"),
        port=int(os.getenv("TCP_BRAIN_DB_PORT", "5432")),
        dbname=os.getenv("TCP_BRAIN_DB_NAME", "tcp_brain"),
        user=os.getenv("TCP_BRAIN_DB_USER", "tcp_brain"),
        password=DB_PASS,
        connect_timeout=3
    )

def _choose_latest_detection_source() -> Optional[Path]:
    candidates: List[Path] = []
    if DETECTION_STATUS_FILE.exists():
        return DETECTION_STATUS_FILE

    for root in (DETECTION_STATUS_DIR, DETECTION_DIAGNOSTICS_ROOT):
        if not root.exists():
            continue
        for name in ("tcp_detection_status.json", "tcp_detection_summary.json"):
            for path in root.rglob(name):
                if path.is_file():
                    candidates.append(path)

    if not candidates:
        return None
    candidates = list({str(path): path for path in candidates}.values())
    return max(candidates, key=lambda path: (path.stat().st_mtime, path.as_posix()))


def _build_detection_status_from_summary(summary: Dict[str, Any], source_path: Path) -> Dict[str, Any]:
    report = summary.get("focus_host_report") or {}
    risk = report.get("risk") or {}
    score_breakdown = report.get("score_breakdown") or {}
    primary_signal_key = None
    primary_signal_value = 0.0
    for key, value in score_breakdown.items():
        if key == "score_base" or not isinstance(value, (int, float)):
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

    pro_scan = list(report.get("pro_scan_evidence") or [])
    against_scan = list(report.get("against_scan_evidence") or [])
    key_reasons = (pro_scan[:3] + against_scan[:3]) or [
        f"score_base={risk.get('score_base', 0.0):.2f}",
        f"risk_score={risk.get('risk_score', 0.0):.2f}",
    ]

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

    temporal_summary = None
    timeline = report.get("timeline") or {}
    windows = list(timeline.get("windows") or [])
    if windows:
        recent = windows[-3:]
        compact_windows = []
        for window in recent:
            start_ts = window.get("start_ts")
            end_ts = window.get("end_ts")
            window_idx = window.get("window", len(compact_windows) + 1)
            label = f"W{window_idx}"
            if isinstance(start_ts, str) and isinstance(end_ts, str) and len(start_ts) >= 16 and len(end_ts) >= 16:
                label = f"{label} {start_ts[11:16]}-{end_ts[11:16]}"
            top_peers_w = window.get("top_peers") or []
            top_families_w = window.get("top_families") or []
            compact_windows.append(
                {
                    "label": label,
                    "score": round(float(window.get("risk_score", 0.0) or 0.0), 2),
                    "udp_probe": int(window.get("udp_probe", 0) or 0),
                    "unique_peers": int(window.get("unique_peers", 0) or 0),
                    "unique_ports": int(window.get("unique_ports", 0) or 0),
                    "top_peer": top_peers_w[0].get("peer") if top_peers_w else None,
                    "top_family": top_families_w[0].get("family") if top_families_w else None,
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

        temporal_summary = {
            "host": report.get("host") or summary.get("focus_host") or "10.45.0.2",
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

    payload = {
        "detector_round_id": source_path.parent.parent.name if source_path.name == "tcp_detection_summary.json" else source_path.parent.name,
        "detector_timestamp": summary.get("last_ts") or summary.get("first_ts"),
        "detector_status": "ok",
        "decision": decision,
        "severity": severity,
        "alert_state": alert_state,
        "primary_signal": primary_signal,
        "monitored_host": report.get("host") or summary.get("focus_host") or "10.45.0.2",
        "monitored_host_status": decision_code,
        "monitored_host_risk_score": round(float(risk.get("risk_score", 0.0) or 0.0), 2),
        "monitored_host_decision": host_decision,
        "key_reasons": key_reasons,
        "top_peers": top_peers,
        "top_ports": (report.get("top_ports") or [])[:5],
        "candidate_flags": candidate_flags,
        "source_diagnostics_path": str(source_path.parent.parent if source_path.name == "tcp_detection_summary.json" else source_path.parent),
        "source_summary_path": str(source_path if source_path.name == "tcp_detection_summary.json" else source_path.with_name("tcp_detection_summary.json")),
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


def load_latest_detection_status() -> Optional[Dict[str, Any]]:
    source = _choose_latest_detection_source()
    if not source:
        return None
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error(f"Falha ao ler status de deteccao de {source}: {exc}")
        return None

    if isinstance(payload, dict) and payload.get("detector_status") and payload.get("monitored_host"):
        return payload
    if isinstance(payload, dict):
        try:
            return _build_detection_status_from_summary(payload, source)
        except Exception as exc:
            log.error(f"Falha ao derivar status de deteccao de {source}: {exc}")
            return None
    return None

def ensure_schema():
    sql = """
    CREATE TABLE IF NOT EXISTS tcp_brain_counters (
        id INTEGER PRIMARY KEY, total_requests BIGINT DEFAULT 0, cache_hits BIGINT DEFAULT 0, 
        ia_calls BIGINT DEFAULT 0, last_updated TIMESTAMP WITH TIME ZONE DEFAULT now()
    );
    INSERT INTO tcp_brain_counters (id) VALUES (1) ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS tcp_patterns (
        pattern_hash TEXT PRIMARY KEY, snippet TEXT, explanation TEXT, 
        severity TEXT DEFAULT 'unknown', tags JSONB DEFAULT '[]'::jsonb, 
        hit_count INTEGER DEFAULT 1, last_seen TIMESTAMP WITH TIME ZONE DEFAULT now()
    );
    """
    try:
        with db_conn() as conn:
            with conn.cursor() as cur: cur.execute(sql)
    except Exception as e: log.error(f"Falha ao garantir schema: {e}")

def canonicalize_snippet(s: str) -> str:
    s = re.sub(r"(\d{1,3}(?:\.\d{1,3}){3})[\.:](\d{1,5})", r"<host>.<port>", s)
    s = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "<host>", s)
    s = re.sub(r"\b\d{5,}\b", "<id>", s)
    return s.strip()


def _bucket_length(length: int) -> str:
    if length == 0:
        return "[0]"
    if length <= 63:
        return "[1-63]"
    if length <= 255:
        return "[64-255]"
    if length <= 511:
        return "[256-511]"
    return "[512+]"


def normalize_operational_family(snippet: str) -> tuple[str, Optional[str]]:
    """Normaliza apenas famílias operacionais dominantes detectadas pelo GAP ENGINE.

    O objetivo é reduzir variação de cksum/seq/ack/win/TS val/length sem colapsar
    assinaturas estruturalmente diferentes.
    """
    family_rule: Optional[str] = None
    normalized = snippet

    if (
        "Flags [P.]" in snippet
        and "options [nop,nop,TS val" in snippet
        and "ack " in snippet
        and "seq " in snippet
    ):
        family_rule = "tcp_family_flags_p"
    elif (
        "Flags [.]" in snippet
        and "options [nop,nop,TS val" in snippet
        and "ack " in snippet
        and "seq " in snippet
    ):
        family_rule = "tcp_family_flags_ack"
    elif (
        "Flags [F.]" in snippet
        and "options [nop,nop,TS val" in snippet
        and "ack " in snippet
        and "seq " in snippet
    ):
        family_rule = "tcp_family_flags_fin"
    elif (
        "Flags [S.]" in snippet
        and "options [mss " in snippet
        and "sackOK,TS val" in snippet
        and "wscale 7" in snippet
        and "ack " in snippet
    ):
        family_rule = "tcp_family_flags_synack"
    elif (
        "Flags [S]" in snippet
        and "options [mss " in snippet
        and "sackOK,TS val" in snippet
        and "ecr 0" in snippet
        and "wscale 7" in snippet
    ):
        family_rule = "tcp_family_flags_syn"
    elif "Flags [R.]" in snippet or "Flags [R]" in snippet:
        family_rule = "tcp_family_flags_rst"
    elif "proto TCP (6)" in snippet and "length 52" in snippet and "flags [DF]" in snippet:
        family_rule = "tcp_family_len52"

    if family_rule:
        normalized = re.sub(r"cksum 0x[0-9a-f]+ \(incorrect -> 0x[0-9a-f]+\)", "cksum <cksum>", normalized)
        normalized = re.sub(r"cksum 0x[0-9a-f]+ \(correct\)", "cksum <cksum>", normalized)
        normalized = re.sub(r"seq [^, ]+(?::[^, ]+)?", "seq <seq>", normalized)
        normalized = re.sub(r"ack [^, ]+", "ack <ack>", normalized)
        normalized = re.sub(r"win \d+", "win <win>", normalized)
        normalized = re.sub(r"mss \d+", "mss <mss>", normalized)
        normalized = re.sub(r"wscale \d+", "wscale <wscale>", normalized)
        normalized = re.sub(r"TS val \d+ ecr \d+", "TS val <ts> ecr <ts>", normalized)
        if family_rule == "tcp_family_len52":
            normalized = re.sub(r"\bttl \d+\b", "ttl <ttl>", normalized)
            normalized = re.sub(r"\bid \d+\b", "id <id>", normalized)

        def _replace_length(match: re.Match[str]) -> str:
            return f"length {_bucket_length(int(match.group(1)))}"

        normalized = re.sub(r"length (\d+)", _replace_length, normalized)

    return normalized.strip(), family_rule


def _record_history_event(
    *,
    raw_input: str,
    canon: str,
    pattern_hash: str,
    cache_hit: bool,
    created_new_pattern: bool,
    used_ai: bool,
    response_mode: str,
    severity: str = "unknown",
    existing_pattern_id: Optional[str] = None,
    family_rule: Optional[str] = None,
    http_status: Optional[int] = None,
) -> None:
    event = build_history_event(
        endpoint="/api/tcp-explain",
        method="POST",
        source="tcp-brain",
        raw_input=raw_input,
        canonical_snippet=canon,
        pattern_hash=pattern_hash,
        cache_hit=cache_hit,
        created_new_pattern=created_new_pattern,
        used_ai=used_ai,
        response_mode=response_mode,
        severity=severity,
        existing_pattern_id=existing_pattern_id,
        http_status=http_status,
        metadata={"service": "tcp-brain", "family_rule": family_rule or ""},
    )
    HISTORY_WRITER.record(event)

@app.get("/metrics")
def metrics():
    if PROM_ENABLED: return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    return PlainTextResponse("# Metrics disabled", status_code=503)

@app.get("/api/health")
def health(): 
    # Frontend espera { "ok": true }
    return {"ok": True, "status": "online", "db": "connected"}



@app.get("/api/recent")
def get_recent():
    try:
        with db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT snippet, explanation, severity, TO_CHAR(last_seen, 'YYYY-MM-DD HH24:MI:SS') as last_seen FROM tcp_patterns ORDER BY last_seen DESC LIMIT 15;")
                return JSONResponse(content=cur.fetchall())
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/stats")
def get_stats():
    try:
        with db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM tcp_brain_counters WHERE id = 1;")
                row = cur.fetchone()
                cur.execute("SELECT COUNT(*) as total FROM tcp_patterns;")
                p_count = cur.fetchone()
                
                # Mapeia severidades
                cur.execute("SELECT severity, COUNT(*) as count FROM tcp_patterns GROUP BY severity;")
                sevs = {r['severity']: r['count'] for r in cur.fetchall()}

                if not row: 
                    return {
                        "total_hits": 0, "cache_hits": 0, "upstream_calls": 0, 
                        "patterns_total": p_count['total'], "severity_counts": sevs
                    }
                
                res = {
                    "total_hits": row['total_requests'],
                    "total_requests": row['total_requests'],
                    "cache_hits": row['cache_hits'],
                    "cache_misses": row['total_requests'] - row['cache_hits'],
                    "upstream_calls": row['ia_calls'],
                    "ia_calls": row['ia_calls'],
                    "new_patterns": p_count['total'],
                    "patterns_total": p_count['total'],
                    "severity_counts": sevs,
                    "cost_per_ia_call_brl": COST_PER_CALL,
                    "estimated_spend_brl": round(row['ia_calls'] * COST_PER_CALL, 2),
                    "estimated_savings_brl": round(row['cache_hits'] * COST_PER_CALL, 2),
                    "estimated_without_cache_brl": round(row['total_requests'] * COST_PER_CALL, 2)
                }
                total = row['total_requests']
                res["cache_hit_rate"] = (row['cache_hits'] / total) if total > 0 else 0
                return res
    except Exception as e: return {"error": str(e)}

@app.get("/api/detection/latest")
def get_detection_latest():
    payload = load_latest_detection_status()
    if not payload:
        return JSONResponse(
            content={
                "detector_status": "unavailable",
                "decision": "sem diagnóstico disponível",
                "message": "Nenhum resumo consolidado do detector foi encontrado.",
            },
            status_code=503,
        )
    return JSONResponse(content=payload)

@app.post("/api/tcp-explain")
async def explain(request: Request):
    body = await request.json()
    raw = body.get("snippet") or body.get("text") or ""
    if not raw: return JSONResponse({"error": "Snippet vazio"}, status_code=400)
    canon = canonicalize_snippet(raw)
    canon_family, family_rule = normalize_operational_family(canon)
    h = hashlib.sha256(canon_family.encode()).hexdigest()
    try:
        with db_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM tcp_patterns WHERE pattern_hash = %s", (h,))
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE tcp_patterns SET hit_count=hit_count+1, last_seen=now() WHERE pattern_hash=%s", (h,))
                    cur.execute("UPDATE tcp_brain_counters SET total_requests=total_requests+1, cache_hits=cache_hits+1 WHERE id=1")
                    _record_history_event(
                        raw_input=raw,
                        canon=canon,
                        pattern_hash=h,
                        cache_hit=True,
                        created_new_pattern=False,
                        used_ai=False,
                        response_mode="cache",
                        severity=row.get("severity", "unknown") if isinstance(row, dict) else "unknown",
                        existing_pattern_id=h,
                        family_rule=family_rule,
                        http_status=200,
                    )
                    return {"source": "cache", **dict(row)}
        
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": UPSTREAM_MODEL,
            "messages": [
                {"role": "system", "content": "Explique este log de tcpdump de forma curta e técnica. Retorne um JSON com 'explanation' e 'severity' (low, medium, high)."}, 
                {"role": "user", "content": canon}
            ]
        }
        resp = requests.post(UPSTREAM_URL, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            ai_resp = resp.json()['choices'][0]['message']['content']
            # Tenta extrair JSON da resposta da IA
            try:
                data = json.loads(ai_resp)
                exp = data.get("explanation", ai_resp)
                sev = data.get("severity", "unknown")
            except:
                exp = ai_resp
                sev = "unknown"

            with db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO tcp_patterns (pattern_hash, snippet, explanation, severity) VALUES (%s, %s, %s, %s)", (h, canon, exp, sev))
                    cur.execute("UPDATE tcp_brain_counters SET total_requests=total_requests+1, ia_calls=ia_calls+1 WHERE id=1")
            _record_history_event(
                raw_input=raw,
                canon=canon_family,
                pattern_hash=h,
                cache_hit=False,
                created_new_pattern=True,
                used_ai=True,
                response_mode="upstream",
                severity=sev,
                existing_pattern_id="",
                family_rule=family_rule,
                http_status=200,
            )
            return {"source": "upstream", "pattern_hash": h, "snippet": canon_family, "explanation": exp, "severity": sev}
    except Exception as e: log.error(f"Erro: {e}")
    _record_history_event(
        raw_input=raw,
        canon=canon_family,
        pattern_hash=h,
        cache_hit=False,
        created_new_pattern=False,
        used_ai=False,
        response_mode="local_fallback",
        severity="unknown",
        existing_pattern_id="",
        family_rule=family_rule,
        http_status=200,
    )
    return {"source": "local", "explanation": "Sem upstream no momento."}


@app.api_route("/dashboard", methods=["GET", "HEAD"])
@app.api_route("/dashboard/", methods=["GET", "HEAD"])
def dashboard():
    if FRONTEND_DIR:
        return FileResponse(FRONTEND_DIR / "index.html")
    return HTMLResponse("<h1>TCP Brain</h1><p>Frontend indisponível.</p>", status_code=503)


@app.get("/")
def root():
    if FRONTEND_DIR:
        return FileResponse(FRONTEND_DIR / "index.html")
    return {"service": "tcp-brain", "hint": "use /api/health, /api/stats, /dashboard"}


if FRONTEND_DIR:
    # Serve o frontend existente em /srv/escossio-site/public/tcp-brain (ou fallback equivalente).
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


@app.on_event("startup")
def startup():
    ensure_schema()
    HISTORY_WRITER.start()


@app.on_event("shutdown")
def shutdown():
    try:
        HISTORY_WRITER.close()
    except Exception as e:
        log.error(f"Falha ao encerrar writer de histórico: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8091)
