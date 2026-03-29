#!/usr/bin/env python3
"""Smoke test operacional do tcp-brain.

Valida:
- /api/health
- /api/detection/latest
- /dashboard
- presença dos elementos-chave do card do detector no HTML

Uso padrão:
    python3 scripts/smoke_tcp_brain.py

Exemplo com URL explícita:
    python3 scripts/smoke_tcp_brain.py --base-url https://tcp.escossio.dev.br
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_BASE_URL = os.getenv("TCP_BRAIN_SMOKE_BASE_URL", "https://tcp.escossio.dev.br")
DEFAULT_TIMEOUT = float(os.getenv("TCP_BRAIN_SMOKE_TIMEOUT", "15"))
USER_AGENT = "tcp-brain-smoke/1.0"


@dataclass
class Response:
    status: int
    body: str
    content_type: str


def fail(message: str) -> "None":
    print(f"[ERRO] {message}", file=sys.stderr)
    raise SystemExit(1)


def ok(message: str) -> None:
    print(f"[OK] {message}")


def fetch(url: str, timeout: float) -> Response:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            content_type = resp.headers.get("Content-Type", "")
            return Response(status=getattr(resp, "status", 200), body=body, content_type=content_type)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        return Response(status=exc.code, body=body, content_type=content_type)
    except urllib.error.URLError as exc:
        fail(f"Falha ao acessar {url}: {exc.reason}")
    except TimeoutError:
        fail(f"Timeout ao acessar {url}")


def fetch_json(url: str, timeout: float) -> tuple[dict[str, Any], Response]:
    resp = fetch(url, timeout)
    if resp.status >= 400:
        fail(f"{url} retornou HTTP {resp.status}")
    try:
        data = json.loads(resp.body)
    except json.JSONDecodeError as exc:
        fail(f"{url} não retornou JSON válido: {exc}")
    if not isinstance(data, dict):
        fail(f"{url} retornou JSON, mas não um objeto")
    return data, resp


def fetch_text(url: str, timeout: float) -> tuple[str, Response]:
    resp = fetch(url, timeout)
    if resp.status >= 400:
        fail(f"{url} retornou HTTP {resp.status}")
    return resp.body, resp


def ensure(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test operacional do tcp-brain")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL do serviço")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout em segundos")
    args = parser.parse_args()

    base_url = str(args.base_url).rstrip("/")
    timeout = float(args.timeout)

    ok(f"Iniciando smoke test em {base_url} com timeout {timeout:.1f}s")

    health_url = f"{base_url}/api/health"
    health, health_resp = fetch_json(health_url, timeout)
    ensure(health.get("ok") is True, f"{health_url} não confirmou ok=true")
    ensure(str(health.get("status", "")).lower() in {"online", "ok"}, f"{health_url} retornou status inesperado")
    ok(f"Backend saudável: HTTP {health_resp.status} | {health.get('status')}")

    detection_url = f"{base_url}/api/detection/latest"
    detection, detection_resp = fetch_json(detection_url, timeout)
    ensure("detector_status" in detection, f"{detection_url} não trouxe detector_status")
    ensure(str(detection.get("detector_status")) != "unavailable", f"{detection_url} retornou detector_status=unavailable")
    ensure("monitored_host_decision" in detection, f"{detection_url} não trouxe monitored_host_decision")
    ensure(bool(detection.get("monitored_host_decision")), f"{detection_url} trouxe monitored_host_decision vazio")
    ensure("monitored_host" in detection, f"{detection_url} não trouxe monitored_host")
    ok(
        "Detector consolidado OK: "
        f"HTTP {detection_resp.status} | detector_status={detection.get('detector_status')} | "
        f"decision={detection.get('monitored_host_decision')}"
    )

    dashboard_url = f"{base_url}/dashboard"
    dashboard_html, dashboard_resp = fetch_text(dashboard_url, timeout)
    ensure("Detector consolidado" in dashboard_html, f"{dashboard_url} não contém o card 'Detector consolidado'")
    ensure("id=\"detector-status-pill\"" in dashboard_html, f"{dashboard_url} não contém detector-status-pill")
    ensure("id=\"detector-state\"" in dashboard_html, f"{dashboard_url} não contém detector-state")
    ensure("id=\"detector-decision\"" in dashboard_html, f"{dashboard_url} não contém detector-decision")
    ok(f"Dashboard OK: HTTP {dashboard_resp.status} | card do detector encontrado")

    print("[OK] Smoke test concluído com sucesso.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
