#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import atexit
import gzip
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("tcp-brain.history")

DEFAULT_HISTORY_DIR = Path(os.getenv("TCP_BRAIN_HISTORY_DIR", "/srv/tcp/knowledge/events"))
DEFAULT_RETENTION_DIR = Path(os.getenv("TCP_BRAIN_HISTORY_RETENTION_DIR", "/srv/tcp/knowledge/retention"))
DEFAULT_HISTORY_FILE = Path(os.getenv("TCP_BRAIN_HISTORY_FILE", str(DEFAULT_HISTORY_DIR / "tcp_brain_history.jsonl")))
MAX_EXCERPT_CHARS = int(os.getenv("TCP_BRAIN_HISTORY_EXCERPT_CHARS", "240"))
MAX_CANONICAL_CHARS = int(os.getenv("TCP_BRAIN_HISTORY_CANONICAL_CHARS", "360"))
MAX_QUEUE_SIZE = int(os.getenv("TCP_BRAIN_HISTORY_QUEUE_SIZE", "2000"))
MAX_FILE_BYTES = int(os.getenv("TCP_BRAIN_HISTORY_MAX_BYTES", str(5 * 1024 * 1024)))
RETENTION_KEEP = int(os.getenv("TCP_BRAIN_HISTORY_RETENTION_KEEP", "20"))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _compact_text(value: Optional[str], limit: int) -> Dict[str, Any]:
    if not value:
        return {"text": "", "truncated": False}
    compact = re.sub(r"\s+", " ", str(value)).strip()
    truncated = len(compact) > limit
    if truncated:
        compact = compact[:limit]
    return {"text": compact, "truncated": truncated}


def _hash_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def build_history_event(
    *,
    endpoint: str,
    raw_input: Optional[str],
    canonical_snippet: str,
    pattern_hash: str,
    cache_hit: bool,
    created_new_pattern: bool,
    used_ai: bool,
    response_mode: str,
    severity: str = "unknown",
    existing_pattern_id: Optional[str] = None,
    source: str = "tcp-brain",
    method: str = "POST",
    http_status: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    raw_compact = _compact_text(raw_input, MAX_EXCERPT_CHARS)
    canon_compact = _compact_text(canonical_snippet, MAX_CANONICAL_CHARS)
    event = {
        "schema_version": 1,
        "ts": _utc_now_iso(),
        "source": source,
        "endpoint": endpoint,
        "method": method,
        "raw_input_present": bool(raw_input),
        "raw_input_length": len(raw_input or ""),
        "raw_input_excerpt": raw_compact["text"],
        "raw_input_excerpt_truncated": raw_compact["truncated"],
        "raw_input_hash": _hash_text(raw_input),
        "canonical_snippet": canon_compact["text"],
        "canonical_snippet_truncated": canon_compact["truncated"],
        "pattern_hash": pattern_hash,
        "cache_hit": cache_hit,
        "existing_pattern_id": existing_pattern_id or "",
        "created_new_pattern": created_new_pattern,
        "severity": severity or "unknown",
        "used_ai": used_ai,
        "response_mode": response_mode,
        "http_status": http_status,
        "metadata": metadata or {},
    }
    return event


class StructuredHistoryWriter:
    def __init__(
        self,
        active_path: Path = DEFAULT_HISTORY_FILE,
        retention_dir: Path = DEFAULT_RETENTION_DIR,
        max_file_bytes: int = MAX_FILE_BYTES,
        keep_archives: int = RETENTION_KEEP,
        queue_size: int = MAX_QUEUE_SIZE,
    ) -> None:
        self.active_path = active_path
        self.retention_dir = retention_dir
        self.max_file_bytes = max_file_bytes
        self.keep_archives = keep_archives
        self.queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=queue_size)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._fh = None
        self._started = False
        self.dropped = 0

    def ensure_layout(self) -> None:
        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_dir.mkdir(parents=True, exist_ok=True)
        for sub in ("exports", "snapshots", "runbooks"):
            (self.active_path.parent.parent / sub).mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if self._started:
            return
        self.ensure_layout()
        self._started = True
        self._thread = threading.Thread(target=self._run, name="tcp-history-writer", daemon=True)
        self._thread.start()
        atexit.register(self.close)

    def close(self) -> None:
        if not self._started:
            return
        self._stop.set()
        try:
            self.queue.put_nowait(None)
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._close_handle()
        self._started = False

    def record(self, event: Dict[str, Any]) -> None:
        if not self._started:
            self.start()
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            log.warning("Fila de histórico cheia; evento descartado (dropped=%s)", self.dropped)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            try:
                self._write_event(item)
            except Exception as exc:
                log.error("Falha ao escrever histórico estruturado: %s", exc)
        self._flush_handle()

    def _open_handle(self) -> None:
        if self._fh is None:
            self.ensure_layout()
            self._fh = open(self.active_path, "a", encoding="utf-8", buffering=1)

    def _close_handle(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            except Exception:
                pass
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def _flush_handle(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.flush()
        except Exception:
            pass

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if not self.active_path.exists():
            return
        current_size = self.active_path.stat().st_size
        if current_size + incoming_bytes <= self.max_file_bytes:
            return
        self._close_handle()
        if self.active_path.exists() and self.active_path.stat().st_size > 0:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            archive_path = self.retention_dir / f"tcp_brain_history-{ts}.jsonl.gz"
            with open(self.active_path, "rb") as src, gzip.open(archive_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            self.active_path.unlink(missing_ok=True)
            self._prune_archives()
        self._open_handle()

    def _prune_archives(self) -> None:
        archives = sorted(self.retention_dir.glob("tcp_brain_history-*.jsonl.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in archives[self.keep_archives :]:
            try:
                old.unlink()
            except Exception:
                log.warning("Falha ao remover arquivo antigo de retenção: %s", old)

    def _write_event(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        line_bytes = line.encode("utf-8")
        self._rotate_if_needed(len(line_bytes))
        self._open_handle()
        assert self._fh is not None
        self._fh.write(line)


HISTORY_WRITER = StructuredHistoryWriter()

