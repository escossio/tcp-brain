#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import select
import signal
import socket
import time
from pathlib import Path
from typing import Any

SCHEMA = "tcp-brain.flow.v1"
STATUS_SCHEMA = "tcp-brain.flow-status.v1"


def iso_from_ns(ts_ns: int) -> str:
    sec, ns = divmod(ts_ns, 1_000_000_000)
    stamp = dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc)
    return f"{stamp.isoformat(timespec='seconds')}.{ns:09d}Z"


def write_json_atomic(path: Path, obj: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(tmp, path)
def load_entities(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    result: dict[str, str] = {}
    for item in data.get("entities", []):
        ip = item.get("ip")
        name = item.get("name")
        if ip and name:
            result[str(ip)] = str(name)
    return result


def endpoint(event: dict[str, Any], prefix: str) -> tuple[str, int]:
    return str(event[f"{prefix}_ip"]), int(event[f"{prefix}_port"])


def canonical_key(event: dict[str, Any]) -> tuple[tuple[str, int], tuple[str, int]]:
    a = endpoint(event, "src")
    b = endpoint(event, "dst")
    return (a, b) if a <= b else (b, a)


def packet_fingerprint(event: dict[str, Any]) -> tuple[Any, ...]:
    return (
        event.get("src_ip"), event.get("dst_ip"),
        event.get("src_port"), event.get("dst_port"),
        event.get("seq"), event.get("ack"),
        event.get("tcp_flags_raw"), event.get("payload_length"),
        event.get("vlan_id"), event.get("src_mac"), event.get("dst_mac"),
    )


def routed_packet_signature(event: dict[str, Any]) -> tuple[Any, ...]:
    return (
        event.get("src_ip"), event.get("dst_ip"),
        event.get("src_port"), event.get("dst_port"),
        event.get("seq"), event.get("ack"),
        event.get("tcp_flags_raw"), event.get("payload_length"),
    )


def attention_vlan_for_ip(ip: str) -> int | None:
    try:
        a, b, c, d = (int(part) for part in ip.split("."))
    except (ValueError, AttributeError):
        return None
    if (a, b, c) != (10, 77, 10) or not 0 <= d < 64:
        return None
    return 210 + (d // 8)


class FlowAnalyzerCore:
    def __init__(
        self,
        entities: dict[str, str],
        handshake_timeout_s: float = 2.0,
        dedupe_window_ms: float = 5.0,
        router_mac: str | None = None,
        forward_timeout_ms: float = 50.0,
    ) -> None:
        self.entities = entities
        self.router_mac = router_mac.lower() if router_mac else None
        self.handshake_timeout_ns = int(handshake_timeout_s * 1e9)
        self.dedupe_window_ns = int(dedupe_window_ms * 1e6)
        self.forward_timeout_ns = int(forward_timeout_ms * 1e6)
        self.flows: dict[Any, dict[str, Any]] = {}
        self.seen_packets: dict[tuple[Any, ...], int] = {}
        self.packets_tcp = 0
        self.packets_ignored = 0
        self.duplicates = 0
        self.anomalies_total = 0
        self.established_total = 0
        self.last_anomaly: dict[str, Any] | None = None
        self.event_seq = 0
        self.witness_window_ns = 1_000_000
        self.l2_witnesses: dict[tuple[Any, ...], list[tuple[int, int]]] = {}
        self.l3_refs: dict[tuple[Any, ...], list[tuple[int, int, Any]]] = {}
        self.mirror_witness_matches = 0
        self.forward_pending: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.forward_reported: dict[tuple[Any, ...], int] = {}
        self.forward_ok_total = 0
        self.forward_missing_total = 0
        self.last_path_event: dict[str, Any] | None = None

    @staticmethod
    def _l2_key(event: dict[str, Any]) -> tuple[Any, ...] | None:
        parts = (event.get("src_mac"), event.get("dst_mac"), event.get("vlan_id"))
        return parts if all(part is not None for part in parts) else None

    @staticmethod
    def _wire_compatible(a: int, b: int) -> bool:
        return abs(a - b) in (0, 4)

    def _new_flow(
        self, event: dict[str, Any], source: str, key: Any
    ) -> dict[str, Any]:
        ts = int(event["capture_timestamp_ns"])
        return {
            "key": key, "first_seen_ns": ts, "last_seen_ns": ts,
            "first_syn_ns": None, "initiator": None, "responder": None,
            "state": "OBSERVED", "syn_count": 0, "synack_count": 0,
            "ack_count": 0, "rst_count": 0, "fin_count": 0,
            "syn_retries": 0, "observed_vlans": set(),
            "sources": {source}, "anomaly_emitted": False,
            "first_syn_seq": None, "mirror_witness_count": 0,
        }

    def _label(self, ep: tuple[str, int]) -> str:
        ip, port = ep
        name = self.entities.get(ip)
        return f"{name} ({ip}:{port})" if name else f"{ip}:{port}"

    def _mark_witness(self, flow: dict[str, Any]) -> None:
        if "mirror-l2-witness" not in flow["sources"]:
            flow["sources"].add("mirror-l2-witness")
            flow["mirror_witness_count"] += 1
            self.mirror_witness_matches += 1

    def _record_l2_witness(self, event: dict[str, Any]) -> None:
        key = self._l2_key(event)
        if key is None or event.get("capture_timestamp_ns") is None:
            return
        ts = int(event["capture_timestamp_ns"])
        wire = int(event.get("wire_length") or 0)
        self.l2_witnesses.setdefault(key, []).append((ts, wire))
        for l3_ts, l3_wire, flow_key in self.l3_refs.get(key, []):
            if abs(ts - l3_ts) <= self.witness_window_ns and self._wire_compatible(wire, l3_wire):
                flow = self.flows.get(flow_key)
                if flow:
                    self._mark_witness(flow)
                    break

    def _record_l3_ref(
        self, event: dict[str, Any], flow_key: Any, flow: dict[str, Any]
    ) -> None:
        key = self._l2_key(event)
        if key is None:
            return
        ts = int(event["capture_timestamp_ns"])
        wire = int(event.get("wire_length") or 0)
        self.l3_refs.setdefault(key, []).append((ts, wire, flow_key))
        for l2_ts, l2_wire in self.l2_witnesses.get(key, []):
            if abs(ts - l2_ts) <= self.witness_window_ns and self._wire_compatible(wire, l2_wire):
                self._mark_witness(flow)
                break

    def _has_physical_ingress_witness(self, pending: dict[str, Any]) -> bool:
        key = (
            pending.get("src_mac"),
            pending.get("dst_mac"),
            pending.get("ingress_vlan"),
        )
        ts = int(pending["timestamp_ns"])
        wire = int(pending.get("wire_length") or 0)
        for witness_ts, witness_wire in self.l2_witnesses.get(key, []):
            if (
                abs(ts - witness_ts) <= self.witness_window_ns
                and self._wire_compatible(wire, witness_wire)
            ):
                return True
        return False

    def _track_inter_vlan_forward(
        self, event: dict[str, Any], source: str
    ) -> None:
        if source != "trunk" or self.router_mac is None:
            return
        flags = set(event.get("tcp_flags") or [])
        if "SYN" not in flags or "ACK" in flags:
            return

        src_ip = str(event.get("src_ip") or "")
        dst_ip = str(event.get("dst_ip") or "")
        if src_ip not in self.entities or dst_ip not in self.entities:
            return
        src_vlan = attention_vlan_for_ip(src_ip)
        dst_vlan = attention_vlan_for_ip(dst_ip)
        if src_vlan is None or dst_vlan is None or src_vlan == dst_vlan:
            return

        src_mac = str(event.get("src_mac") or "").lower()
        dst_mac = str(event.get("dst_mac") or "").lower()
        observed_vlan = event.get("vlan_id")
        signature = routed_packet_signature(event)
        ts = int(event["capture_timestamp_ns"])

        if dst_mac == self.router_mac and observed_vlan == src_vlan:
            if signature not in self.forward_pending:
                self.forward_pending[signature] = {
                    "signature": signature,
                    "timestamp_ns": ts,
                    "src_ip": src_ip,
                    "src_port": int(event["src_port"]),
                    "dst_ip": dst_ip,
                    "dst_port": int(event["dst_port"]),
                    "seq": event.get("seq"),
                    "tcp_flags": list(event.get("tcp_flags") or []),
                    "ingress_vlan": src_vlan,
                    "expected_egress_vlan": dst_vlan,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "wire_length": int(event.get("wire_length") or 0),
                }
            return

        if src_mac == self.router_mac and observed_vlan == dst_vlan:
            pending = self.forward_pending.pop(signature, None)
            if pending is not None:
                self.forward_ok_total += 1

    def _path_missing_event(
        self, pending: dict[str, Any], now_ns: int
    ) -> dict[str, Any]:
        self.event_seq += 1
        physical = self._has_physical_ingress_witness(pending)
        src = (pending["src_ip"], pending["src_port"])
        dst = (pending["dst_ip"], pending["dst_port"])
        elapsed_ms = round((now_ns - int(pending["timestamp_ns"])) / 1e6, 3)
        witness_text = (
            " e confirmado pelo mirror físico"
            if physical
            else ""
        )
        text = (
            f"{self._label(src)} enviou SYN pela VLAN "
            f"{pending['ingress_vlan']}{witness_text}, mas nenhuma emissão "
            f"correspondente foi observada na VLAN "
            f"{pending['expected_egress_vlan']} em {elapsed_ms} ms. "
            "A interrupção está localizada entre o ingresso e o egress "
            "inter-VLAN da MikroTik."
        )
        event = {
            "schema_version": "tcp-brain.path.v1",
            "event_id": f"path-{now_ns:x}-{self.event_seq:x}",
            "event_type": "PATH_ANOMALY",
            "anomaly_type": "INTER_VLAN_EGRESS_MISSING",
            "severity": "WARNING",
            "device": "mikrotik-core",
            "layer": "L3_FORWARDING",
            "src_ip": pending["src_ip"],
            "src_port": pending["src_port"],
            "dst_ip": pending["dst_ip"],
            "dst_port": pending["dst_port"],
            "src_service": self.entities.get(pending["src_ip"]),
            "dst_service": self.entities.get(pending["dst_ip"]),
            "ingress_vlan": pending["ingress_vlan"],
            "expected_egress_vlan": pending["expected_egress_vlan"],
            "seq": pending.get("seq"),
            "tcp_flags": pending.get("tcp_flags"),
            "forward_timeout_ms": self.forward_timeout_ns / 1e6,
            "elapsed_ms": elapsed_ms,
            "physical_ingress_witness": physical,
            "egress_observed": False,
            "payload_observed": False,
            "ai_used": False,
            "natural_language": text,
        }
        self.forward_missing_total += 1
        self.last_path_event = event
        return event

    def _anomaly(
        self, flow: dict[str, Any], kind: str, now_ns: int
    ) -> dict[str, Any]:
        self.event_seq += 1
        src = flow["initiator"]
        dst = flow["responder"]
        duration_ms = round((now_ns - int(flow["first_syn_ns"])) / 1e6, 3)
        if kind == "HANDSHAKE_INCOMPLETE":
            text = (
                f"{self._label(src)} enviou {flow['syn_count']} SYN para "
                f"{self._label(dst)} em {duration_ms} ms; nenhum SYN/ACK "
                "foi observado."
            )
        else:
            text = (
                f"{self._label(src)} tentou conexão com {self._label(dst)}; "
                f"RST observado antes do estabelecimento."
            )
        event = {
            "schema_version": SCHEMA,
            "event_id": f"flow-{now_ns:x}-{self.event_seq:x}",
            "event_type": "ANOMALY",
            "anomaly_type": kind,
            "severity": "WARNING",
            "first_seen_ns": flow["first_seen_ns"],
            "last_seen_ns": flow["last_seen_ns"],
            "first_seen": iso_from_ns(flow["first_seen_ns"]),
            "last_seen": iso_from_ns(flow["last_seen_ns"]),
            "duration_ms": duration_ms,
            "src_ip": src[0], "src_port": src[1],
            "dst_ip": dst[0], "dst_port": dst[1],
            "src_service": self.entities.get(src[0]),
            "dst_service": self.entities.get(dst[0]),
            "observed_vlans": sorted(flow["observed_vlans"]),
            "capture_sources": sorted(flow["sources"]),
            "syn_count": flow["syn_count"],
            "synack_count": flow["synack_count"],
            "syn_retries": flow["syn_retries"],
            "rst_count": flow["rst_count"],
            "fin_count": flow["fin_count"],
            "state": flow["state"],
            "evidence": {
                "metadata_only": True,
                "payload_observed": False,
                "dedupe_window_ms": self.dedupe_window_ns / 1e6,
                "physical_mirror_witness": (
                    "mirror" in flow["sources"]
                    or "mirror-l2-witness" in flow["sources"]
                ),
                "mirror_correlation_window_ms": self.witness_window_ns / 1e6,
            },
            "natural_language": text,
            "ai_used": False,
        }
        flow["anomaly_emitted"] = True
        self.anomalies_total += 1
        self.last_anomaly = event
        return event
    def ingest(self, event: dict[str, Any], source: str) -> list[dict[str, Any]]:
        if event.get("protocol") != "TCP":
            if (
                source == "mirror"
                and event.get("decode_quality") == "L2_ONLY_8023_OR_MIRROR_ARTIFACT"
            ):
                self._record_l2_witness(event)
            self.packets_ignored += 1
            return []
        required = ("src_ip", "dst_ip", "src_port", "dst_port", "capture_timestamp_ns")
        if any(event.get(k) is None for k in required):
            self.packets_ignored += 1
            return []

        self.packets_tcp += 1
        self._track_inter_vlan_forward(event, source)
        ts = int(event["capture_timestamp_ns"])
        # Flow semantics deduplicate the same routed packet across observation
        # points/VLAN hops. Path localization is handled before this step.
        fp = routed_packet_signature(event)
        previous = self.seen_packets.get(fp)
        key = canonical_key(event)
        flow = self.flows.get(key)
        if previous is not None and 0 <= ts - previous <= self.dedupe_window_ns:
            self.duplicates += 1
            if flow:
                flow["sources"].add(source)
                if event.get("vlan_id") is not None:
                    flow["observed_vlans"].add(int(event["vlan_id"]))
            return []
        self.seen_packets[fp] = ts

        if flow is None:
            flow = self._new_flow(event, source, key)
            self.flows[key] = flow
        flow["last_seen_ns"] = ts
        flow["sources"].add(source)
        if event.get("vlan_id") is not None:
            flow["observed_vlans"].add(int(event["vlan_id"]))
        self._record_l3_ref(event, key, flow)

        flags = set(event.get("tcp_flags") or [])
        src = endpoint(event, "src")
        dst = endpoint(event, "dst")
        out: list[dict[str, Any]] = []

        if "SYN" in flags and "ACK" not in flags:
            if flow["state"] in {"RESET", "CLOSED", "TIMEOUT"}:
                flow = self._new_flow(event, source, key)
                self.flows[key] = flow
                if event.get("vlan_id") is not None:
                    flow["observed_vlans"].add(int(event["vlan_id"]))
            flow["initiator"] = src
            flow["responder"] = dst
            if flow["first_syn_ns"] is None:
                flow["first_syn_ns"] = ts
                flow["first_syn_seq"] = event.get("seq")
            else:
                flow["syn_retries"] += 1
            flow["syn_count"] += 1
            if flow["state"] not in {"SYN_ACK_SEEN", "ESTABLISHED", "CLOSING"}:
                flow["state"] = "SYN_SENT"

        elif "SYN" in flags and "ACK" in flags:
            if flow["initiator"] is None:
                flow["initiator"], flow["responder"] = dst, src
            flow["synack_count"] += 1
            flow["state"] = "SYN_ACK_SEEN"

        elif "RST" in flags:
            flow["rst_count"] += 1
            rejected = flow["state"] == "SYN_SENT" and flow["synack_count"] == 0
            flow["state"] = "RESET"
            if rejected and not flow["anomaly_emitted"]:
                out.append(self._anomaly(flow, "CONNECTION_REJECTED", ts))

        elif "ACK" in flags:
            flow["ack_count"] += 1
            if flow["state"] == "SYN_ACK_SEEN" and src == flow["initiator"]:
                flow["state"] = "ESTABLISHED"
                self.established_total += 1

        if "FIN" in flags:
            flow["fin_count"] += 1
            flow["state"] = "CLOSED" if flow["fin_count"] >= 2 else "CLOSING"

        return out

    def expire(self, now_ns: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for flow in list(self.flows.values()):
            first_syn = flow.get("first_syn_ns")
            if (
                flow["state"] == "SYN_SENT"
                and first_syn is not None
                and flow["synack_count"] == 0
                and not flow["anomaly_emitted"]
                and now_ns - int(first_syn) >= self.handshake_timeout_ns
            ):
                flow["state"] = "TIMEOUT"
                out.append(self._anomaly(flow, "HANDSHAKE_INCOMPLETE", now_ns))

        for signature, pending in list(self.forward_pending.items()):
            if now_ns - int(pending["timestamp_ns"]) < self.forward_timeout_ns:
                continue
            last_reported = self.forward_reported.get(signature)
            if last_reported is None or now_ns - last_reported >= int(5e9):
                out.append(self._path_missing_event(pending, now_ns))
                self.forward_reported[signature] = now_ns
            self.forward_pending.pop(signature, None)

        cutoff = now_ns - int(300 * 1e9)
        self.flows = {
            key: flow for key, flow in self.flows.items()
            if int(flow["last_seen_ns"]) >= cutoff
        }
        seen_cutoff = now_ns - int(1e9)
        self.seen_packets = {
            fp: ts for fp, ts in self.seen_packets.items() if ts >= seen_cutoff
        }
        correlation_cutoff = now_ns - 100_000_000
        self.l2_witnesses = {
            key: [(ts, wire) for ts, wire in values if ts >= correlation_cutoff]
            for key, values in self.l2_witnesses.items()
            if any(ts >= correlation_cutoff for ts, _wire in values)
        }
        self.l3_refs = {
            key: [
                (ts, wire, flow_key)
                for ts, wire, flow_key in values
                if ts >= correlation_cutoff
            ]
            for key, values in self.l3_refs.items()
            if any(ts >= correlation_cutoff for ts, _wire, _flow_key in values)
        }
        return out
class FlowDaemon:
    def __init__(
        self,
        inputs: dict[str, Path],
        event_socket: Path,
        status_file: Path,
        core: FlowAnalyzerCore,
    ) -> None:
        self.inputs = inputs
        self.event_socket = event_socket
        self.status_file = status_file
        self.core = core
        self.running = True
        self.started_ns = time.time_ns()
        self.sources: dict[str, socket.socket] = {}
        self.buffers: dict[str, bytes] = {}
        self.reconnect_at: dict[str, float] = {}
        self.clients: list[socket.socket] = []
        self.events_emitted = 0
        self.input_events = 0
        self.last_input_ns: int | None = None

        self.event_socket.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.event_socket.unlink()
        except FileNotFoundError:
            pass
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.event_socket))
        os.chmod(self.event_socket, 0o660)
        self.server.listen(8)
        self.server.setblocking(False)

    def stop(self, *_: Any) -> None:
        self.running = False
    def connect_sources(self) -> None:
        now = time.monotonic()
        for name, path in self.inputs.items():
            if name in self.sources or now < self.reconnect_at.get(name, 0):
                continue
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(path))
                s.setblocking(False)
                self.sources[name] = s
                self.buffers[name] = b""
            except OSError as exc:
                print(json.dumps({
                    "event": "source_connect_failed",
                    "source": name,
                    "path": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                }, sort_keys=True), flush=True)
                s.close()
                self.reconnect_at[name] = now + 1.0

    def accept_clients(self) -> None:
        while True:
            try:
                client, _ = self.server.accept()
                client.setblocking(False)
                self.clients.append(client)
            except BlockingIOError:
                return

    def publish(self, event: dict[str, Any]) -> None:
        payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        print(payload.decode().rstrip(), flush=True)
        alive: list[socket.socket] = []
        for client in self.clients:
            try:
                client.sendall(payload)
                alive.append(client)
            except OSError:
                try:
                    client.close()
                except OSError:
                    pass
        self.clients = alive
        self.events_emitted += 1
    def consume(self, name: str) -> None:
        s = self.sources[name]
        try:
            data = s.recv(65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            s.close()
            self.sources.pop(name, None)
            self.reconnect_at[name] = time.monotonic() + 1.0
            return

        buf = self.buffers.get(name, b"") + data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.input_events += 1
            self.last_input_ns = int(event.get("capture_timestamp_ns") or time.time_ns())
            for flow_event in self.core.ingest(event, name):
                self.publish(flow_event)
        self.buffers[name] = buf

    def status(self) -> dict[str, Any]:
        now = time.time_ns()
        freshness = None
        if self.last_input_ns is not None:
            freshness = max(0.0, (now - self.last_input_ns) / 1e9)
        return {
            "schema_version": STATUS_SCHEMA,
            "state": "HEALTHY" if self.sources else "NO_INPUT",
            "started_timestamp_ns": self.started_ns,
            "inputs_configured": sorted(self.inputs),
            "inputs_connected": sorted(self.sources),
            "input_events": self.input_events,
            "tcp_packets": self.core.packets_tcp,
            "ignored_packets": self.core.packets_ignored,
            "deduplicated_packets": self.core.duplicates,
            "mirror_l2_witness_matches": self.core.mirror_witness_matches,
            "active_flows": len(self.core.flows),
            "established_total": self.core.established_total,
            "anomalies_total": self.core.anomalies_total,
            "forward_ok_total": self.core.forward_ok_total,
            "forward_missing_total": self.core.forward_missing_total,
            "forward_pending": len(self.core.forward_pending),
            "last_path_event": self.core.last_path_event,
            "events_emitted": self.events_emitted,
            "freshness_seconds": None if freshness is None else round(freshness, 3),
            "last_anomaly": self.core.last_anomaly,
            "payload_persisted": False,
            "ai_used": False,
        }

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        next_status = 0.0
        while self.running:
            self.connect_sources()
            readers = [self.server, *self.sources.values()]
            readable, _, _ = select.select(readers, [], [], 0.2)
            if self.server in readable:
                self.accept_clients()
            for name, sock in list(self.sources.items()):
                if sock in readable:
                    self.consume(name)
            for event in self.core.expire(time.time_ns()):
                self.publish(event)
            now = time.monotonic()
            if now >= next_status:
                write_json_atomic(self.status_file, self.status())
                next_status = now + 1.0
        try:
            write_json_atomic(self.status_file, self.status())
        except OSError:
            pass
        for s in self.sources.values():
            s.close()
        for client in self.clients:
            client.close()
        self.server.close()
        try:
            self.event_socket.unlink()
        except FileNotFoundError:
            pass


def parse_inputs(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"invalid input {value!r}; expected NAME=/path/socket")
        name, raw_path = value.split("=", 1)
        result[name] = Path(raw_path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--event-socket", type=Path, default=Path("/run/tcp-brain-flow/events.sock"))
    parser.add_argument("--status-file", type=Path, default=Path("/run/tcp-brain-flow/status.json"))
    parser.add_argument("--entities", type=Path)
    parser.add_argument("--handshake-timeout", type=float, default=2.0)
    parser.add_argument("--dedupe-window-ms", type=float, default=5.0)
    parser.add_argument("--router-mac")
    parser.add_argument("--forward-timeout-ms", type=float, default=50.0)
    args = parser.parse_args()

    inputs = parse_inputs(args.input)
    if not inputs:
        inputs = {"mirror": Path("/run/tcp-brain-capture/events.sock")}
    core = FlowAnalyzerCore(
        load_entities(args.entities),
        handshake_timeout_s=args.handshake_timeout,
        dedupe_window_ms=args.dedupe_window_ms,
        router_mac=args.router_mac,
        forward_timeout_ms=args.forward_timeout_ms,
    )
    daemon = FlowDaemon(inputs, args.event_socket, args.status_file, core)
    print(json.dumps({
        "event": "flow_analyzer_started",
        "inputs": {k: str(v) for k, v in inputs.items()},
        "payload_persisted": False,
        "ai_used": False,
    }, sort_keys=True), flush=True)
    daemon.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
