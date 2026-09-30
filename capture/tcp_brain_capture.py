#!/usr/bin/env python3
"""Passive L2/L3/L4 metadata collector for a SPAN/mirror interface.

Raw packet bytes are bounded to HEADER_WINDOW bytes, parsed in memory, and
immediately discarded. Only structured metadata is emitted over a local Unix
socket and aggregate health is persisted to a status JSON file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import select
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

ETH_P_ALL = 0x0003
VLAN_ETHERTYPES = {0x8100, 0x88A8}
SO_TIMESTAMPNS = 35
SO_RXQ_OVFL = 40
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6
HEADER_WINDOW = 104
PACKET_TYPES = {
    0: "HOST",
    1: "BROADCAST",
    2: "MULTICAST",
    3: "OTHERHOST",
    4: "OUTGOING",
    5: "LOOPBACK",
}

TCP_FLAGS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


def mac(raw: bytes | memoryview) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def iso_from_ns(ts_ns: int) -> str:
    sec, ns = divmod(ts_ns, 1_000_000_000)
    stamp = dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc)
    return f"{stamp.isoformat(timespec='seconds')}.{ns:09d}Z"


def tcp_flag_names(value: int) -> list[str]:
    return [name for bit, name in TCP_FLAGS if value & bit]


def parse_frame(
    raw: bytes | bytearray | memoryview,
    wire_length: int,
    ts_ns: int,
    interface: str,
    event_id: str,
    aux_vlan_id: int | None = None,
    aux_vlan_tpid: int | None = None,
    observation_point: str = "unknown",
    packet_type: int | None = None,
) -> dict[str, Any] | None:
    view = memoryview(raw)
    if len(view) < 14:
        return None

    dst_mac = mac(view[0:6])
    src_mac = mac(view[6:12])
    ethertype = struct.unpack_from("!H", view, 12)[0]
    offset = 14
    vlan_tags: list[int] = []

    vlan_source = "wire"
    vlan_tpid: int | None = None
    while ethertype in VLAN_ETHERTYPES and len(view) >= offset + 4:
        vlan_tpid = ethertype
        tci, ethertype = struct.unpack_from("!HH", view, offset)
        vlan_tags.append(tci & 0x0FFF)
        offset += 4

    if not vlan_tags and aux_vlan_id is not None:
        vlan_tags.append(aux_vlan_id)
        vlan_tpid = aux_vlan_tpid or 0x8100
        vlan_source = "packet_auxdata"

    observed_ethertype = ethertype
    decode_quality = "FULL_L3_L4" if ethertype > 1500 else "L2_ONLY_8023_OR_MIRROR_ARTIFACT"

    event: dict[str, Any] = {
        "schema_version": "tcp-brain.capture.v1",
        "event_id": event_id,
        "capture_timestamp_ns": ts_ns,
        "capture_timestamp": iso_from_ns(ts_ns),
        "capture_interface": interface,
        "observation_point": observation_point,
        "packet_type": PACKET_TYPES.get(packet_type, str(packet_type) if packet_type is not None else None),
        "vlan_tags": vlan_tags,
        "vlan_id": vlan_tags[-1] if vlan_tags else None,
        "vlan_source": vlan_source if vlan_tags else None,
        "vlan_tpid": f"0x{vlan_tpid:04x}" if vlan_tpid is not None else None,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "ethertype": f"0x{ethertype:04x}",
        "ethertype_observed": f"0x{observed_ethertype:04x}",
        "decode_quality": decode_quality,
        "wire_length": wire_length,
    }

    if ethertype <= 1500:
        return event

    if ethertype == 0x0800:
        if len(view) < offset + 20:
            return event
        version_ihl = view[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or ihl < 20 or len(view) < offset + ihl:
            return event

        total_length = struct.unpack_from("!H", view, offset + 2)[0]
        proto = view[offset + 9]
        src_ip = socket.inet_ntop(socket.AF_INET, bytes(view[offset + 12 : offset + 16]))
        dst_ip = socket.inet_ntop(socket.AF_INET, bytes(view[offset + 16 : offset + 20]))
        frag_field = struct.unpack_from("!H", view, offset + 6)[0]
        fragment_offset = frag_field & 0x1FFF
        more_fragments = bool(frag_field & 0x2000)

        event.update(
            {
                "ip_version": 4,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ip_protocol": proto,
                "ip_total_length": total_length,
                "ip_header_length": ihl,
                "fragment_offset": fragment_offset,
                "more_fragments": more_fragments,
            }
        )

        l4 = offset + ihl
        if fragment_offset != 0:
            return event

        if proto == 6 and len(view) >= l4 + 20:
            src_port, dst_port, seq, ack = struct.unpack_from("!HHII", view, l4)
            data_offset = (view[l4 + 12] >> 4) * 4
            flags = view[l4 + 13]
            window = struct.unpack_from("!H", view, l4 + 14)[0]
            payload_length = max(0, total_length - ihl - data_offset)
            event.update(
                {
                    "protocol": "TCP",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tcp_flags": tcp_flag_names(flags),
                    "tcp_flags_raw": flags,
                    "seq": seq,
                    "ack": ack,
                    "window": window,
                    "tcp_header_length": data_offset,
                    "payload_length": payload_length,
                }
            )
        elif proto == 17 and len(view) >= l4 + 8:
            src_port, dst_port, udp_length = struct.unpack_from("!HHH", view, l4)
            event.update(
                {
                    "protocol": "UDP",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "udp_length": udp_length,
                    "payload_length": max(0, udp_length - 8),
                }
            )
        elif proto == 1:
            event["protocol"] = "ICMP"
        else:
            event["protocol"] = f"IPPROTO_{proto}"

    elif ethertype == 0x86DD:
        if len(view) < offset + 40:
            return event
        version = view[offset] >> 4
        if version != 6:
            return event
        payload_len = struct.unpack_from("!H", view, offset + 4)[0]
        next_header = view[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, bytes(view[offset + 8 : offset + 24]))
        dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(view[offset + 24 : offset + 40]))
        event.update(
            {
                "ip_version": 6,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ip_protocol": next_header,
                "ip_total_length": payload_len + 40,
                "ip_header_length": 40,
            }
        )
        l4 = offset + 40
        if next_header == 6 and len(view) >= l4 + 20:
            src_port, dst_port, seq, ack = struct.unpack_from("!HHII", view, l4)
            data_offset = (view[l4 + 12] >> 4) * 4
            flags = view[l4 + 13]
            window = struct.unpack_from("!H", view, l4 + 14)[0]
            event.update(
                {
                    "protocol": "TCP",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tcp_flags": tcp_flag_names(flags),
                    "tcp_flags_raw": flags,
                    "seq": seq,
                    "ack": ack,
                    "window": window,
                    "tcp_header_length": data_offset,
                    "payload_length": max(0, payload_len - data_offset),
                }
            )
        elif next_header == 17 and len(view) >= l4 + 8:
            src_port, dst_port, udp_length = struct.unpack_from("!HHH", view, l4)
            event.update(
                {
                    "protocol": "UDP",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "udp_length": udp_length,
                    "payload_length": max(0, udp_length - 8),
                }
            )
        else:
            event["protocol"] = f"IPV6_NH_{next_header}"

    return event


def read_int(path: Path, default: int = 0) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, obj: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


class Collector:
    def __init__(
        self,
        interface: str,
        status_file: Path,
        socket_path: Path,
        vlans: set[int],
        observation_point: str,
    ):
        self.interface = interface
        self.observation_point = observation_point
        self.status_file = status_file
        self.socket_path = socket_path
        self.vlans = vlans
        self.running = True
        self.started_ns = time.time_ns()
        self.seq = 0
        self.packets_received = 0
        self.wire_bytes = 0
        self.events_emitted = 0
        self.parse_errors = 0
        self.header_window_truncations = 0
        self.subscriber_drops = 0
        self.socket_drop_count = 0
        self.aux_vlan_recovered = 0
        self.last_packet_ns: int | None = None
        self.last_event: dict[str, Any] | None = None
        self.peak_bps = 0.0
        self.prev_rate_ns = time.monotonic_ns()
        self.prev_wire_bytes = 0
        self.current_bps = 0.0
        self.sysfs = Path("/sys/class/net") / interface / "statistics"
        self.rx_drop_baseline = read_int(self.sysfs / "rx_dropped")
        self.rx_missed_baseline = read_int(self.sysfs / "rx_missed_errors")

        self.packet_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.packet_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        try:
            self.packet_sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        except OSError:
            pass
        try:
            self.packet_sock.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
        except OSError:
            pass
        self.packet_sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        self.packet_sock.bind((interface, 0))
        self.packet_sock.setblocking(False)

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        self.server.listen(8)
        self.server.setblocking(False)
        self.clients: list[socket.socket] = []

    def stop(self, *_: Any) -> None:
        self.running = False

    def ancillary_metadata(
        self, ancdata: list[tuple[int, int, bytes]]
    ) -> tuple[int, int | None, int | None, int | None]:
        ts_ns = time.time_ns()
        drops: int | None = None
        aux_vlan_id: int | None = None
        aux_vlan_tpid: int | None = None
        for level, ctype, data in ancdata:
            if level == socket.SOL_SOCKET:
                if ctype == SO_TIMESTAMPNS and len(data) >= 16:
                    sec, nsec = struct.unpack_from("qq", data)
                    ts_ns = sec * 1_000_000_000 + nsec
                elif ctype == SO_RXQ_OVFL and len(data) >= 4:
                    drops = struct.unpack_from("I", data)[0]
            elif level == SOL_PACKET and ctype == PACKET_AUXDATA and len(data) >= 20:
                status, _tp_len, _tp_snaplen, _tp_mac, _tp_net, vlan_tci, vlan_tpid = struct.unpack_from(
                    "=IIIHHHH", data
                )
                if status & TP_STATUS_VLAN_VALID:
                    aux_vlan_id = vlan_tci & 0x0FFF
                    aux_vlan_tpid = vlan_tpid if status & TP_STATUS_VLAN_TPID_VALID else 0x8100
        return ts_ns, drops, aux_vlan_id, aux_vlan_tpid

    def broadcast(self, event: dict[str, Any]) -> None:
        if not self.clients:
            return
        payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        alive: list[socket.socket] = []
        for client in self.clients:
            try:
                client.sendall(payload)
                alive.append(client)
            except (BrokenPipeError, ConnectionResetError, BlockingIOError, OSError):
                self.subscriber_drops += 1
                try:
                    client.close()
                except OSError:
                    pass
        self.clients = alive

    def accept_clients(self) -> None:
        while True:
            try:
                client, _ = self.server.accept()
                client.setblocking(False)
                self.clients.append(client)
            except BlockingIOError:
                return

    def status(self) -> dict[str, Any]:
        now_ns = time.time_ns()
        carrier = read_int(Path("/sys/class/net") / self.interface / "carrier", -1)
        speed = read_int(Path("/sys/class/net") / self.interface / "speed", -1)
        rx_dropped = read_int(self.sysfs / "rx_dropped")
        rx_missed = read_int(self.sysfs / "rx_missed_errors")
        rx_drop_delta = max(0, rx_dropped - self.rx_drop_baseline)
        rx_missed_delta = max(0, rx_missed - self.rx_missed_baseline)
        freshness_s = None if self.last_packet_ns is None else (now_ns - self.last_packet_ns) / 1e9

        if carrier != 1:
            state = "NO_CARRIER"
        elif self.socket_drop_count > 0 or rx_drop_delta > 0 or rx_missed_delta > 0:
            state = "DROPPING"
        elif freshness_s is not None and freshness_s > 30:
            state = "STALE"
        else:
            state = "HEALTHY"

        return {
            "schema_version": "tcp-brain.capture-status.v1",
            "state": state,
            "interface": self.interface,
            "observation_point": self.observation_point,
            "allowed_vlans": sorted(self.vlans),
            "header_window_bytes": HEADER_WINDOW,
            "payload_persisted": False,
            "carrier": carrier == 1,
            "link_speed_mbps": speed,
            "packets_received": self.packets_received,
            "wire_bytes_received": self.wire_bytes,
            "events_emitted": self.events_emitted,
            "parse_errors": self.parse_errors,
            "header_window_truncations": self.header_window_truncations,
            "socket_drop_count": self.socket_drop_count,
            "aux_vlan_recovered": self.aux_vlan_recovered,
            "interface_rx_drop_delta": rx_drop_delta,
            "interface_rx_missed_delta": rx_missed_delta,
            "subscriber_drops": self.subscriber_drops,
            "current_bps": round(self.current_bps, 2),
            "peak_bps": round(self.peak_bps, 2),
            "last_packet_timestamp_ns": self.last_packet_ns,
            "freshness_seconds": None if freshness_s is None else round(freshness_s, 3),
            "started_timestamp_ns": self.started_ns,
            "last_event": self.last_event,
        }

    def update_rate(self) -> None:
        now = time.monotonic_ns()
        elapsed = (now - self.prev_rate_ns) / 1e9
        if elapsed < 0.5:
            return
        delta = self.wire_bytes - self.prev_wire_bytes
        self.current_bps = (delta * 8) / elapsed
        self.peak_bps = max(self.peak_bps, self.current_bps)
        self.prev_rate_ns = now
        self.prev_wire_bytes = self.wire_bytes

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        next_status = time.monotonic()
        ancbuf = socket.CMSG_SPACE(16) + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(20)
        buf = bytearray(HEADER_WINDOW)

        while self.running:
            readable, _, _ = select.select([self.packet_sock, self.server], [], [], 0.25)
            if self.server in readable:
                self.accept_clients()

            if self.packet_sock in readable:
                while True:
                    try:
                        nbytes, ancdata, _flags, packet_addr = self.packet_sock.recvmsg_into(
                            [buf], ancbuf, socket.MSG_TRUNC
                        )
                    except BlockingIOError:
                        break
                    except OSError:
                        self.parse_errors += 1
                        break

                    ts_ns, drops, aux_vlan_id, aux_vlan_tpid = self.ancillary_metadata(ancdata)
                    if drops is not None:
                        self.socket_drop_count = max(self.socket_drop_count, drops)
                    if aux_vlan_id is not None:
                        self.aux_vlan_recovered += 1
                    self.packets_received += 1
                    self.wire_bytes += nbytes
                    self.last_packet_ns = ts_ns
                    if nbytes > HEADER_WINDOW:
                        self.header_window_truncations += 1

                    self.seq += 1
                    captured_len = min(nbytes, HEADER_WINDOW)
                    try:
                        event = parse_frame(
                            memoryview(buf)[:captured_len],
                            nbytes,
                            ts_ns,
                            self.interface,
                            f"{ts_ns:x}-{self.seq:x}",
                            aux_vlan_id,
                            aux_vlan_tpid,
                            self.observation_point,
                            packet_addr[2] if len(packet_addr) > 2 else None,
                        )
                    except Exception:
                        self.parse_errors += 1
                        continue

                    if not event:
                        continue
                    vlan_id = event.get("vlan_id")
                    if vlan_id not in self.vlans:
                        continue

                    self.events_emitted += 1
                    self.last_event = event
                    self.broadcast(event)

            now = time.monotonic()
            if now >= next_status:
                self.update_rate()
                write_json_atomic(self.status_file, self.status())
                next_status = now + 1.0

        try:
            write_json_atomic(self.status_file, self.status())
        except OSError:
            pass
        for client in self.clients:
            try:
                client.close()
            except OSError:
                pass
        self.packet_sock.close()
        self.server.close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


def parse_vlans(value: str) -> set[int]:
    result: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = map(int, part.split("-", 1))
            result.update(range(lo, hi + 1))
        elif part:
            result.add(int(part))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="enp3s0")
    parser.add_argument("--status-file", type=Path, default=Path("/run/tcp-brain-capture/status.json"))
    parser.add_argument("--socket-path", type=Path, default=Path("/run/tcp-brain-capture/events.sock"))
    parser.add_argument("--vlans", default="210-217")
    parser.add_argument("--observation-point", default="unknown")
    args = parser.parse_args()

    collector = Collector(
        args.interface,
        args.status_file,
        args.socket_path,
        parse_vlans(args.vlans),
        args.observation_point,
    )
    print(
        json.dumps(
            {
                "event": "capture_started",
                "interface": args.interface,
                "observation_point": args.observation_point,
                "vlans": sorted(collector.vlans),
                "header_window_bytes": HEADER_WINDOW,
                "payload_persisted": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    collector.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
