import importlib.util
import socket
import struct
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "capture" / "tcp_brain_capture.py"
spec = importlib.util.spec_from_file_location("tcp_brain_capture", MODULE)
capture = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(capture)


def build_vlan_ipv4_tcp(vlan: int, flags: int = 0x02) -> bytes:
    dst = bytes.fromhex("488f5a020689")
    src = bytes.fromhex("0ed9dc924599")
    ethernet = dst + src + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    src_ip = socket.inet_aton("10.77.10.10")
    dst_ip = socket.inet_aton("10.77.10.2")
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0, 64, 6, 0, src_ip, dst_ip
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        44001, 9223, 1234, 0, 0x50, flags, 64240, 0, 0
    )
    return ethernet + ip + tcp


def test_vlan_tcp_syn_metadata_only():
    frame = build_vlan_ipv4_tcp(211)
    event = capture.parse_frame(frame, len(frame), 123456789, "enp3s0", "evt-1")
    assert event["vlan_id"] == 211
    assert event["src_ip"] == "10.77.10.10"
    assert event["dst_ip"] == "10.77.10.2"
    assert event["src_port"] == 44001
    assert event["dst_port"] == 9223
    assert event["tcp_flags"] == ["SYN"]
    assert event["payload_length"] == 0
    assert "payload" not in event
    assert "raw" not in event



def test_mirror_length_field_is_not_inferred_as_ip():
    frame = bytearray(build_vlan_ipv4_tcp(211))
    stripped = bytes(frame[0:12] + bytes.fromhex("0028") + frame[18:])
    event = capture.parse_frame(
        stripped,
        len(stripped),
        123456790,
        "enp3s0",
        "evt-2",
        aux_vlan_id=211,
        aux_vlan_tpid=0x8100,
    )
    assert event["vlan_id"] == 211
    assert event["ethertype"] == "0x0028"
    assert event["decode_quality"] == "L2_ONLY_8023_OR_MIRROR_ARTIFACT"
    assert "src_ip" not in event
    assert "dst_ip" not in event


if __name__ == "__main__":
    test_vlan_tcp_syn_metadata_only()
    test_mirror_length_field_is_not_inferred_as_ip()
    print("PASS")
