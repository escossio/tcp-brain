import importlib.util
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "flow" / "tcp_brain_flow.py"
spec = importlib.util.spec_from_file_location("tcp_brain_flow", MODULE)
flowmod = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(flowmod)


def event(
    ts_ns: int,
    flags: list[str],
    *,
    seq: int = 100,
    ack: int = 0,
    vlan: int = 211,
    src_ip: str = "10.77.10.10",
    src_port: int = 44001,
    dst_ip: str = "10.77.10.2",
    dst_port: int = 9223,
    src_mac: str = "0e:d9:dc:92:45:99",
    dst_mac: str = "48:8f:5a:02:06:89",
):
    raw = 0
    for name, bit in {"FIN":1,"SYN":2,"RST":4,"PSH":8,"ACK":16}.items():
        if name in flags:
            raw |= bit
    return {
        "capture_timestamp_ns": ts_ns,
        "protocol": "TCP",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "tcp_flags": flags,
        "tcp_flags_raw": raw,
        "seq": seq,
        "ack": ack,
        "payload_length": 0,
        "vlan_id": vlan,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "wire_length": 78,
    }


def test_handshake_incomplete_and_dedup():
    core = flowmod.FlowAnalyzerCore(
        {"10.77.10.10": "transport", "10.77.10.2": "browser"},
        handshake_timeout_s=2.0,
        dedupe_window_ms=5.0,
    )
    t0 = 1_000_000_000
    syn = event(t0, ["SYN"])
    assert core.ingest(syn, "trunk") == []

    duplicate = dict(syn)
    duplicate["capture_timestamp_ns"] = t0 + 1_000_000
    assert core.ingest(duplicate, "mirror") == []

    retry = event(t0 + 1_000_000_000, ["SYN"])
    assert core.ingest(retry, "trunk") == []

    out = core.expire(t0 + 2_100_000_000)
    assert len(out) == 1
    anomaly = out[0]
    assert anomaly["anomaly_type"] == "HANDSHAKE_INCOMPLETE"
    assert anomaly["syn_count"] == 2
    assert anomaly["syn_retries"] == 1
    assert anomaly["synack_count"] == 0
    assert anomaly["src_service"] == "transport"
    assert anomaly["dst_service"] == "browser"
    assert anomaly["observed_vlans"] == [211]
    assert anomaly["capture_sources"] == ["mirror", "trunk"]
    assert anomaly["ai_used"] is False
    assert anomaly["evidence"]["payload_observed"] is False


def test_successful_handshake_has_no_anomaly():
    core = flowmod.FlowAnalyzerCore({}, handshake_timeout_s=2.0)
    t0 = 10_000_000_000
    core.ingest(event(t0, ["SYN"]), "trunk")
    core.ingest(event(
        t0 + 10_000_000, ["SYN", "ACK"],
        src_ip="10.77.10.2", src_port=9223,
        dst_ip="10.77.10.10", dst_port=44001,
        seq=500, ack=101, vlan=210,
    ), "trunk")
    core.ingest(event(
        t0 + 20_000_000, ["ACK"],
        seq=101, ack=501,
    ), "trunk")
    assert core.expire(t0 + 3_000_000_000) == []
    assert core.established_total == 1


def test_rst_before_synack_emits_rejected():
    core = flowmod.FlowAnalyzerCore({}, handshake_timeout_s=2.0)
    t0 = 20_000_000_000
    core.ingest(event(t0, ["SYN"]), "trunk")
    out = core.ingest(event(
        t0 + 10_000_000, ["RST", "ACK"],
        src_ip="10.77.10.2", src_port=9223,
        dst_ip="10.77.10.10", dst_port=44001,
        seq=0, ack=101, vlan=210,
    ), "trunk")
    assert len(out) == 1
    assert out[0]["anomaly_type"] == "CONNECTION_REJECTED"
    assert out[0]["rst_count"] == 1


def test_syn_after_synack_does_not_claim_missing_synack():
    core = flowmod.FlowAnalyzerCore({}, handshake_timeout_s=2.0)
    t0 = 30_000_000_000
    core.ingest(event(t0, ["SYN"]), "trunk")
    core.ingest(event(
        t0 + 10_000_000, ["SYN", "ACK"],
        src_ip="10.77.10.2", src_port=9223,
        dst_ip="10.77.10.10", dst_port=44001,
        seq=500, ack=101, vlan=210,
    ), "mirror")
    core.ingest(event(t0 + 1_000_000_000, ["SYN"]), "trunk")
    assert core.expire(t0 + 3_000_000_000) == []


def test_l2_mirror_witness_correlates_with_trunk_syn():
    core = flowmod.FlowAnalyzerCore({}, handshake_timeout_s=2.0)
    t0 = 40_000_000_000
    mirror = {
        "capture_timestamp_ns": t0 + 50_000,
        "decode_quality": "L2_ONLY_8023_OR_MIRROR_ARTIFACT",
        "src_mac": "0e:d9:dc:92:45:99",
        "dst_mac": "48:8f:5a:02:06:89",
        "vlan_id": 211,
        "wire_length": 74,
    }
    core.ingest(mirror, "mirror")
    syn = event(t0, ["SYN"])
    syn.update({
        "src_mac": "0e:d9:dc:92:45:99",
        "dst_mac": "48:8f:5a:02:06:89",
        "wire_length": 78,
    })
    core.ingest(syn, "trunk")
    out = core.expire(t0 + 2_100_000_000)
    assert len(out) == 1
    assert out[0]["evidence"]["physical_mirror_witness"] is True
    assert "mirror-l2-witness" in out[0]["capture_sources"]


def test_inter_vlan_missing_egress_localizes_router():
    entities = {"10.77.10.10": "transport", "10.77.10.2": "browser"}
    core = flowmod.FlowAnalyzerCore(
        entities,
        handshake_timeout_s=2.0,
        router_mac="48:8f:5a:02:06:89",
        forward_timeout_ms=50.0,
    )
    t0 = 50_000_000_000
    mirror = {
        "capture_timestamp_ns": t0 + 50_000,
        "decode_quality": "L2_ONLY_8023_OR_MIRROR_ARTIFACT",
        "src_mac": "0e:d9:dc:92:45:99",
        "dst_mac": "48:8f:5a:02:06:89",
        "vlan_id": 211,
        "wire_length": 74,
    }
    core.ingest(mirror, "mirror")
    core.ingest(event(t0, ["SYN"]), "trunk")
    out = core.expire(t0 + 60_000_000)
    assert len(out) == 1
    path = out[0]
    assert path["event_type"] == "PATH_ANOMALY"
    assert path["anomaly_type"] == "INTER_VLAN_EGRESS_MISSING"
    assert path["ingress_vlan"] == 211
    assert path["expected_egress_vlan"] == 210
    assert path["physical_ingress_witness"] is True
    assert path["egress_observed"] is False


def test_inter_vlan_egress_clears_pending():
    entities = {"10.77.10.10": "transport", "10.77.10.2": "browser"}
    core = flowmod.FlowAnalyzerCore(
        entities,
        handshake_timeout_s=2.0,
        router_mac="48:8f:5a:02:06:89",
        forward_timeout_ms=50.0,
    )
    t0 = 60_000_000_000
    core.ingest(event(t0, ["SYN"]), "trunk")
    egress = event(
        t0 + 1_000_000,
        ["SYN"],
        vlan=210,
        src_mac="48:8f:5a:02:06:89",
        dst_mac="d0:00:05:35:29:b6",
    )
    core.ingest(egress, "trunk")
    assert core.forward_ok_total == 1
    assert core.forward_pending == {}
    assert core.expire(t0 + 100_000_000) == []


if __name__ == "__main__":
    test_handshake_incomplete_and_dedup()
    test_successful_handshake_has_no_anomaly()
    test_rst_before_synack_emits_rejected()
    test_syn_after_synack_does_not_claim_missing_synack()
    test_l2_mirror_witness_correlates_with_trunk_syn()
    test_inter_vlan_missing_egress_localizes_router()
    test_inter_vlan_egress_clears_pending()
    print("PASS")
