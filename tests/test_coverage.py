"""Coverage fixtures: no physical device and no production event socket."""
import importlib.util
import ipaddress
import runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("coverage_flow",ROOT/"flow/tcp_brain_flow.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
legacy_event=runpy.run_path(str(ROOT/"tests/test_flow_analyzer.py"))["event"]
def event(*args,**kwargs):
    kwargs.setdefault("src_ip","198.18.0.10")
    kwargs.setdefault("dst_ip","198.18.0.2")
    kwargs.setdefault("src_mac","02:00:00:00:00:01")
    kwargs.setdefault("dst_mac","02:00:00:00:00:02")
    return legacy_event(*args,**kwargs)
T=100_000_000_000
MAC="02:00:00:00:00:02"
ENTS={"198.18.0.10":"synthetic-a","198.18.0.2":"synthetic-b"}
COUNTERS={k:0 for k in ("rx_dropped","rx_missed_errors","rx_errors","socket_drops","parse_errors","timestamp_missing","timestamp_regressions","l3_ambiguous")}
NAMES=("mirror","trunk")
NETWORK_MAP=((ipaddress.IPv4Network("198.18.0.0/29"),210),(ipaddress.IPv4Network("198.18.0.8/29"),211))
def fixture():
 return m.EvidenceGuard(NAMES),{n:m.StreamContinuity() for n in NAMES}
def marker(w,tracker,ts,seq=0,epoch="lab",healthy=True,vlans=(210,211),counters=None,now=None,source="trunk"):
 w.mark({"stream_epoch":epoch,"stream_seq":seq,"watermark_ns":ts,"healthy":healthy,"vlans":list(vlans),"counters":dict(COUNTERS if counters is None else counters)},tracker,ts if now is None else now,require_l3=source=="trunk")
def mark_all(g,t,ts,**kw):
 for n,w in g.windows.items():marker(w,t[n],ts,source=n,**kw)
def decision(g,started=T,deadline=T+50_000_000,now=T+60_000_000,connected=NAMES,vlans={210,211}):
 return g.decide(started,deadline,vlans,now,connected)
def core():
 return m.FlowAnalyzerCore(ENTS,router_mac=MAC,forward_timeout_ms=50,network_map=NETWORK_MAP)
def syn(t=T):
 return event(t,["SYN"])
def egress(t=T+1_000_000):
 return event(t,["SYN"],vlan=210,src_mac=MAC,dst_mac="02:00:00:00:00:02")
def test_marker_window_authorizes_only_bounded_interval():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 assert decision(g)[0]=="wait"
 mark_all(g,t,T+55_000_000)
 assert decision(g)[0]=="observed"
 assert decision(g,started=T-20_000_000)[0]=="inconclusive"
 assert decision(g,vlans={210,212})[0]=="inconclusive"
def test_no_watermark_fails_closed_after_grace():
 g,t=fixture()
 assert decision(g)[0]=="wait"
 assert decision(g,now=T+2_060_000_000)[0]=="inconclusive"
def test_source_disconnect_fails_closed():
 g,t=fixture();mark_all(g,t,T-10_000_000);mark_all(g,t,T+55_000_000)
 assert decision(g,connected=("trunk",))[0]=="inconclusive"
def test_loss_counter_invalidates_before_new_window():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 marker(g.windows["trunk"],t["trunk"],T+55_000_000,counters={**COUNTERS,"socket_drops":1})
 marker(g.windows["mirror"],t["mirror"],T+55_000_000,source="mirror")
 assert g.windows["trunk"].start is None and decision(g)[0]=="wait"
 marker(g.windows["trunk"],t["trunk"],T+60_000_000,counters={**COUNTERS,"socket_drops":1})
 assert decision(g,now=T+70_000_000)[0]=="inconclusive"
def test_epoch_change_and_marker_jump_never_fill_gap():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 w=g.windows["trunk"];tracker=t["trunk"]
 marker(w,tracker,T+55_000_000,seq=5)
 assert tracker.gaps==5 and w.start is None
 marker(w,tracker,T+56_000_000,seq=5)
 marker(w,tracker,T+57_000_000,seq=0,epoch="new")
 assert tracker.epoch_changes==1 and w.start is None
def test_old_clock_marker_and_invalid_health_rejected():
 g,t=fixture();w=g.windows["trunk"];tr=t["trunk"]
 marker(w,tr,T-10_000_000);marker(w,tr,T-20_000_000)
 assert w.start is None
 marker(w,tr,T,now=T+2_000_000_000)
 assert w.start is None
 marker(w,tr,T,healthy=False)
 assert w.start is None
 marker(w,tr,T,counters={**COUNTERS,"rx_errors":-1})
 assert w.start is None
def test_l3_ambiguity_in_authoritative_source_invalidates():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 for n,w in g.windows.items():marker(w,t[n],T+55_000_000,counters={**COUNTERS,"l3_ambiguous":1},source=n)
 assert g.windows["mirror"].start is not None and g.windows["trunk"].start is None
def test_late_egress_arrives_before_watermark_no_false_path_alarm():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 c=core();c.ingest(syn(),"trunk")
 gate=lambda a,b,v,n:g.decide(a,b,v,n,NAMES)
 assert c.expire(T+70_000_000,gate)==[] and len(c.forward_pending)==1
 c.ingest(egress(),"trunk")
 mark_all(g,t,T+90_000_000)
 assert c.expire(T+100_000_000,gate)==[] and c.forward_ok_total==1
def test_egress_arrival_before_ingress_with_valid_timestamp_order():
 c=core();c.ingest(egress(),"trunk");c.ingest(syn(),"trunk")
 assert c.forward_ok_total==1 and not c.forward_pending
def test_real_observed_absence_is_not_claim_of_router_failure():
 g,t=fixture();mark_all(g,t,T-10_000_000);mark_all(g,t,T+55_000_000)
 c=core();c.ingest(syn(),"trunk")
 out=c.expire(T+60_000_000,lambda a,b,v,n:g.decide(a,b,v,n,NAMES))
 assert len(out)==1 and out[0]["anomaly_type"]=="INTER_VLAN_EGRESS_MISSING"
 assert out[0]["network_fault_confirmed"] is False and out[0]["observation_coverage"]=="BOUNDED_WINDOW"
def test_gap_does_not_increment_network_anomaly_counter():
 g,t=fixture();mark_all(g,t,T-10_000_000);mark_all(g,t,T+55_000_000)
 g.windows["trunk"].invalidate("stream_discontinuity")
 c=core();c.ingest(syn(),"trunk")
 out=c.expire(T+2_060_000_000,lambda a,b,v,n:g.decide(a,b,v,n,NAMES))
 assert out and all(x["event_type"]=="OBSERVATION_INCONCLUSIVE" and "anomaly_type" not in x for x in out)
 assert c.forward_missing_total==c.anomalies_total==0 and c.observation_inconclusive_total==len(out)
def test_rst_is_still_positive_observation():
 c=core();c.ingest(syn(),"trunk")
 out=c.ingest(event(T+1_000_000,["RST","ACK"],src_ip="198.18.0.2",src_port=9223,dst_ip="198.18.0.10",dst_port=44001,seq=0,ack=101,vlan=210),"trunk")
 assert len(out)==1 and out[0]["anomaly_type"]=="CONNECTION_REJECTED"
def test_handshake_timeout_waits_for_coverage():
 g,t=fixture();mark_all(g,t,T-10_000_000)
 c=m.FlowAnalyzerCore(ENTS,handshake_timeout_s=2.0,network_map=NETWORK_MAP);c.ingest(syn(),"trunk")
 gate=lambda a,b,v,n:g.decide(a,b,v,n,NAMES)
 assert c.expire(T+2_100_000_000,gate)==[]
 # A response captured on time but delivered later still suppresses timeout.
 c.ingest(event(T+1_900_000_000,["SYN","ACK"],src_ip="198.18.0.2",src_port=9223,dst_ip="198.18.0.10",dst_port=44001,seq=500,ack=101,vlan=210),"mirror")
 mark_all(g,t,T+2_200_000_000)
 assert not c.expire(T+2_300_000_000,gate)
