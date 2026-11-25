"""Configurable mapping: private local sockets and synthetic addresses."""
import importlib.util,json,queue,socket,tempfile,time,ipaddress,runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("threaded_flow",ROOT/"flow/tcp_brain_flow.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def test_explicit_network_map_rejects_overlap_and_unknown():
 with tempfile.TemporaryDirectory() as td:
  p=Path(td)/"map.json";a={"cidr":"198.18.0.0/29","vlan":310};b={"cidr":"198.18.0.8/29","vlan":312}
  p.write_text(json.dumps({"networks":[a,b]}));c=m.FlowAnalyzerCore({},network_map=m.load_network_map(p))
  assert c.vlan_for_ip("198.18.0.2")==310 and c.vlan_for_ip("198.18.0.10")==312
  assert c.vlan_for_ip("198.18.1.2") is None and c.vlan_for_ip("not-ip") is None
  p.write_text(json.dumps({"networks":[a,{"cidr":"198.18.0.0/28","vlan":313}]}))
  try:m.load_network_map(p)
  except ValueError:pass
  else:raise AssertionError("overlap accepted")
def test_forward_counter_for_generic_vlan_pair():
 fixture=runpy.run_path(str(ROOT/"tests/test_flow_analyzer.py"))["event"]
 mac="02:00:00:00:00:02";a="198.18.0.10";b="198.18.0.2"
 c=m.FlowAnalyzerCore({a:"a",b:"b"},router_mac=mac,network_map=((ipaddress.IPv4Network("198.18.0.0/29"),310),(ipaddress.IPv4Network("198.18.0.8/29"),312)))
 c.ingest(fixture(1000000000,["SYN"],vlan=312,src_ip=a,dst_ip=b,src_mac="02:00:00:00:00:01",dst_mac=mac),"trunk")
 c.ingest(fixture(1001000000,["SYN"],vlan=310,src_ip=a,dst_ip=b,src_mac=mac,dst_mac="02:00:00:00:00:03"),"trunk")
 assert c.forward_ok_total==1 and c.forward_ok_by_vlan=={"312->310":1}
