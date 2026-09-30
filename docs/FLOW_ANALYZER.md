# TCP Brain Flow Analyzer

The flow analyzer consumes metadata-only events from the passive capture plane.
It does not read or persist application payload and does not call AI.

Inputs:
- `mirror`: physical SPAN witness from MikroTik ether2 -> ether5 -> AGT enp3s0.
- `trunk`: temporary authoritative L3/L4 validation sensor on AGT enp1s0.

The trunk input exists because some QCA8337 mirrored frames arrive as valid
L2 evidence but without a trustworthy L3/L4 EtherType. Those frames are not
guessed or force-decoded.
The analyzer deduplicates the same L3/L4 packet when it is observed at more
than one observation point within a small time window. A later repeated SYN
is therefore treated as a retry, not as a SPAN duplicate.

Current state machine tracks:
- SYN
- SYN/ACK
- ACK
- RST
- FIN
- SYN retries
- observed VLANs
- capture sources
- handshake timeout

Current anomaly events:
- `HANDSHAKE_INCOMPLETE`
- `CONNECTION_REJECTED`
Runtime outputs:
- status: `/run/tcp-brain-flow/status.json`
- event stream: `/run/tcp-brain-flow/events.sock`
- journal: `tcp-brain-flow.service`

Entity labels are loaded read-only from the Attention Router ROC entity
inventory. The analyzer does not write to the historical TCP Brain database.

The next integration stage may feed validated flow events into the TCP Brain
pattern/knowledge layer. Packet-level LLM calls are explicitly out of scope.


## Inter-VLAN path localization

For Attention Router endpoint traffic, the analyzer also follows TCP SYN packets
across the MikroTik routing hop. The source VLAN is derived from the current
10.77.10.0/26 runtime layout, and the router MAC is supplied explicitly by the
systemd unit.

A SYN seen on the authoritative trunk with endpoint -> router MAC creates a
short-lived forwarding expectation. The same routed TCP signature must then be
observed router -> endpoint on the destination VLAN. If the egress copy is not
seen within the forwarding window, the analyzer emits:

- `INTER_VLAN_EGRESS_MISSING`
- schema `tcp-brain.path.v1`
- ingress VLAN and expected egress VLAN
- physical ingress mirror witness when available
- no payload and no AI

The routed packet signature excludes VLAN and MAC addresses so the ingress and
egress copies can be correlated across the L3 hop. Flow-level deduplication uses
that routed signature, while path localization executes before deduplication.

A physical mirror witness may be L2-only when the QCA8337 mirror path presents
an unreliable EtherType. In that case the analyzer does not guess L3 fields;
it correlates MAC/VLAN/wire-length/timestamp evidence with the authoritative
trunk event.

The first certified production case was Transport VLAN 211 to Browser/CDP
VLAN 210. The SYN was observed on VLAN 211 and confirmed by the physical
mirror, while no corresponding VLAN 210 egress was observed. A temporary,
exact-match RouterOS raw-prerouting passthrough counter remained at zero for
that TCP attempt, while an equivalent ICMP-to-gateway raw counter incremented
3/3. Both temporary diagnostic rules were removed immediately afterward.
