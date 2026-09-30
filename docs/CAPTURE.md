# Passive capture plane

tcp-brain-capture.service observes the MikroTik ether2 bidirectional mirror
delivered through ether5 to AGT enp3s0.

The capture NIC is L2-only: no IPv4, IPv6, bridge, route, or VLAN child.

The collector reads only a bounded 104-byte header window from each frame.
It never persists raw frames or application payload. It emits structured
L2/L3/L4 metadata for VLANs 210-217 over
/run/tcp-brain-capture/events.sock and writes aggregate sensor health to
/run/tcp-brain-capture/status.json.

The existing TCP Brain backend, database, pattern table, and AI path are not
used by this collector.
