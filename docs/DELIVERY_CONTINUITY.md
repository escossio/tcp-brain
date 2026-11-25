# Bounded distribution and observation continuity

Status: proposed V2; validation and operator approval required before rollout.
This change intentionally retains single-threaded correlation. A separate reader
thread did not pass the highest end-to-end synthetic load and is not included.

## Distribution
The capture process emits metadata only. A nonblocking bounded FIFO per
subscriber accepts up to 1,024 queued records and 1 MiB of record bytes
(excluding interpreter and kernel overhead). Maximum eight peers. Batches are
limited to 64 records/64 KiB; partial writes continue from their offset.
EAGAIN retains pending records and is counted separately from disconnects.
An overflowing slow subscriber is evicted without blocking other clients or
capture; queued discarded records and reason are reported. No replay or ACK:
handoff to the kernel does not prove consumer receipt.

## Evidence
Sequence is assigned after VLAN filtering; epoch identifies the capture process.
Coverage markers share the FIFO and do not increment data sequence. A marker is
emitted after AF_PACKET reads would block, with a conservative 10 ms margin and
100 ms target cadence when the capture queue is drained. PACKET_STATISTICS
interval counters are accumulated independently; interface/parse/time/stream
integrity and scope matter. A marker is an operational observation bound, not
proof of zero loss everywhere on the physical wire. Under sustained traffic,
marker delay or ambiguity may make observation inconclusive.

Flow maintains a window per source. Negative conclusions need all configured
sources and authoritative trunk coverage of both VLANs. Missing or invalid
coverage produces OBSERVATION_INCONCLUSIVE after bounded wait, not a confirmed
network fault. PATH_ANOMALY / INTER_VLAN_EGRESS_MISSING retains its legacy event
type but explicitly indicates network_fault_confirmed=false for a bounded
observation. Downstream consumers must be verified not to infer root cause from
that type alone. Positive packet evidence continues to be processed.

## Configuration
The optional --network-map JSON supplies explicit nonoverlapping IPv4 CIDRs and
VLAN IDs; unknown addresses return unknown scope. Without it, the preexisting
default map is preserved for compatibility. Example (synthetic):
```json
{"networks":[{"cidr":"198.18.0.0/29","vlan":310},{"cidr":"198.18.0.8/29","vlan":312}]}
```
Set the map, entity registry, allowed VLANs and router identity outside the
public repository. The additive forward_ok_by_vlan field counts observed
forwarding by source->destination VLAN. No deployment-specific inventory in
the diff. Legacy readers consuming raw capture streams must handle COVERAGE
records separately. Integration with external consumers is a rollout gate.

## Validation and rollback
Run python -B tests/run_tests.py. Validate a coherent version of both collectors
and the correlator in isolated environments. Compare capture loss, distribution
overflow, sequence gaps, timestamps, coverage and resource utilization.
Retain exact prior config, binaries and status snapshots; restart only authorized
units in a controlled window and verify both sources and existing endpoints.
Rollback restores the previously certified artifacts and private configuration;
do not reset or clear counters to conceal failures. Real-world soak and reboot
certification are separate. No automatic deployment or schema change.
