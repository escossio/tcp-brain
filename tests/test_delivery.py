"""Synthetic tests for bounded distribution and stream continuity."""
import importlib.util, socket, select, json, errno, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
capture=load('capture_candidate',ROOT/'capture/tcp_brain_capture.py')
flow=load('flow_candidate',ROOT/'flow/tcp_brain_flow.py')
class Fake:
 def __init__(self,actions):self.actions=iter(actions);self.written=bytearray()
 def sendmsg(self,parts):
  b=b''.join(parts);a=next(self.actions,len(b))
  if isinstance(a,Exception):raise a
  n=min(a,len(b));self.written.extend(b[:n]);return n
def test_partial_write_and_eagain_preserve_exact_stream():
 s=Fake([2,BlockingIOError(errno.EAGAIN,'busy'),4,100]);q=capture.SubscriberQueue(s)
 assert q.enqueue(b'abc\n') and q.enqueue(b'def\n')
 q.flush();assert q.offset==2 and q.completed==0 and q.pending_bytes==6
 q.flush();assert q.offset==2 and q.backpressure==1
 q.flush();assert q.completed==1 and q.offset==2 and q.pending_bytes==2
 q.flush();assert q.completed==2 and not q.frames and q.allocated_bytes==q.pending_bytes==0
 assert bytes(s.written)==b'abc\ndef\n' and q.partial_writes==2
def test_bounded_records_and_bytes_include_partial_allocation():
 q=capture.SubscriberQueue(Fake([1,100]),max_records=2,max_bytes=8)
 assert q.enqueue(b'abcd') and q.enqueue(b'efgh') and not q.enqueue(b'x')
 q.flush();assert q.allocated_bytes==8 and q.pending_bytes==7 and not q.enqueue(b'x')
 q.flush();assert q.enqueue(b'x') and not q.enqueue(b'12345678')
def test_real_socket_backpressure_recovers():
 a,b=socket.socketpair();a.setblocking(False);b.setblocking(False);a.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
 q=capture.SubscriberQueue(a,max_records=200,max_bytes=256000)
 expected=b''.join((str(i).encode()+b':'+b'x'*850+b'\n') for i in range(180))
 try:
  for line in expected.splitlines(keepends=True):assert q.enqueue(line)
  for _ in range(50):
   q.flush()
   if q.backpressure:break
  assert q.backpressure and q.frames
  output=bytearray();end=time.monotonic()+3
  while q.frames or len(output)<len(expected):
   if time.monotonic()>end:raise AssertionError('drain timeout')
   q.flush()
   while True:
    try:data=b.recv(65536)
    except BlockingIOError:break
    assert data;output.extend(data)
  assert bytes(output)==expected and q.completed==180 and q.pending_bytes==0
 finally:a.close();b.close()
def collector():
 c=capture.Collector.__new__(capture.Collector)
 c.clients={}
 for k in ('subscriber_backpressure','subscriber_partial_writes','subscriber_queue_overflows','subscriber_peer_closed','subscriber_write_errors','subscriber_rejected','subscriber_queue_records_discarded','subscriber_queue_peak_bytes','subscriber_frames_written','subscriber_drops'):setattr(c,k,0)
 return c
def test_slow_peer_overflow_does_not_disconnect_healthy_peer():
 a,b=socket.socketpair();x,y=socket.socketpair()
 for s in (a,b,x,y):s.setblocking(False)
 c=collector();c.clients={a:capture.SubscriberQueue(a,max_records=2),x:capture.SubscriberQueue(x,max_records=10)}
 try:
  for i in range(3):
   c.broadcast({'stream_epoch':'e','stream_seq':i+1})
   c.flush_client(x)
  assert a not in c.clients and x in c.clients
  assert c.subscriber_queue_overflows==1 and c.subscriber_queue_records_discarded==3 and c.subscriber_drops==1
  d=y.recv(65536);assert [json.loads(l)['stream_seq'] for l in d.splitlines()]==[1,2,3]
 finally:
  for s in (a,b,x,y):s.close()
def test_peer_closed_separate_from_backpressure():
 a,b=socket.socketpair();a.setblocking(False)
 c=collector();c.clients[a]=capture.SubscriberQueue(a)
 try:
  b.close();c.broadcast({'stream_seq':1});c.flush_client(a)
  assert not c.clients and c.subscriber_peer_closed==1 and c.subscriber_backpressure==0 and c.subscriber_queue_overflows==0
 finally:a.close();b.close()
def test_stream_sequence_and_epochs():
 t=flow.StreamContinuity()
 for event in ({'stream_epoch':'a','stream_seq':17},{'stream_epoch':'a','stream_seq':18},{'stream_epoch':'a','stream_seq':21},{'stream_epoch':'a','stream_seq':21},{'stream_epoch':'b','stream_seq':1},{}):t.observe(event)
 assert t.gaps==2 and t.out_of_order==1 and t.epoch_changes==1 and t.unverified==1 and t.seq==1
def test_consumer_partial_json_and_disconnect_continuity():
 with tempfile.TemporaryDirectory() as td:
  p=Path(td);d=flow.FlowDaemon({'mirror':p/'m','trunk':p/'t'},p/'events.sock',p/'status.json',flow.FlowAnalyzerCore({}))
  a,b=socket.socketpair();d.sources['mirror']=a
  try:
   b.sendall(b'{"stream_epoch":"a","stream_seq":1}\n{"stream_')
   d.consume('mirror');assert d.input_events==1 and d.buffers['mirror']
   b.sendall(b'epoch":"a","stream_seq":3}\n')
   d.consume('mirror');assert d.input_events==2 and d.continuity['mirror'].gaps==1
   assert d.status()['state']=='DEGRADED'
   b.sendall(b'{"stream_');d.consume('mirror');b.close();d.consume('mirror')
   assert d.continuity['mirror'].disconnects==1 and d.continuity['mirror'].invalid_records==1
   assert d.status()['state']=='NO_INPUT'
  finally:a.close();b.close();d.server.close()
def test_batched_writer_sustained_and_pause():
 # 50 bursts × 150 metadata records; periodic pauses without disconnect.
 a,b=socket.socketpair();a.setblocking(False);b.setblocking(False)
 q=capture.SubscriberQueue(a);got=bytearray();expected=bytearray()
 try:
  for burst in range(50):
   for j in range(150):
    line=(json.dumps({'stream_epoch':'synthetic','stream_seq':burst*150+j+1,'padding':'x'*780},separators=(',',':'))+'\n').encode()
    assert q.enqueue(line);expected.extend(line)
   for _ in range(5):q.flush()
   # A finite pause every tenth burst; remaining capacity must absorb it.
   if burst%10==0:continue
   end=time.monotonic()+1
   while q.frames or len(got)<len(expected):
    if time.monotonic()>end:raise AssertionError('drain timeout')
    q.flush()
    while True:
     try:d=b.recv(65536)
     except BlockingIOError:break
     assert d;got.extend(d)
  assert got==expected and q.completed==7500 and not q.frames
 finally:a.close();b.close()
