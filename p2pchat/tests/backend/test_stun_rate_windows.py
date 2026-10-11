"""Deterministic callback-arrival policy tests; no assumed OS send throughput."""
import struct
import asyncio
import socket
import time
import pytest
from p2pchat.server import Stun,Store as PersistentStore,stun_binding

REQUEST=struct.pack('!HHI',1,0,0x2112A442)+b'123456789012'
class Clock:
    def __init__(self):self.now=100.0
    def __call__(self):return self.now
class Store:
    def __init__(self,clock,cost=0):self.clock=clock;self.cost=cost;self.events=0
    def event(self,*args):self.events+=1;self.clock.now+=self.cost
class Transport:
    def __init__(self):self.replies=[]
    def sendto(self,data,addr):self.replies.append((data,addr))
def endpoint(cost=0):
    clock=Clock();store=Store(clock,cost);protocol=Stun(store,clock=clock);transport=Transport();protocol.connection_made(transport)
    return clock,store,protocol,transport

@pytest.mark.parametrize('address',['192.0.2.1','2001:db8::1'])
def test_per_source_port_changes_do_not_reset_budget_and_exact_window(address):
    clock,store,p,t=endpoint()
    for port in range(26):p.datagram_received(REQUEST,(address,10000+port))
    assert len(t.replies)==20 and store.events==20
    clock.now=100.999
    p.datagram_received(REQUEST,(address,15000));assert len(t.replies)==20
    clock.now=101.0
    p.datagram_received(REQUEST,(address,15000))
    assert len(t.replies)==21 and p.total==1 and p.buckets=={address:1}

def test_global_budget_and_reset_are_independent_of_source_budget():
    clock,store,p,t=endpoint()
    for i in range(1001):
        p.datagram_received(REQUEST,(f'2001:db8::{i+1:x}',1234))
    assert len(t.replies)==1000 and store.events==1000
    assert p.total==1001 and len(p.buckets)==1000
    clock.now=101.0;p.datagram_received(REQUEST,('2001:db8::9999',1234))
    assert len(t.replies)==1001 and p.total==1 and len(p.buckets)==1

def test_invalid_datagrams_still_consume_abuse_budget():
    clock,store,p,t=endpoint()
    for _ in range(20):p.datagram_received(b'bad',('192.0.2.1',1234))
    p.datagram_received(REQUEST,('192.0.2.1',1234))
    assert not t.replies and store.events==0
    clock.now+=1;p.datagram_received(REQUEST,('192.0.2.1',1234))
    assert len(t.replies)==1

def test_slow_callbacks_can_legitimately_span_multiple_fixed_windows():
    # Simulate 60ms synchronous logging cost per permitted response. This is a
    # causal counterexample, not a measurement of the Windows SQLite duration.
    clock,store,p,t=endpoint(cost=.06)
    p.datagram_received(REQUEST,('192.0.2.1',1234))
    baseline=len(t.replies);windows={}
    for _ in range(25):
        before=len(t.replies);p.datagram_received(REQUEST,('192.0.2.1',1234))
        if len(t.replies)>before:windows[p.window]=windows.get(p.window,0)+1
    assert len(t.replies)-baseline==25  # same old failing observation, legal here
    assert len(windows)==2 and all(count<=20 for count in windows.values())
    assert clock.now>101 and store.events==26


@pytest.mark.asyncio
@pytest.mark.parametrize('address,family',[('127.0.0.1',socket.AF_INET),('::1',socket.AF_INET6)])
async def test_production_default_clock_real_binding_and_window_reset(tmp_path,address,family):
    loop=asyncio.get_running_loop();store=PersistentStore(tmp_path)
    transport,p=await loop.create_datagram_endpoint(lambda:Stun(store),local_addr=(address,0),family=family)
    sock=socket.socket(family,socket.SOCK_DGRAM);sock.bind((address,0));sock.setblocking(False)
    try:
        assert p.clock is time.monotonic
        remote=transport.get_extra_info('sockname')
        await loop.sock_sendto(sock,REQUEST,remote)
        response,_=await asyncio.wait_for(loop.sock_recvfrom(sock,1024),2)
        assert response==stun_binding(REQUEST,sock.getsockname())
        previous=p.window
        # Wait for the actual production clock to cross its window; no guessed
        # batch speed, and no fabricated change to counters or timestamps.
        async with asyncio.timeout(3):
            while p.clock()-previous<1:await asyncio.sleep(.02)
        await loop.sock_sendto(sock,REQUEST,remote)
        response,_=await asyncio.wait_for(loop.sock_recvfrom(sock,1024),2)
        assert response==stun_binding(REQUEST,sock.getsockname())
        assert p.window-previous>=1 and p.total==1 and p.buckets[address]==1
    finally:sock.close();transport.close();store.close()
