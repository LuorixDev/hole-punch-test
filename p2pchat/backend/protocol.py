"""Closed signaling schemas; no arbitrary forwarding and no network I/O."""
import ipaddress
import re
from cryptography import x509
from .telemetry import uid

PROFILES=('ice-v6','ice-v4','ice-dual')
MECHANISMS={'webrtc','udp-probe','quic','tcp','tcp-simopen','upnp','pcp','natpmp'}
class ProtocolError(ValueError): pass

def check(ok,code='SCHEMA_INVALID'):
    if not ok: raise ProtocolError(code)

def fields(data,required,optional=()):
    check(isinstance(data,dict) and set(required)<=set(data) and set(data)<=set(required)|set(optional))

def string(value,maximum,minimum=1):
    check(isinstance(value,str) and minimum<=len(value.encode())<=maximum)

def join(data):
    fields(data,{'v','type','room','secret','name','clientSessionId','capabilities'})
    check(data['v']==1,'UNSUPPORTED_VERSION'); check(data['type']=='join')
    for key,lo,hi in [('room',1,64),('secret',8,256),('name',1,48)]: string(data[key],hi,lo)
    uid(data['clientSessionId'])
    caps=data['capabilities']
    check(isinstance(caps,list) and len(caps)<=8 and all(x in MECHANISMS for x in caps))

def candidate(raw):
    string(raw,2048)
    parts=raw.removeprefix('a=').removeprefix('candidate:').split()
    check(len(parts)>=8 and len(parts)%2==0 and parts[6]=='typ')
    check(parts[7]!='relay','RELAY_FORBIDDEN')
    check(parts[7] in {'host','srflx','prflx'} and parts[2].lower() in {'udp','tcp'})
    try: numeric=1<=int(parts[1])<=2 and 0<=int(parts[3])<=2**32-1 and 1<=int(parts[5])<=65535
    except ValueError: numeric=False
    check(numeric)
    try: ip=ipaddress.ip_address(parts[4])
    except ValueError: check(bool(re.fullmatch(r'[a-zA-Z0-9-]{1,63}\.local',parts[4])))
    else: check(not (ip.is_multicast or ip.is_unspecified or str(ip)=='255.255.255.255'))
    return parts

def signal(data):
    fields(data,{'v','type','to','connectionId','attemptId','mechanism','profile'}, {'description','candidate','nativeCandidate','retry','endOfCandidates'})
    check(data['v']==1,'UNSUPPORTED_VERSION')
    uid(data['connectionId']); uid(data['attemptId']); string(data['to'],100)
    check(data['mechanism'] in MECHANISMS)
    string(data['profile'],48)
    if data['mechanism']=='webrtc': check(data['profile'] in PROFILES)
    else: check(data['profile'] in MECHANISMS|{'default','direct','ipv4','ipv6'})
    payloads=set(data)&{'description','candidate','nativeCandidate','retry'}
    check(len(payloads)==1)
    if 'description' in data:
        desc=data['description']; fields(desc,{'type','sdp'})
        check(desc['type'] in {'offer','answer'}); string(desc['sdp'],65536)
        check('endOfCandidates' not in data)
        if data['mechanism']=='webrtc':
            count=0
            for line in desc['sdp'].splitlines():
                if line.lower().startswith('a=candidate:'):
                    candidate(line); count+=1
            check(count<=64,'LIMIT_EXCEEDED')
        else:
            check(data['mechanism'] in {'tcp','quic','tcp-simopen'})
            try: x509.load_pem_x509_certificate(desc['sdp'].encode())
            except ValueError: raise ProtocolError('SCHEMA_INVALID') from None
    if 'candidate' in data:
        check(data['mechanism']=='webrtc')
        c=data['candidate']
        if c is None: check(data.get('endOfCandidates') is True)
        else:
            fields(c,{'candidate','sdpMid','sdpMLineIndex'}); candidate(c['candidate'])
            check(c['sdpMid'] is None or isinstance(c['sdpMid'],str) and len(c['sdpMid'])<=64)
            check(c['sdpMLineIndex'] is None or type(c['sdpMLineIndex']) is int and 0<=c['sdpMLineIndex']<16)
            check('endOfCandidates' not in data)
    if 'nativeCandidate' in data:
        check(data['mechanism']!='webrtc')
        c=data['nativeCandidate']; fields(c,{'id','family','transport','address','port','kind','socketId'},{'certificateFingerprint'})
        string(c['id'],100); string(c['socketId'],100)
        check(c['kind']!='relay','RELAY_FORBIDDEN'); check(c['kind'] in {'host','srflx','mapped'})
        check(c['transport'] in {'udp','quic','tcp'} and type(c['port']) is int and 1<=c['port']<=65535)
        try: ip=ipaddress.ip_address(c['address'])
        except ValueError: raise ProtocolError('SCHEMA_INVALID') from None
        check(ip.version==c['family'] and not (ip.is_multicast or ip.is_unspecified or ip.is_link_local or str(ip)=='255.255.255.255') and '%' not in c['address'])
        if 'certificateFingerprint' in c: check(bool(re.fullmatch('[0-9a-f]{64}',c['certificateFingerprint'])))
    if 'retry' in data:
        fields(data['retry'],{'previousAttemptId','reason'}); uid(data['retry']['previousAttemptId'])
        check(data['retry']['reason'] in {'TIMEOUT','CLOSED','NETWORK_CHANGED','RETRY'})
    return data
