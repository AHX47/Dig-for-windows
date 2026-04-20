#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dig.py  ─  DNS lookup utility for Windows
Exact replica of BIND DiG 9.20.x  (output, options, behaviour)
No external dependencies. Compile with:
    pyinstaller --onefile --console --name dig dig.py
"""

import socket, struct, time, sys, os, random, re, base64, ipaddress
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any

# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════
VERSION = "9.20.22"

QTYPES: Dict[str, int] = {
    'A':1,'NS':2,'MD':3,'MF':4,'CNAME':5,'SOA':6,'MB':7,'MG':8,'MR':9,
    'NULL':10,'WKS':11,'PTR':12,'HINFO':13,'MINFO':14,'MX':15,'TXT':16,
    'RP':17,'AFSDB':18,'X25':19,'ISDN':20,'RT':21,'NSAP':22,'NSAP-PTR':23,
    'SIG':24,'KEY':25,'PX':26,'GPOS':27,'AAAA':28,'LOC':29,'NXT':30,
    'EID':31,'NIMLOC':32,'SRV':33,'ATMA':34,'NAPTR':35,'KX':36,'CERT':37,
    'A6':38,'DNAME':39,'SINK':40,'OPT':41,'APL':42,'DS':43,'SSHFP':44,
    'IPSECKEY':45,'RRSIG':46,'NSEC':47,'DNSKEY':48,'DHCID':49,'NSEC3':50,
    'NSEC3PARAM':51,'TLSA':52,'SMIMEA':53,'HIP':55,'NINFO':56,'RKEY':57,
    'TALINK':58,'CDS':59,'CDNSKEY':60,'OPENPGPKEY':61,'CSYNC':62,
    'ZONEMD':63,'SVCB':64,'HTTPS':65,'SPF':99,'NID':104,'L32':105,
    'L64':106,'LP':107,'EUI48':108,'EUI64':109,
    'TKEY':249,'TSIG':250,'IXFR':251,'AXFR':252,'MAILB':253,'MAILA':254,
    'ANY':255,'URI':256,'CAA':257,'AVC':258,'DOA':259,'AMTRELAY':260,
    'TA':32768,'DLV':32769,
}
QTYPES_R = {v: k for k, v in QTYPES.items()}

QCLASSES: Dict[str, int] = {'IN':1,'CH':3,'HS':4,'NONE':254,'ANY':255}
QCLASSES_R = {v: k for k, v in QCLASSES.items()}

OPCODES  = {0:'QUERY',1:'IQUERY',2:'STATUS',4:'NOTIFY',5:'UPDATE'}
RCODES   = {
    0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',
    5:'REFUSED',6:'YXDOMAIN',7:'YXRRSET',8:'NXRRSET',9:'NOTAUTH',
    10:'NOTZONE',16:'BADSIG',17:'BADKEY',18:'BADTIME',19:'BADMODE',
    20:'BADNAME',21:'BADALG',22:'BADTRUNC',23:'BADCOOKIE',
}

ROOT_SERVERS = [
    ('a.root-servers.net.','198.41.0.4'),
    ('b.root-servers.net.','170.247.170.2'),
    ('c.root-servers.net.','192.33.4.12'),
    ('d.root-servers.net.','199.7.91.13'),
    ('e.root-servers.net.','192.203.230.10'),
    ('f.root-servers.net.','192.5.5.241'),
    ('g.root-servers.net.','192.112.36.4'),
    ('h.root-servers.net.','198.97.190.53'),
    ('i.root-servers.net.','192.36.148.17'),
    ('j.root-servers.net.','192.58.128.30'),
    ('k.root-servers.net.','193.0.14.129'),
    ('l.root-servers.net.','199.7.83.42'),
    ('m.root-servers.net.','202.12.27.33'),
]

# ═══════════════════════════════════════════════════════════════
#  OPTIONS
# ═══════════════════════════════════════════════════════════════
class Opts:
    show_cmd       = True
    show_comments  = True
    show_question  = True
    show_answer    = True
    show_authority = False
    show_additional= False
    show_stats     = True
    short          = False
    multiline      = False
    onesoa         = False
    identify       = False
    ttlid          = True
    ttlunits       = False
    show_class     = True
    crypto         = True
    unknown_format = False
    recurse        = True
    tcp            = False
    ignore_tc      = False
    dnssec         = False
    adflag         = True
    cdflag         = False
    aaflag         = False
    raflag         = False
    rdflag         = True
    zflag          = False
    trace          = False
    nssearch       = False
    sigchase       = False
    qr             = False
    fail           = False
    search         = False
    defname        = True
    expire         = False
    badcookie      = False
    port           = 53
    timeout        = 5
    tries          = 3
    bufsize        = 1232
    ndots          = 1
    split          = 56
    padding        = 0
    ipv4_only      = False
    ipv6_only      = False

# ═══════════════════════════════════════════════════════════════
#  DNS WIRE FORMAT – BUILDER
# ═══════════════════════════════════════════════════════════════
def encode_name(name: str) -> bytes:
    if name in ('', '.'):
        return b'\x00'
    n = name.rstrip('.')
    buf = b''
    for lbl in n.split('.'):
        enc = lbl.encode('ascii')
        buf += bytes([len(enc)]) + enc
    return buf + b'\x00'

def build_query(qname: str, qtype: int, qclass: int, mid: int, o: Opts) -> bytes:
    flags = 0
    if o.recurse:  flags |= 0x0100
    if o.adflag:   flags |= 0x0020
    if o.cdflag:   flags |= 0x0010
    if o.aaflag:   flags |= 0x0400
    if o.zflag:    flags |= 0x0040
    hdr   = struct.pack('!HHHHHH', mid, flags, 1, 0, 0, 1)
    quest = encode_name(qname) + struct.pack('!HH', qtype, qclass)
    # OPT record (EDNS0)
    opt_ttl = 0
    if o.dnssec: opt_ttl |= 0x00008000
    opt = b'\x00' + struct.pack('!HHIH', 41, o.bufsize, opt_ttl, 0)
    return hdr + quest + opt

# ═══════════════════════════════════════════════════════════════
#  DNS WIRE FORMAT – PARSER
# ═══════════════════════════════════════════════════════════════
def decode_name(pkt: bytes, off: int) -> Tuple[str, int]:
    labels, jumped, ret_off = [], False, 0
    seen = set()
    while off < len(pkt):
        n = pkt[off]
        if n == 0:
            off += 1; break
        if (n & 0xC0) == 0xC0:
            if off + 1 >= len(pkt): break
            ptr = ((n & 0x3F) << 8) | pkt[off+1]
            if ptr in seen: break
            seen.add(ptr)
            if not jumped: ret_off = off + 2
            off, jumped = ptr, True
        else:
            off += 1
            labels.append(pkt[off:off+n].decode('ascii','replace'))
            off += n
    name = '.'.join(labels) + '.' if labels else '.'
    return name, (ret_off if jumped else off)

def parse_rr(pkt: bytes, off: int) -> Tuple[Optional[Dict], int]:
    try:
        name, off = decode_name(pkt, off)
        if off + 10 > len(pkt): return None, len(pkt)
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', pkt[off:off+10])
        off += 10
        rdata_bytes = pkt[off:off+rdlen]
        rdata_off   = off
        off += rdlen
        rdata = _parse_rdata(rtype, rdata_bytes, pkt, rdata_off)
        return dict(name=name,type=rtype,cls=rclass,ttl=ttl,rdlen=rdlen,
                    rdata=rdata,raw=rdata_bytes), off
    except Exception:
        return None, len(pkt)

def _parse_rdata(rt: int, rd: bytes, pkt: bytes, off0: int) -> Any:
    try:
        if rt == 1:   return socket.inet_ntoa(rd)
        if rt == 28:
            return socket.inet_ntop(socket.AF_INET6, rd)
        if rt in (2,5,12,39):
            n,_ = decode_name(pkt, off0); return n
        if rt == 15:
            pref = struct.unpack('!H',rd[:2])[0]
            ex,_ = decode_name(pkt, off0+2)
            return dict(pref=pref, ex=ex)
        if rt == 6:
            mn, o = decode_name(pkt, off0)
            rn, o = decode_name(pkt, o)
            sr,rf,ry,exp,mn_ = struct.unpack('!5I', pkt[o:o+20])
            return dict(mname=mn,rname=rn,serial=sr,refresh=rf,
                        retry=ry,expire=exp,minimum=mn_)
        if rt == 16:
            txts,i = [],0
            while i < len(rd):
                l=rd[i]; i+=1; txts.append(rd[i:i+l]); i+=l
            return txts
        if rt == 33:
            pr,wt,po = struct.unpack('!HHH',rd[:6])
            tg,_ = decode_name(pkt, off0+6)
            return dict(priority=pr,weight=wt,port=po,target=tg)
        if rt == 257:
            fl=rd[0]; tl=rd[1]
            tag=rd[2:2+tl].decode('ascii')
            val=rd[2+tl:].decode('utf-8','replace')
            return dict(flags=fl,tag=tag,value=val)
        if rt == 35:
            order,pref=struct.unpack('!HH',rd[:4]); i=4
            fl=rd[i+1:i+1+rd[i]].decode('ascii'); i+=1+rd[i]
            sv=rd[i+1:i+1+rd[i]].decode('ascii'); i+=1+rd[i]
            rx=rd[i+1:i+1+rd[i]].decode('ascii'); i+=1+rd[i]
            rep,_=decode_name(pkt,off0+i)
            return dict(order=order,pref=pref,flags=fl,
                        service=sv,regexp=rx,replacement=rep)
        if rt == 43:
            kt,alg,dt=struct.unpack('!HBB',rd[:4])
            return dict(keytag=kt,alg=alg,dtype=dt,digest=rd[4:].hex().upper())
        if rt == 48:
            fl,pr,alg=struct.unpack('!HBB',rd[:4])
            return dict(flags=fl,proto=pr,alg=alg,
                        key=base64.b64encode(rd[4:]).decode())
        if rt == 46:
            tc,alg,lbl,ottl=struct.unpack('!HBBI',rd[:8])
            exp,inc=struct.unpack('!II',rd[8:16])
            kt=struct.unpack('!H',rd[16:18])[0]
            sn,o2=decode_name(pkt,off0+18)
            sig=base64.b64encode(rd[o2-off0:]).decode()
            return dict(tc=tc,alg=alg,labels=lbl,orig_ttl=ottl,
                        exp=exp,inc=inc,keytag=kt,signer=sn,sig=sig)
        if rt == 47:
            nd,o2=decode_name(pkt,off0)
            return dict(next=nd,types=_nsec_bitmap(rd[o2-off0:]))
        if rt == 50:
            alg,fl,it=struct.unpack('!BBH',rd[:4]); i=4
            sl=rd[i]; i+=1; salt=rd[i:i+sl].hex().upper() or '-'; i+=sl
            hl=rd[i]; i+=1
            nh=base64.b32encode(rd[i:i+hl]).decode(); i+=hl
            return dict(alg=alg,flags=fl,iters=it,salt=salt,
                        next=nh,types=_nsec_bitmap(rd[i:]))
        if rt == 52:
            us,se,mt=struct.unpack('!BBB',rd[:3])
            return dict(usage=us,sel=se,mtype=mt,cert=rd[3:].hex().upper())
        if rt == 44:
            alg,ft=struct.unpack('!BB',rd[:2])
            return dict(alg=alg,ftype=ft,fp=rd[2:].hex().upper())
        if rt == 13:
            i=0; cl=rd[i]; i+=1; cpu=rd[i:i+cl].decode('ascii'); i+=cl
            ol=rd[i]; i+=1; osv=rd[i:i+ol].decode('ascii')
            return dict(cpu=cpu,os=osv)
        if rt == 41:
            return dict(udp=None)   # class=udp size, parsed from rr
        if rt == 59:
            kt,alg,dt=struct.unpack('!HBB',rd[:4])
            return dict(keytag=kt,alg=alg,dtype=dt,digest=rd[4:].hex().upper())
        if rt == 60:
            fl,pr,alg=struct.unpack('!HBB',rd[:4])
            return dict(flags=fl,proto=pr,alg=alg,
                        key=base64.b64encode(rd[4:]).decode())
        if rt == 36:
            pref=struct.unpack('!H',rd[:2])[0]
            ex,_=decode_name(pkt,off0+2)
            return dict(pref=pref,ex=ex)
        if rt == 17:
            mb,o2=decode_name(pkt,off0); tx,_=decode_name(pkt,o2)
            return dict(mbox=mb,txt=tx)
        if rt == 44:
            alg,ft=struct.unpack('!BB',rd[:2])
            return dict(alg=alg,ftype=ft,fp=rd[2:].hex().upper())
        if rt == 64 or rt == 65:  # SVCB / HTTPS
            prio=struct.unpack('!H',rd[:2])[0]
            tg,_=decode_name(pkt,off0+2)
            return dict(prio=prio,target=tg,params=rd.hex())
        # Generic unknown
        return dict(generic=rd.hex(),raw=rd)
    except Exception:
        return dict(generic=rd.hex() if rd else '',raw=rd)

def _nsec_bitmap(data: bytes) -> List[str]:
    types,i = [],0
    while i+2 <= len(data):
        win=data[i]; blen=data[i+1]; i+=2
        bmp=data[i:i+blen]; i+=blen
        for bi,byte in enumerate(bmp):
            for bit in range(8):
                if byte & (0x80>>bit):
                    t=win*256+bi*8+bit
                    types.append(QTYPES_R.get(t,f'TYPE{t}'))
    return types

def parse_packet(data: bytes) -> Dict:
    if len(data) < 12: raise ValueError("Packet too short")
    mid,flags,qd,an,ns,ar = struct.unpack('!HHHHHH',data[:12])
    f = dict(
        qr=(flags>>15)&1, opcode=(flags>>11)&0xF,
        aa=(flags>>10)&1, tc=(flags>>9)&1,
        rd=(flags>>8)&1,  ra=(flags>>7)&1,
        z=(flags>>6)&1,   ad=(flags>>5)&1,
        cd=(flags>>4)&1,  rcode=flags&0xF,
    )
    off = 12
    questions = []
    for _ in range(qd):
        nm,off = decode_name(data,off)
        if off+4 > len(data): break
        qt,qc = struct.unpack('!HH',data[off:off+4]); off+=4
        questions.append(dict(name=nm,qtype=qt,qclass=qc))
    answers,authorities,additionals = [],[],[]
    for _ in range(an):
        r,off = parse_rr(data,off)
        if r: answers.append(r)
    for _ in range(ns):
        r,off = parse_rr(data,off)
        if r: authorities.append(r)
    for _ in range(ar):
        r,off = parse_rr(data,off)
        if r: additionals.append(r)
    return dict(id=mid,flags=f,rcode=f['rcode'],
                qdcount=qd,ancount=an,nscount=ns,arcount=ar,
                questions=questions,answers=answers,
                authorities=authorities,additionals=additionals,
                rawsize=len(data))

# ═══════════════════════════════════════════════════════════════
#  TRANSPORT
# ═══════════════════════════════════════════════════════════════
def _sock_family(server: str, o: Opts) -> Tuple[int,tuple]:
    fam = socket.AF_UNSPEC
    if o.ipv4_only: fam = socket.AF_INET
    if o.ipv6_only: fam = socket.AF_INET6
    ai = socket.getaddrinfo(server, o.port, fam, socket.SOCK_DGRAM)
    if not ai: raise OSError(f"No address for {server}")
    return ai[0][0], ai[0][4]

def _send_udp(pkt,server,port,timeout,fam,addr):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, addr)
        return s.recvfrom(65535)[0]
    finally:
        s.close()

def _recv_all(s, n):
    buf = b''
    while len(buf)<n:
        c=s.recv(n-len(buf))
        if not c: break
        buf+=c
    return buf

def _send_tcp(pkt,server,port,timeout,fam,addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(addr)
        s.sendall(struct.pack('!H',len(pkt))+pkt)
        rlen = struct.unpack('!H',_recv_all(s,2))[0]
        return _recv_all(s, rlen)
    finally:
        s.close()

def send_dns(pkt: bytes, server: str, o: Opts) -> Tuple[bytes,float,str]:
    fam, addr = _sock_family(server, o)
    t0 = time.time()
    if o.tcp:
        data = _send_tcp(pkt, server, o.port, o.timeout, fam, addr)
        return data, (time.time()-t0)*1000, 'TCP'
    # UDP first
    data = _send_udp(pkt, server, o.port, o.timeout, fam, addr)
    # TC bit → retry TCP
    if len(data)>3 and (data[2]&0x02) and not o.ignore_tc:
        data = _send_tcp(pkt, server, o.port, o.timeout, fam, addr)
        return data, (time.time()-t0)*1000, 'TCP'
    return data, (time.time()-t0)*1000, 'UDP'

# ═══════════════════════════════════════════════════════════════
#  SYSTEM RESOLVER DETECTION
# ═══════════════════════════════════════════════════════════════
def get_system_resolver() -> str:
    if sys.platform == 'win32':
        try:
            import subprocess
            r = subprocess.run(
                ['powershell','-NoProfile','-Command',
                 '(Get-DnsClientServerAddress -AddressFamily IPv4 | '
                 'Where-Object {$_.ServerAddresses -ne $null} | '
                 'Select-Object -First 1).ServerAddresses[0]'],
                capture_output=True, text=True, timeout=5)
            ip = r.stdout.strip()
            if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                return ip
        except Exception:
            pass
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    sub = winreg.OpenKey(key, winreg.EnumKey(key,i))
                    for val in ('DhcpNameServer','NameServer'):
                        try:
                            dns,_ = winreg.QueryValueEx(sub,val)
                            ip = dns.replace(',',' ').split()[0]
                            if ip: return ip
                        except Exception: pass
                except Exception: pass
        except Exception:
            pass
        return '8.8.8.8'
    # Unix
    try:
        for line in open('/etc/resolv.conf'):
            if line.startswith('nameserver'):
                return line.split()[1]
    except Exception:
        pass
    return '127.0.0.1'

# ═══════════════════════════════════════════════════════════════
#  FORMATTING
# ═══════════════════════════════════════════════════════════════
def tname(t: int) -> str: return QTYPES_R.get(t, f'TYPE{t}')
def cname(c: int) -> str: return QCLASSES_R.get(c, f'CLASS{c}')

def _esc_txt(b: bytes) -> str:
    out=[]
    for byte in b:
        if   byte==34:  out.append('\\"')
        elif byte==92:  out.append('\\\\')
        elif 32<=byte<127: out.append(chr(byte))
        else:           out.append(f'\\{byte:03d}')
    return ''.join(out)

def _esc_str(s: str) -> str:
    return s.replace('\\','\\\\').replace('"','\\"')

def _b64wrap(s: str, o: Opts) -> str:
    if o.multiline:
        chunks=[s[i:i+o.split] for i in range(0,len(s),o.split)]
        return (' '+'\n\t\t\t\t\t'.join(chunks)+' )') if len(chunks)>1 else s
    return s

def _hexwrap(s: str, o: Opts) -> str:
    if o.multiline:
        chunks=[s[i:i+o.split] for i in range(0,len(s),o.split)]
        return '\n\t\t\t\t'.join(chunks)
    return s

def fmt_ts(ts: int) -> str:
    try: return datetime.utcfromtimestamp(ts).strftime('%Y%m%d%H%M%S')
    except: return str(ts)

def fmt_rdata(r: Dict, o: Opts) -> str:
    rt = r['type']; d = r['rdata']
    if rt==1:   return str(d)
    if rt==28:  return str(d)
    if rt in(2,5,12,39): return str(d)
    if rt==15:  return f"{d['pref']} {d['ex']}"
    if rt==6:
        if o.multiline:
            return (f"{d['mname']} {d['rname']} (\n"
                    f"\t\t\t\t\t{d['serial']}\t ; serial\n"
                    f"\t\t\t\t\t{d['refresh']}\t ; refresh\n"
                    f"\t\t\t\t\t{d['retry']}\t ; retry\n"
                    f"\t\t\t\t\t{d['expire']}\t ; expire\n"
                    f"\t\t\t\t\t{d['minimum']} )\t ; minimum")
        return (f"{d['mname']} {d['rname']} {d['serial']} "
                f"{d['refresh']} {d['retry']} {d['expire']} {d['minimum']}")
    if rt==16:
        parts=[f'"{_esc_txt(c)}"' for c in d]
        if o.multiline:
            return '( ' + '\n\t\t\t\t\t'.join(parts) + ' )'
        return ' '.join(parts)
    if rt==33:  return f"{d['priority']} {d['weight']} {d['port']} {d['target']}"
    if rt==257: return f"{d['flags']} {d['tag']} \"{_esc_str(d['value'])}\""
    if rt==35:
        return (f"{d['order']} {d['pref']} \"{d['flags']}\" "
                f"\"{d['service']}\" \"{d['regexp']}\" {d['replacement']}")
    if rt==43:
        h = _hexwrap(d['digest'],o)
        return f"{d['keytag']} {d['alg']} {d['dtype']} {h}"
    if rt==48:
        k = _b64wrap(d['key'],o)
        return f"{d['flags']} {d['proto']} {d['alg']} {k}"
    if rt==46:
        sig=_b64wrap(d['sig'],o)
        return (f"{tname(d['tc'])} {d['alg']} {d['labels']} {d['orig_ttl']} "
                f"{fmt_ts(d['exp'])} {fmt_ts(d['inc'])} {d['keytag']} "
                f"{d['signer']} {sig}")
    if rt==47:  return f"{d['next']} {' '.join(d['types'])}"
    if rt==50:
        return (f"{d['alg']} {d['flags']} {d['iters']} {d['salt']} "
                f"{d['next']} {' '.join(d['types'])}")
    if rt==52:  return f"{d['usage']} {d['sel']} {d['mtype']} {d['cert']}"
    if rt==44:  return f"{d['alg']} {d['ftype']} {d['fp']}"
    if rt==13:  return f'"{d["cpu"]}" "{d["os"]}"'
    if rt==59:
        h=_hexwrap(d['digest'],o)
        return f"{d['keytag']} {d['alg']} {d['dtype']} {h}"
    if rt==60:
        k=_b64wrap(d['key'],o)
        return f"{d['flags']} {d['proto']} {d['alg']} {k}"
    if rt==36:  return f"{d['pref']} {d['ex']}"
    if rt==17:  return f"{d['mbox']} {d['txt']}"
    if rt in(64,65):
        return f"{d['prio']} {d['target']}"
    if isinstance(d,dict) and 'generic' in d:
        raw=d['raw']; return f"\\# {len(raw)} {d['generic'].lower()}"
    return str(d)

def fmt_rdata_short(r: Dict) -> str:
    rt=r['type']; d=r['rdata']
    if rt in(1,28): return str(d)
    if rt in(2,5,12,39): return str(d)
    if rt==15: return f"{d['pref']} {d['ex']}"
    if rt==33: return f"{d['priority']} {d['weight']} {d['port']} {d['target']}"
    if rt==16: return ' '.join(_esc_txt(c) for c in d)
    if rt==6:
        d2=d
        return (f"{d2['mname']} {d2['rname']} {d2['serial']} "
                f"{d2['refresh']} {d2['retry']} {d2['expire']} {d2['minimum']}")
    if rt==257: return f"{d['flags']} {d['tag']} \"{d['value']}\""
    return fmt_rdata(r, Opts())

def fmt_record(r: Dict, o: Opts) -> str:
    nm  = r['name']
    ttl = str(r['ttl']) if o.ttlid else ''
    cls = cname(r['cls'])
    rtp = tname(r['type'])
    rd  = fmt_rdata(r, o)
    # Column widths matching real dig
    nm_col = f"{nm:<24}"
    if o.ttlid:
        return f"{nm_col}{ttl:<8}{cls}\t{rtp}\t{rd}"
    return f"{nm_col}{cls}\t{rtp}\t{rd}"

def _flags_str(f: Dict) -> str:
    p=[]
    if f.get('qr'): p.append('qr')
    op=f.get('opcode',0)
    if op: p.append(OPCODES.get(op,f'op{op}').lower())
    if f.get('aa'): p.append('aa')
    if f.get('tc'): p.append('tc')
    if f.get('rd'): p.append('rd')
    if f.get('ra'): p.append('ra')
    if f.get('z'):  p.append('z')
    if f.get('ad'): p.append('ad')
    if f.get('cd'): p.append('cd')
    return ' '.join(p)

def print_header(resp: Dict, o: Opts):
    if not o.show_comments: return
    op   = OPCODES.get(resp['flags']['opcode'], 'QUERY')
    rc   = RCODES.get(resp['rcode'], f"RCODE{resp['rcode']}")
    fl   = _flags_str(resp['flags'])
    adds = len(resp['additionals'])
    print(";; Got answer:")
    print(f";; ->>HEADER<<- opcode: {op}, status: {rc}, id: {resp['id']}")
    print(f";; flags: {fl}; QUERY: {resp['qdcount']}, "
          f"ANSWER: {len(resp['answers'])}, "
          f"AUTHORITY: {len(resp['authorities'])}, "
          f"ADDITIONAL: {adds}")

def print_opt(resp: Dict, o: Opts):
    if not o.show_comments: return
    for r in resp['additionals']:
        if r['type'] == 41:
            udp  = r['cls']
            ttl  = r['ttl']
            ev   = (ttl>>16)&0xFF
            do   = (ttl>>15)&1
            fl   = ' do' if do else ''
            print(";; OPT PSEUDOSECTION:")
            print(f"; EDNS: version: {ev}, flags:{fl}; udp: {udp}")
            break

def print_question(resp: Dict, o: Opts):
    if not o.show_question: return
    if o.show_comments: print(";; QUESTION SECTION:")
    for q in resp['questions']:
        nm = q['name']; cls=cname(q['qclass']); rtp=tname(q['qtype'])
        print(f";{nm:<23} {cls}\t{rtp}")
    print()

def print_section(title: str, recs: List, o: Opts):
    recs2 = [r for r in recs if r['type']!=41]
    if not recs2: return
    if o.show_comments: print(f";; {title}:")
    for r in recs2: print(fmt_record(r, o))
    print()

def print_stats(server: str, qt: float, o: Opts, sz: int, tp: str):
    if not o.show_stats: return
    when = datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')
    print(f";; Query time: {int(qt)} msec")
    print(f";; SERVER: {server}#{o.port}({server}) ({tp})")
    print(f";; WHEN: {when}")
    print(f";; MSG SIZE  rcvd: {sz}")
    print()

# ═══════════════════════════════════════════════════════════════
#  +trace
# ═══════════════════════════════════════════════════════════════
def do_trace(qname: str, qtype: int, qclass: int, o: Opts):
    to = Opts()
    to.__dict__.update(vars(o))
    to.recurse = False
    to.show_cmd = False
    servers = list(ROOT_SERVERS)
    depth   = 0
    visited_ips = set()

    while depth < 32:
        depth += 1
        success = False
        for sname, sip in servers:
            if sip in visited_ips: continue
            visited_ips.add(sip)
            mid = random.randint(1,65535)
            pkt = build_query(qname, qtype, qclass, mid, to)
            try:
                data, qt, tp = send_dns(pkt, sip, to)
            except Exception as e:
                print(f";; ERROR talking to {sip}: {e}")
                continue
            try:
                resp = parse_packet(data)
            except Exception as e:
                print(f";; ERROR parsing from {sip}: {e}")
                continue

            print(f";; Received {len(data)} bytes from "
                  f"{sip}#{to.port}({sname.rstrip('.')}) in {int(qt)} ms\n")

            # Print all non-OPT records
            for sect in [resp['answers'],resp['authorities'],resp['additionals']]:
                for r in sect:
                    if r['type']!=41: print(fmt_record(r,to))
            print()

            if resp['answers']:
                return  # Done

            ns_recs = [r for r in resp['authorities'] if r['type']==2]
            if not ns_recs:
                return

            # Build next server list from ADDITIONAL glue
            glue = {}
            for r in resp['additionals']:
                if r['type']==1:
                    glue.setdefault(r['name'].lower(),[]).append(r['rdata'])
                elif r['type']==28:
                    glue.setdefault(r['name'].lower(),[]).append(r['rdata'])

            next_servers = []
            for ns in ns_recs:
                ns_name = ns['rdata']
                ips = glue.get(ns_name.lower(),[])
                for ip in ips:
                    next_servers.append((ns_name, ip))

            if not next_servers:
                # Resolve first NS
                ns_name = ns_recs[0]['rdata'].rstrip('.')
                try:
                    ip = socket.gethostbyname(ns_name)
                    next_servers = [(ns_name+'.', ip)]
                except Exception:
                    pass

            if next_servers:
                servers = next_servers
                success = True
                break

        if not success:
            print(";; No nameservers could be reached")
            return

# ═══════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════
def parse_plus(name_raw: str, o: Opts):
    s = name_raw.lower()
    neg = s.startswith('no')
    nm  = s[2:] if neg else s
    val = None
    if '=' in nm: nm, val = nm.split('=',1)
    b   = not neg

    M = {
        'cmd':        ('show_cmd',None),
        'comments':   ('show_comments',None),
        'question':   ('show_question',None),
        'answer':     ('show_answer',None),
        'authority':  ('show_authority',None),
        'additional': ('show_additional',None),
        'stats':      ('show_stats',None),
        'multiline':  ('multiline',None),
        'onesoa':     ('onesoa',None),
        'identify':   ('identify',None),
        'ttlid':      ('ttlid',None),
        'ttl':        ('ttlid',None),
        'ttlunits':   ('ttlunits',None),
        'class':      ('show_class',None),
        'crypto':     ('crypto',None),
        'unknownformat':('unknown_format',None),
        'recurse':    ('recurse',None),
        'rec':        ('recurse',None),
        'tcp':        ('tcp',None),
        'vc':         ('tcp',None),
        'ignore':     ('ignore_tc',None),
        'dnssec':     ('dnssec',None),
        'adflag':     ('adflag',None),
        'ad':         ('adflag',None),
        'cdflag':     ('cdflag',None),
        'cd':         ('cdflag',None),
        'aaflag':     ('aaflag',None),
        'aa':         ('aaflag',None),
        'raflag':     ('raflag',None),
        'rdflag':     ('rdflag',None),
        'zflag':      ('zflag',None),
        'trace':      ('trace',None),
        'nssearch':   ('nssearch',None),
        'sigchase':   ('sigchase',None),
        'qr':         ('qr',None),
        'fail':       ('fail',None),
        'search':     ('search',None),
        'sea':        ('search',None),
        'defname':    ('defname',None),
        'expire':     ('expire',None),
        'badcookie':  ('badcookie',None),
    }
    if nm in M:
        attr,_ = M[nm]
        setattr(o, attr, b)
        if nm in ('recurse','rec','rdflag'): o.rdflag = b
    elif nm == 'all':
        for a in ['show_cmd','show_comments','show_question','show_answer',
                  'show_authority','show_additional','show_stats']:
            setattr(o,a,b)
    elif nm == 'short' and b:
        o.short=True; o.show_cmd=False; o.show_comments=False
        o.show_question=False; o.show_stats=False
    elif nm == 'short' and not b:
        o.short=False
    elif nm in ('tries','retry') and val:
        try: o.tries=int(val)
        except: pass
    elif nm=='timeout' and val:
        try: o.timeout=int(val)
        except: pass
    elif nm=='bufsize' and val:
        try: o.bufsize=int(val)
        except: pass
    elif nm=='ndots' and val:
        try: o.ndots=int(val)
        except: pass
    elif nm=='split' and val:
        try: o.split=int(val)
        except: pass
    elif nm=='padding' and val:
        try: o.padding=int(val)
        except: pass
    # silently ignore unknown options (same as real dig)

def ip_to_arpa(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv4Address):
            return '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa.'
        else:
            full = a.exploded.replace(':','')
            return '.'.join(reversed(full)) + '.ip6.arpa.'
    except ValueError:
        return ip

def parse_args(argv: List[str]) -> Tuple[List[Dict], Opts]:
    o = Opts()
    queries: List[Dict] = []
    cur = dict(server=None,name=None,qtype='A',qclass='IN',reverse=False)

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg.startswith('@'):
            srv = arg[1:]
            if '#' in srv:
                p = srv.split('#',1)
                srv = p[0]
                try: o.port = int(p[1])
                except: pass
            cur['server'] = srv

        elif arg == '-4': o.ipv4_only=True; o.ipv6_only=False
        elif arg == '-6': o.ipv6_only=True; o.ipv4_only=False
        elif arg in ('-h','--help','-help'):
            print_help(); sys.exit(0)
        elif arg == '-v':
            print(f"DiG {VERSION}"); sys.exit(0)
        elif arg in ('-r','-i','-m'): pass
        elif arg in ('-b','-k','-y'): i+=1  # consume next
        elif arg == '-c':
            i+=1
            if i<len(argv): cur['qclass'] = argv[i].upper()
        elif arg == '-t':
            i+=1
            if i<len(argv): cur['qtype']  = argv[i].upper()
        elif arg == '-p':
            i+=1
            if i<len(argv):
                try: o.port=int(argv[i])
                except: pass
        elif arg == '-q':
            i+=1
            if i<len(argv): cur['name'] = argv[i]
        elif arg == '-x':
            i+=1
            if i<len(argv):
                cur['name']    = ip_to_arpa(argv[i])
                cur['qtype']   = 'PTR'
                cur['reverse'] = True
        elif arg == '-f':
            i+=1
            # batch file: handled in main
            o._batch_file = argv[i] if i<len(argv) else None

        elif arg.startswith('+'):
            parse_plus(arg[1:], o)

        elif arg.startswith('--'):
            sys.stderr.write(f"Invalid option: {arg}\n")
            sys.stderr.write(
                "Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}\n"
                "            {global-d-opt} host [@local-server] {local-d-opt}\n"
                "            [ host [@local-server] {local-d-opt} [...]]\n\n"
                'Use "dig -h" (or "dig -h | more") for complete list of options\n')
            sys.exit(1)

        else:
            up = arg.upper()
            if up in QTYPES:
                cur['qtype'] = up
            elif up in QCLASSES:
                cur['qclass'] = up
            elif cur['name'] is None:
                cur['name'] = arg
            else:
                # new query starts
                queries.append(dict(cur))
                cur = dict(server=cur['server'],name=arg,
                           qtype='A',qclass='IN',reverse=False)
        i += 1

    if cur['name'] is None:
        cur['name']  = '.'
        cur['qtype'] = 'NS'
    queries.append(cur)
    return queries, o

# ═══════════════════════════════════════════════════════════════
#  SINGLE QUERY RUNNER
# ═══════════════════════════════════════════════════════════════
def run_query(q: Dict, o: Opts, argv_str: str) -> int:
    name   = q['name']
    qt     = QTYPES.get(q['qtype'].upper(), 1)
    qc     = QCLASSES.get(q['qclass'].upper(), 1)
    server = q.get('server') or get_system_resolver()

    if o.trace:
        if o.show_cmd:
            print(f"; <<>> DiG {VERSION} <<dev by abdo_hak47>> +trace {name}")
            print(";; global options: +cmd")
        do_trace(name, qt, qc, o)
        return 0

    mid = random.randint(1, 65535)
    pkt = build_query(name, qt, qc, mid, o)

    if o.qr and o.show_comments:
        print(f";; Sending query to {server}#{o.port}")

    resp_data = None
    query_time = 0.0
    transport  = 'UDP'
    last_err   = ''

    for _ in range(max(1, o.tries)):
        try:
            resp_data, query_time, transport = send_dns(pkt, server, o)
            break
        except socket.timeout:
            last_err = 'connection timed out'
        except Exception as e:
            last_err = str(e)
            break

    if resp_data is None:
        if not o.short and o.show_comments:
            print(f"; <<>> DiG {VERSION} <<dev by abdo_hak47>> {argv_str}")
            print(";; global options: +cmd")
        print(f";; connection timed out; no servers could be reached")
        return 9

    try:
        resp = parse_packet(resp_data)
    except Exception as e:
        print(f";; ERROR parsing response: {e}")
        return 1

    # +short
    if o.short:
        for r in resp['answers']:
            if r['type'] != 41:
                print(fmt_rdata_short(r))
        return 0 if resp['rcode']==0 else 1

    # Full output
    if o.show_cmd:
        print(f"; <<>> DiG {VERSION} <<dev by abdo_hak47>> {argv_str}")
        print(";; global options: +cmd")

    if o.show_comments:
        print_header(resp, o)
        print_opt(resp, o)

    print_question(resp, o)

    if o.show_answer:     print_section("ANSWER SECTION",     resp['answers'],     o)
    if o.show_authority:  print_section("AUTHORITY SECTION",  resp['authorities'], o)
    if o.show_additional: print_section("ADDITIONAL SECTION", resp['additionals'], o)

    print_stats(server, query_time, o, len(resp_data), transport)
    return 0 if resp['rcode']==0 else 1

# ═══════════════════════════════════════════════════════════════
#  HELP TEXT
# ═══════════════════════════════════════════════════════════════
HELP = f"""\
*****************************************************************
**************Dev BY Abdo_hak47 *********************************
*****************************************************************
Usage:  dig [@global-server] [domain] [q-type] [q-class] {{q-opt}}
            {{global-d-opt}} host [@local-server] {{local-d-opt}}
            [ host [@local-server] {{local-d-opt}} [...]]
Where:  domain   is in the Domain Name System
        q-class  is one of (in,hs,ch,...) [default: in]
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]
                 (Use ixfr=version for type ixfr)
        q-opt    is one of:
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
                 -b address[#port]   (bind to source address/port)
                 -c class            (specify query class)
                 -f filename         (batch mode)
                 -h                  (print help and exit)
                 -k keyfile          (specify tsig key file)
                 -m                  (enable memory usage debugging)
                 -p port             (specify port number)
                 -q name             (specify query name)
                 -r                  (do not read ~/.digrc)
                 -t type             (specify query type)
                 -v                  (print version and exit)
                 -x dot-notation     (shortcut for reverse lookups)
                 -y [hmac:]name:key  (specify named base64 tsig key)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]aaflag         (Set AA flag in query (+[no]aaflag))
                 +[no]additional     (Control display of additional section)
                 +[no]adflag         (Set AD flag in query (+[no]adflag))
                 +[no]all            (Set or clear all display flags)
                 +[no]answer         (Control display of answer section)
                 +[no]authority      (Control display of authority section)
                 +[no]badcookie      (Retry BADCOOKIE responses)
                 +[no]cdflag         (Set checking disabled flag in query)
                 +[no]class          (Control display of class in records)
                 +[no]cmd            (Control display of command line)
                 +[no]comments       (Control display of comments)
                 +[no]crypto         (Control display of cryptographic fields)
                 +[no]defname        (Use search list (+[no]search))
                 +[no]dnssec         (Request DNSSEC records)
                 +[no]expire         (Request time to expire)
                 +[no]fail           (Don't try next server on SERVFAIL)
                 +[no]identify       (ID responders in short answers)
                 +[no]ignore         (Don't revert to TCP for TC responses)
                 +[no]multiline      (Print records in an expanded format)
                 +ndots=###          (Set search NDOTS value)
                 +[no]onesoa         (AXFR prints only one soa record)
                 +[no]qr             (Print question before sending)
                 +[no]question       (Control display of question section)
                 +[no]rdflag         (Recursive mode (+[no]rec[urse]))
                 +[no]recurse        (Recursive mode (+[no]rdflag))
                 +[no]search         (Set whether to use searchlist)
                 +[no]short          (Display nothing except short form of answer)
                 +[no]showsearch     (Search with intermediate results)
                 +split=##           (Split hex/base64 fields into chunks)
                 +[no]stats          (Control display of statistics)
                 +[no]tcp            (TCP mode (+[no]vc))
                 +timeout=###        (Set query timeout) [5]
                 +[no]trace          (Trace delegation down from root)
                 +tries=###          (Set number of UDP attempts) [3]
                 +[no]ttlid          (Control display of ttls in records)
                 +[no]ttlunits       (Display TTLs in human-readable units)
                 +[no]unknownformat  (Print RDATA in RFC 3597 "unknown" format)
                 +[no]vc             (TCP mode (+[no]tcp))
                 +[no]zflag          (Set Z flag in query)
        global d-opts and servers (before host name) affect all queries.
        local  d-opts and servers (after host name) affect only that lookup.
        -h (or +help) is to print help and exit.
"""

def print_help():
    print(HELP)

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    argv = sys.argv[1:]
    argv_str = ' '.join(argv)

    # No arguments: query root NS (same as real dig)
    if not argv:
        queries, o = parse_args(['.','NS'])
        argv_str = ''
    else:
        queries, o = parse_args(argv)

    # Batch file
    bf = getattr(o, '_batch_file', None)
    if bf:
        try:
            lines = open(bf).readlines()
        except IOError as e:
            sys.stderr.write(f";; ERROR opening batch file: {e}\n")
            sys.exit(1)
        rc = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('#'): continue
            bq, bo = parse_args(line.split())
            for q in bq:
                r = run_query(q, bo, line)
                if r: rc = r
        sys.exit(rc)

    rc = 0
    for idx, q in enumerate(queries):
        if idx > 0: print()
        r = run_query(q, o, argv_str)
        if r: rc = r
    sys.exit(rc)

if __name__ == '__main__':
    main()
