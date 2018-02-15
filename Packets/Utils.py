from scapy.all import *
from Maths.Bounds import *

# Hardcoded sport
sport  = 24000
# Hardcoded dport
dport  = 33456
# Hardcoded max_ttl

#nk to ensure 5% failure probability
nk95, nk99 = get_nks()

def build_probe(destination, ttl, flow_id):
    ip = build_ip_probe(destination, ttl)
    udp = build_transport_probe(flow_id)
    raw = build_raw_probe("he")
    return ip/udp/raw

def build_ip_probe(destination, ttl):
    return IP(dst=destination, ttl=ttl)

def build_transport_probe(flow_id):
    return UDP(dport = dport, sport = sport + flow_id)
def build_raw_probe(data):
    return Raw(load = data)

# 1 protocol for prototyping, UDP
# Must write vertex_confidence
def get_phase_1_probe(destination, ttl, vertex_confidence):
    probes = []
    for j in range (1, nk99[2]+1):
        probes.append(build_probe(destination, ttl, j))
    return probes

def extract_src_ip(p):
    return p[IP].src

def extract_flow_id_reply(reply):
    return reply[ICMP].sport - 24000

def extract_flow_id_probe(probe):
    return probe[UDP].sport-24000

def extract_ttl(p):
    return p[IP].ttl