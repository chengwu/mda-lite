from scapy.all import *
from Maths.Bounds import *

# Hardcoded sport
sport  = 24000
# Hardcoded dport
dport  = 33435
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

def build_alias_probe(destination):
    return IP(dst = destination)/ICMP()

# 1 protocol for prototyping, UDP
# Must write vertex_confidence
def get_phase_1_probe(destination, ttl, nks, starting_flow):
    probes = []
    for j in range (starting_flow, starting_flow + nk99[2]+1):
        probes.append(build_probe(destination, ttl, j))
    return probes

def extract_src_ip(p):
    return p[IP].src

def extract_flow_id_reply(reply):
    return reply[ICMP].sport - sport

def extract_flow_id_probe(probe):
    return probe[UDP].sport - sport

def extract_ttl(p):
    return p[IP].ttl

def extract_ip_id(reply):
    return reply[IP].id