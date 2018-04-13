from scapy.all import *
from Maths.Bounds import *
from scapy.packet import *
from scapy.contrib.icmp_extensions import *
# Hardcoded sport
sport  = 24000
# Hardcoded dport
dport  = 33435
# Hardcoded max_ttl

#nk to ensure 5% failure probability
nk95, nk99 = get_nks()

def build_icmp_echo_request_probe(destination):
    return IP(dst=destination)/ICMP()

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
def get_phase_1_probe(destination, ttl, nks, black_flows):
    white_flows = []
    i = 0
    while len(white_flows) < nks[2]:
        i += 1
        if i not in black_flows:
            white_flows.append(i)
    probes = []
    for j in white_flows:
        probes.append(build_probe(destination, ttl, j))
    return probes


def extract_time(p):
    return p[IP].time

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

def extract_icmp_reply_infos(reply):
    udp_error = reply[IP][ICMP][IPerror][UDPerror]
    # udp_error.post_dissection(reply)
    # udp_error.
    # Extract MPLS infos
    icmp_extension = udp_error.payload.payload.payload
    mpls_infos = None
    if type(icmp_extension) != scapy.packet.NoPayload:
        if type(icmp_extension.payload) == ICMPExtensionMPLS:
            # Extract MPLS stack
            mpls_stack = icmp_extension.payload.fields["stack"][0].fields
            mpls_infos = mpls_stack
    src_ip = extract_src_ip(reply)
    flow_id = extract_flow_id_reply(reply)
    ttl = extract_ttl(reply)
    ip_id = extract_ip_id(reply)
    return src_ip, flow_id, ttl, ip_id, mpls_infos

def extract_probe_infos(probe):
    ttl = extract_ttl(probe)
    ip_id = extract_ip_id(probe)

    return ttl, ip_id
