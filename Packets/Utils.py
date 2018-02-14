from scapy.all import *

def extract_src_ip(p):
    return p[IP].src

def extract_flow_id_reply(reply):
    return reply[ICMP].sport - 24000

def extract_flow_id_probe(probe):
    return probe[UDP].sport-24000

def extract_ttl(p):
    return p[IP].ttl