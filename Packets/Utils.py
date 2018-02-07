from scapy.all import *

def extract_src_ip(p):
    return p[IP].src

def extract_flow_id(p):
    return p[ICMP].sport - 24000