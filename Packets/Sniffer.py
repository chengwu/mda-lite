from graph_tool.all import *
from scapy.all import *
from Graph.Operations import *

def callback(reply):
    src_ip = extract_src_ip(reply)
    flow_id = extract_flow_id_reply(reply)
    ttl = extract_ttl(probe)
    # Update the graph
    g = update_graph(g, src_ip, ttl, flow_id)

def sniff_thread(g):

    while True:
        sniff()
