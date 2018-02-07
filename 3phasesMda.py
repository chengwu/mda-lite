from scapy import config
config.Conf.load_layers.remove("x509")
from scapy.all import *
from Maths.Bounds import *
from Packets.Utils import *
from Graph.Operations import *
from Graph.Visualization import *
# Hardcoded sport
sport  = 24000
# Hardcoded dport
dport  = 33657
# Hardcoded max_ttl
max_ttl= 30

#nk to ensure 5% failure probability
nk95, nk99 = get_nks()

def build_ip_probe(destination, ttl):
    return IP(dst=destination, ttl=ttl)

def build_transport_probe(flow_id):
    return UDP(dport = dport, sport = sport + flow_id)

# 1 protocol for prototyping, UDP
def get_phase_1_probe(destination, ttl):
    probes = []
    for j in range (1, nk95[2]+1):
        ip  = build_ip_probe(destination, ttl)
        udp = build_transport_probe(j)
        probes.append(ip/udp)
    return probes

def main():
    g = init_graph()
    # 3 phases in the algorithm :
    # 1-2) hop by hop 6 probes to discover length + position of LB
    # 3) Load balancer discovery

    destination  = sys.argv[1]
    print "Starting phase 1 and 2 : finding a length to the destination and the load balancers"
    # Phase 1
    has_found_destination = False
    ttl = 1
    while not has_found_destination:
        phase1_probes = get_phase_1_probe(destination, ttl)
        replies, unanswered = sr(phase1_probes, timeout=1, verbose = False)
        for probe, reply in replies:
            src_ip  = extract_src_ip(reply)
            flow_id = extract_flow_id(reply)
            ttl     = extract_ttl(probe)
            # Update the graph
            g = update_graph(g, src_ip, flow_id, ttl)
            graph_topology_draw(g)

            if src_ip == destination:
                has_found_destination = True
                break
        ttl = ttl + 1

    #Phase 2

    # Heuristics :
    # 1) If all flows reconverge to 1 interface
    # 2) If shared succesors
if __name__ == "__main__":
    config.conf.L3socket = L3RawSocket
    main()
