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

def execute_phase3(g, destination, llb):
    #llb : List of load balancer lb
    for lb in llb:
        # nint is the number of already discovered interfaces
        for ttl, nint in lb.get_ttl_vertices_number().iteritems():
            # TODO Parametrize the nks
            nprobe_sent = find_probes_sent(g, ttl)
            hypothesis = nint + 1
            while nprobe_sent < nk95[hypothesis]:
                flow_id = find_max_flow_id(g, ttl) + 1
                nprobes = nk95[hypothesis] - nprobe_sent
                probes  = []
                # Generate the nprobes
                for j in range(1, nprobes + 1):
                    ip = build_ip_probe(destination, ttl)
                    udp = build_transport_probe(flow_id + j)
                    probes.append(ip/udp)
                replies, answered = sr(probes, timeout=1, verbose=False)
                for probe, reply in replies:
                    src_ip = extract_src_ip(reply)
                    flow_id = extract_flow_id(reply)
                    ttl = extract_ttl(probe)
                    if is_new_ip(g, src_ip):
                        hypothesis = hypothesis + 1
                    # Update the graph
                    g = update_graph(g, src_ip, ttl, flow_id)
                nprobe_sent = nprobe_sent + nprobes
            if len(lb.get_ttl_vertices_number()) == 1:
                apply_converging_heuristic(g, ttl)
                #graph_topology_draw(g)


def main():
    budget  = 500
    used    = 0
    g = init_graph()
    # 3 phases in the algorithm :
    # 1-2) hop by hop 6 probes to discover length + position of LB
    # 3) Load balancer discovery

    destination  = sys.argv[1]
    print "Starting phase 1 and 2 : finding a length to the destination and the load balancers"
    # Phase 1
    has_found_destination = False
    ttl = 1
    while not has_found_destination or used >= budget:
        phase1_probes = get_phase_1_probe(destination, ttl)
        replies, unanswered = sr(phase1_probes, timeout=1, verbose=False)
        used = used + len(phase1_probes)
        for probe, reply in replies:
            src_ip  = extract_src_ip(reply)
            flow_id = extract_flow_id(reply)
            ttl     = extract_ttl(probe)
            # Update the graph
            g = update_graph(g, src_ip, ttl, flow_id)
            #graph_topology_draw(g)

            if src_ip == destination:
                has_found_destination = True
        ttl = ttl + 1
    #graph_topology_draw(g)

    #Phase 2
    llb = extract_load_balancers(g)

    # We assume symmetry until we discover that it is not.
    # First reach the nks for this corresponding hops.
    execute_phase3(g, destination, llb)

    print "Phase 3 finished"
    # Heuristics :
    # 1) If all flows reconverge to 1 interface
    # 2) If shared succesors
if __name__ == "__main__":
    config.conf.L3socket = L3RawSocket
    main()
