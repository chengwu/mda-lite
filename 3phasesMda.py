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

# Link batches
batch_link_probe_size = 30

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

def reconnect_successors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl + 1)

def reconnect_predecessors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl-1)

def reconnect_impl(g, destination, ttl, ttl2):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    no_predecessor_vertices = find_no_predecessor_vertices(g, ttl)
    check_predecessor_probes = []
    for v in no_predecessor_vertices:
        flow_id = ttls_flow_ids[v][ttl][0]
        ip = build_ip_probe(destination, ttl2)
        udp = build_transport_probe(flow_id)
        check_predecessor_probes.append(ip / udp)
    replies, answered = sr(check_predecessor_probes, timeout=1, verbose=False)
    for probe, reply in replies:
        src_ip = extract_src_ip(reply)
        flow_id = extract_flow_id(reply)
        ttl = extract_ttl(probe)
        # Update the graph
        g = update_graph(g, src_ip, ttl, flow_id)

def execute_phase3(g, destination, llb, limit_link_probes):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    #llb : List of load balancer lb
    for lb in llb:
        # nint is the number of already discovered interfaces
        for ttl, nint in lb.get_ttl_vertices_number().iteritems():
            # TODO Parametrize the nks
            nprobe_sent = find_probes_sent(g, ttl)
            hypothesis = nint + 1
            while nprobe_sent < nk99[hypothesis]:
                next_flow_id = find_max_flow_id(g, ttl)
                nprobes = nk99[hypothesis] - nprobe_sent
                probes  = []
                # Generate the nprobes
                for j in range(1, nprobes + 1):
                    ip = build_ip_probe(destination, ttl)
                    udp = build_transport_probe(next_flow_id + j)
                    probes.append(ip/udp)
                replies, answered = sr(probes, timeout=1, verbose=False)
                for probe, reply in replies:
                    src_ip = extract_src_ip(reply)
                    flow_id = extract_flow_id(reply)
                    probe_ttl = extract_ttl(probe)
                    if is_new_ip(g, src_ip):
                        hypothesis = hypothesis + 1
                    # Update the graph
                    g = update_graph(g, src_ip, probe_ttl, flow_id)
                nprobe_sent = nprobe_sent + nprobes

            if len(lb.get_ttl_vertices_number()) == 1:
                apply_converging_heuristic(g, ttl, forward=True, backward=True)
            elif ttl == max(lb.get_ttl_vertices_number().keys()):
                apply_converging_heuristic(g, ttl, forward=True, backward=False)
    # Second round, reconnect all the nodes that have no successors or no predecessors
    for lb in llb:
        for ttl, nint in lb.get_ttl_vertices_number().iteritems():
            reconnect_predecessors(g, destination, ttl)
            reconnect_successors(g, destination, ttl)
    #graph_topology_draw(g)
    # Third round, try to infer the missing links if necessary from the flows you already have
    for lb in llb:
        for ttl, nint in lb.get_ttl_vertices_number().iteritems():
            if ttl == min(lb.get_ttl_vertices_number().keys()):
                continue
            if apply_has_predecessors_heuristic(g, ttl):
                # Here it is more complicated, we have to infer multiple predecessors
                missing_flows = find_missing_flows(g, ttl, ttl - 1)
                check_predecessor_probes = []
                for flow_id in missing_flows:
                    ip = build_ip_probe(destination, ttl-1)
                    udp = build_transport_probe(flow_id)
                    check_predecessor_probes.append(ip / udp)
                replies, answered = sr(check_predecessor_probes, timeout=1, verbose=False)
                for probe, reply in replies:
                    src_ip = extract_src_ip(reply)
                    flow_id = extract_flow_id(reply)
                    probe_ttl = extract_ttl(probe)
                    # Update the graph
                    g = update_graph(g, src_ip, probe_ttl, flow_id)

    # Fourth round, try to infer the missing links by generating new flows
    # This number is parametrable
    links_probes_sent = 0
    while links_probes_sent < limit_link_probes:
        for lb in llb:
            # Filter the ttls where there are multiple predecessors
            for ttl, nint in lb.get_ttl_vertices_number().iteritems():
                if ttl == min(lb.get_ttl_vertices_number().keys()):
                    continue
                if apply_has_predecessors_heuristic(g, ttl):
                    has_discovered_new_link = True
                    # Generate probes new flow_ids
                    while has_discovered_new_link:
                        has_discovered_new_link = False
                        # Privilegiate flows that are already at ttl - 1
                        check_links_probes = []
                        overflows = find_missing_flows(g, ttl-1, ttl)
                        for flow in overflows:
                            ip = build_ip_probe(destination, ttl)
                            udp = build_transport_probe(flow)
                            check_links_probes.append(ip / udp)
                        next_flow_id_overflows = 0
                        if len(overflows) != 0:
                            next_flow_id_overflows = max(overflows)
                        next_flow_id = max(find_max_flow_id(g, ttl), next_flow_id_overflows)
                        for i in range(1, batch_link_probe_size+1-len(overflows)):
                            ip = build_ip_probe(destination, ttl)
                            udp = build_transport_probe(next_flow_id + i)
                            check_links_probes.append(ip / udp)
                        replies, answered = sr(check_links_probes, timeout=1, verbose=False)
                        discovered = 0

                        for probe, reply in replies:
                            src_ip = extract_src_ip(reply)
                            flow_id = extract_flow_id(reply)
                            probe_ttl = extract_ttl(probe)
                            if has_discovered_edge(g, src_ip, probe_ttl, flow_id):
                                has_discovered_new_link = True
                                discovered = discovered + 1
                            # Update the graph
                            g = update_graph(g, src_ip, probe_ttl, flow_id)
                        links_probes_sent = links_probes_sent + batch_link_probe_size
                        # With the new flows generated, find the missing flows at ttl-1
                        check_missing_flow_probes = []
                        missing_flows = find_missing_flows(g, ttl, ttl-1)
                        for flow in missing_flows:
                            ip = build_ip_probe(destination, ttl-1)
                            udp = build_transport_probe(flow)
                            check_missing_flow_probes.append(ip / udp)
                        replies, answered = sr(check_missing_flow_probes, timeout=1, verbose=False)
                        for probe, reply in replies:
                            src_ip = extract_src_ip(reply)
                            flow_id = extract_flow_id(reply)
                            probe_ttl = extract_ttl(probe)
                            # Update the graph
                            if has_discovered_edge(g, src_ip, probe_ttl, flow_id):
                                has_discovered_new_link = True
                                discovered = discovered + 1
                            g = update_graph(g, src_ip, probe_ttl, flow_id)
                        links_probes_sent = links_probes_sent + len(check_missing_flow_probes)
                        dump_flows(g)

def main():
    budget  = 500
    used    = 0
    limit_edges = 2500
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
    execute_phase3(g, destination, llb, limit_edges)
    remove_parallel_edges(g)
    graph_topology_draw(g)
    print "Phase 3 finished"

    full_mda_g = load_graph("/home/osboxes/CLionProjects/fakeRouteC++/resources/ple2.planet-lab.eu_125.155.82.17.xml")
    graph_topology_draw(full_mda_g)
    # Heuristics :
    # 1) If all flows reconverge to 1 interface
    # 2) If shared succesors
if __name__ == "__main__":
    config.conf.L3socket = L3RawSocket
    main()
