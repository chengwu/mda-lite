#!/usr/bin/env python

from scapy import config
import sys, getopt
import time
import threading
config.Conf.load_layers.remove("x509")
import shlex
from scapy.all import *
from Maths.Bounds import *
from Packets.Utils import *
from Graph.Operations import *
from Graph.Visualization import *
from Graph.Statistics import *
from Graph.Probabilities import  *
from Alias.Resolution import *
import platform

# Link batches
max_batch_link_probe_size = 150

# Batching growth
batching_growth = 0.2

total_probe_sent = 0

default_stop_on_consecutive_stars = 3

max_acceptable_asymmetry = 400
# Check if too much negative deltas
default_timeout = 3
default_meshing_link_timeout = 3
default_icmp_rate_limit = 50

max_ttl = 30
def increment_probe_sent(n):
    global total_probe_sent
    total_probe_sent = total_probe_sent + n

def update_graph_from_replies(g, replies):
    for probe, reply in replies:
        src_ip = extract_src_ip(reply)
        flow_id = extract_flow_id_reply(reply)
        ttl = extract_ttl(probe)
        # Update the graph
        g = update_graph(g, src_ip, ttl, flow_id)

def reconnect_successors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl + 1)

def reconnect_predecessors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl-1)

def reconnect_impl(g, destination, ttl, ttl2):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    if ttl > ttl2 :
        no_neighbors_vertices = find_no_predecessor_vertices(g, ttl)
    else:
        no_neighbors_vertices = find_no_successor_vertices(g, ttl)
    check_neighbors_probes = []
    for v in no_neighbors_vertices:
        flow_id = ttls_flow_ids[v][ttl][0]
        check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, answered = sr(check_neighbors_probes, timeout=default_timeout, verbose=False)
    increment_probe_sent(len(check_neighbors_probes))
    update_graph_from_replies(g, replies)

# These functions reconnect a flow_number number of flows (serves for checking cross edges)
def reconnect_flows_ttl_predecessor(g, destination, ttl, flow_number):
    reconnect_flows_ttl_impl(g, destination, ttl, ttl - 1, flow_number)

def reconnect_flows_ttl_successor(g, destination, ttl, flow_number):
    reconnect_flows_ttl_impl(g, destination, ttl , ttl + 1, flow_number)
def reconnect_flows_ttl_impl(g, destination, ttl, ttl2, flow_number):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    check_neighbors_probes = []
    for v in vertices_ttl:
        for i in range(1, flow_number+1):
            flow_ids_ttl = ttls_flow_ids[v][ttl]
            if len(flow_ids_ttl) >= i:
                flow_id = ttls_flow_ids[v][ttl][i - 1]
                predecessors = find_vertex_by_ttl_flow_id(g, ttl2, flow_id)
                if predecessors is None:
                    check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, answered = sr(check_neighbors_probes, timeout=default_timeout, verbose=False)
    increment_probe_sent(len(check_neighbors_probes))
    update_graph_from_replies(g, replies)

def reconnect_all_neigh_flows_ttl(g, destination, ttl, ttl2):
    missing_flows = find_missing_flows(g, ttl, ttl2)
    check_predecessor_probes = []
    for flow_id in missing_flows:
        check_predecessor_probes.append(build_probe(destination, ttl2, flow_id))
    increment_probe_sent(len(check_predecessor_probes))
    replies, answered = sr(check_predecessor_probes, timeout=default_timeout, verbose=False)
    update_graph_from_replies(g, replies)

def reconnect_all_succ_flows_ttl(g, destination, ttl):
    reconnect_all_neigh_flows_ttl(g, destination, ttl, ttl + 1)

def reconnect_all_pred_flows_ttl(g, destination, ttl):
    reconnect_all_neigh_flows_ttl(g, destination, ttl, ttl - 1)

def reconnect_all_flows(g, destination, llb):
    # Third round, try to infer the missing links if necessary from the flows we already have
    for lb in llb:
        for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            if ttl == min(lb.get_ttl_vertices_number().keys()):
                continue
            # Check if this TTL is a divergence point or a convergence point
            if is_a_divergent_ttl(g, ttl):
               has_to_probe_more = apply_multiple_predecessors_heuristic(g, ttl)
            else:
               has_to_probe_more = apply_multiple_successors_heuristic(g, ttl - 1)
            if has_to_probe_more:
                # Here it is more complicated, we have to infer multiple predecessors
                reconnect_all_pred_flows_ttl(g, destination, ttl)


def execute_phase1(g, destination, nks):
    global default_stop_on_consecutive_stars
    has_found_longest_path_to_destination = False
    consecutive_only_star = 0
    ttl = 1
    starting_flow = 1
    while not has_found_longest_path_to_destination and ttl < max_ttl:
        if consecutive_only_star == default_stop_on_consecutive_stars:
            print str(default_stop_on_consecutive_stars) + " consecutive hop with only stars found, stopping the algorithm, passing to next step"
            return True
        phase1_probes = get_phase_1_probe(destination, ttl, nks, starting_flow)
        replies, unanswered = sr(phase1_probes, timeout=default_timeout, verbose=True)
        increment_probe_sent(len(phase1_probes))
        replies_only_from_destination = True
        if len(replies) == 0:
            consecutive_only_star = consecutive_only_star + 1
            replies_only_from_destination = False
            starting_flow += nks[2]
        else:
            consecutive_only_star = 0
        for probe in unanswered:
            flow_id = extract_flow_id_probe(probe)
            src_ip = "* * * " + str(ttl)
            # Update the graph
            g = update_graph(g, src_ip, ttl, flow_id)
        for probe, reply in replies:
            src_ip = extract_src_ip(reply)
            flow_id = extract_flow_id_reply(reply)
            probe_ttl = extract_ttl(probe)
            # Update the graph
            g = update_graph(g, src_ip, probe_ttl, flow_id)
            # graph_topology_draw(g)
            print src_ip
            if src_ip != destination:
                replies_only_from_destination = False
        if replies_only_from_destination:
            has_found_longest_path_to_destination = True
        ttl = ttl + 1
    return False
def probe_until_nk(g, destination, ttl, nprobe_sent, hypothesis, nks):
    while nprobe_sent < nks[hypothesis]:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = nks[hypothesis] - nprobe_sent
        probes = []
        # Generate the nprobes
        for j in range(1, nprobes + 1):
            probes.append(build_probe(destination, ttl, next_flow_id + j))
        increment_probe_sent(len(probes))
        replies, answered = sr(probes, timeout=default_timeout, verbose=False)
        for probe, reply in replies:
            src_ip = extract_src_ip(reply)
            flow_id = extract_flow_id_reply(reply)
            probe_ttl = extract_ttl(probe)
            if is_new_ip(g, src_ip):
                hypothesis = hypothesis + 1
            # Update the graph
            g = update_graph(g, src_ip, probe_ttl, flow_id)
        nprobe_sent = nprobe_sent + nprobes

def probe_asymmetry_ttl(g, destination, lb, ttl, nprobe_sent, max_probe_needed, nks):
    while nprobe_sent < max_probe_needed:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = max_probe_needed - nprobe_sent
        probes = []
        # Generate the nprobes
        for j in range(1, nprobes + 1):
            probes.append(build_probe(destination, ttl, next_flow_id + j))
        increment_probe_sent(len(probes))
        replies, answered = sr(probes, timeout=default_timeout, verbose=False)
        for probe, reply in replies:
            src_ip = extract_src_ip(reply)
            flow_id = extract_flow_id_reply(reply)
            probe_ttl = extract_ttl(probe)
            # Update the graph
            g = update_graph(g, src_ip, probe_ttl, flow_id)
        nprobe_sent = nprobe_sent + nprobes
        reconnect_predecessors(g, destination, ttl)
        max_probe_needed = max_probes_needed_ttl(g, lb, ttl, nks)

def get_ttls_in_lb(llb):
    ttls_with_lb = []
    for lb in llb:
        for ttl in lb.get_ttl_vertices_number():
            ttls_with_lb.append(ttl)
    return ttls_with_lb

def adapt_sending_rate(adaptive_icmp_rate, last_loss_fraction, adaptive_timeout, ttl, replies, unanswered):
    if last_loss_fraction[ttl] >= float(len(unanswered)) / len(replies):
        adaptive_icmp_rate[ttl] += int(batching_growth * adaptive_icmp_rate[ttl])
        last_loss_fraction[ttl] = float(len(unanswered)) / len(replies)
        adaptive_timeout[ttl] += 1
    elif last_loss_fraction[ttl] < float(len(unanswered)) / len(replies):
        adaptive_icmp_rate[ttl] -= int(batching_growth * adaptive_icmp_rate[ttl])
        last_loss_fraction[ttl] = float(len(unanswered)) / len(replies)
        adaptive_timeout[ttl] -= 1
def execute_phase3(g, destination, llb, vertex_confidence,total_budget, limit_link_probes, with_inference, nks, verbose):
    #llb : List of load balancer lb
    for lb in llb:
        # nint is the number of already discovered interfaces
        for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            probe_until_nk(g, destination, ttl, find_probes_sent(g, ttl), nint+1, nks)
            # Check if this is a divergent ttl and if we found cross edges
            is_divergent_ttl = is_a_divergent_ttl(g, ttl)
            vertices_prev_ttl = find_vertex_by_ttl(g, ttl-1)
            vertices_next_ttl = find_vertex_by_ttl(g, ttl+1)
            if len(vertices_prev_ttl) == 1:
                # Only reconnect predecessors if we know we have only one pred at ttl-1
                reconnect_predecessors(g, destination, ttl)
            if len(vertices_next_ttl) == 1:
                reconnect_successors(g, destination, ttl)
            if len(vertices_prev_ttl) > 1:
                if is_divergent_ttl:
                    # Reconnect predecessors with a certain number of flows available in order to figure out width asymmetry
                    reconnect_flows_ttl_predecessor(g, destination, ttl, 2)
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                    # If we find width asymmetry with no cross edges, adapt nks
                    degrees = out_degrees_ttl(g, ttl - 1)
                else:
                    reconnect_flows_ttl_successor(g, destination, ttl-1, 2)
                    has_cross_edges = apply_multiple_successors_heuristic(g, ttl-1)
                    degrees = in_degrees_ttl(g, ttl)
                if len(set(degrees)) != 1 and not has_cross_edges:
                    # Here we have to pass in a "local" mode with nk's for each node.
                    # Find the number of different interfaces discovered for each node at this ttl
                    # If the asymmetry is too high, meaning we are gonna loose a lot of probes to reach nks,
                    # do not do it
                    max_probe_needed = max_probes_needed_ttl(g, lb, ttl, nks)
                    probe_sent = find_probes_sent(g, ttl)
                    if max_probe_needed - probe_sent <= max_acceptable_asymmetry:
                        probe_asymmetry_ttl(g, destination, lb, ttl, probe_sent, max_probe_needed, nks)
                if with_inference:
                    if len(lb.get_ttl_vertices_number()) == 1:
                        apply_converging_heuristic(g, ttl, forward=True, backward=True)
                    elif ttl == max(lb.get_ttl_vertices_number().keys()):
                        apply_converging_heuristic(g, ttl, forward=True, backward=False)


    # Second step has been done previously by reconnecting two flows by divergent/convergent hop
    # to discover if a topology is asymmetric


    # Third step, try to infer the missing links if necessary from the flows we already have
    #reconnect_all_flows(g, destination, llb)

    # Fourth round, try to infer the missing links by generating new flows
    # This number is parametrable

    # If three consecutive rounds where we do not discover more edges, we stop
    consecutive_round_without_new_information = 0
    links_probes_sent = 0
    responding = True
    # Optimization to tell keep in memory if a ttl has reached its statistical guarantees.
    ttl_finished = []
    meshing_round = 0

    # Prepare the map of the adaptive ICMP rates
    adaptive_icmp_rate = {}
    last_loss_fraction = {}
    adaptive_timeout = {}
    for lb in llb:
        for ttl , nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            adaptive_icmp_rate[ttl] = max_batch_link_probe_size
            last_loss_fraction[ttl] = 1.0
            adaptive_timeout[ttl] = default_meshing_link_timeout
    while total_probe_sent < total_budget \
            and links_probes_sent < limit_link_probes\
            and responding\
            and len(ttl_finished) < len(get_ttls_in_lb(llb)):
        if meshing_round % 5 == 0:
            print 'Meshing round ' + str(meshing_round) + ", sent " + str(total_probe_sent)
        meshing_round += 1
        responding = False
        for lb in llb:

            # Filter the ttls where there are multiple predecessors
            for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
                # First hop of the diamond does not have to be reconnected
                if ttl in ttl_finished:
                    continue
                if ttl == min(lb.get_ttl_vertices_number().keys()):
                    ttl_finished.append(ttl)
                    continue
                # Check if this TTL is a divergence point or a convergence point
                probes_sent_to_current_ttl = find_probes_sent(g, ttl)
                if is_a_divergent_ttl(g, ttl):
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                else:
                    has_cross_edges = apply_multiple_successors_heuristic(g, ttl - 1)
                probes_needed_to_reach_guarantees = max_probes_needed_ttl(g, lb, ttl, nks)
                has_to_probe_more = has_cross_edges
                if probes_needed_to_reach_guarantees <= probes_sent_to_current_ttl or not has_cross_edges:
                    ttl_finished.append(ttl)
                    has_to_probe_more = False
                if has_to_probe_more:
                    # Generate probes new flow_ids
                    if links_probes_sent < limit_link_probes:
                        # Privilegiate flows that are already at ttl - 1
                        check_links_probes = []
                        overflows = find_missing_flows(g, ttl-1, ttl)
                        for flow in overflows:
                            check_links_probes.append(build_probe(destination, ttl, flow))
                        next_flow_id_overflows = 0
                        if len(overflows) != 0:
                            next_flow_id_overflows = max(overflows)
                        next_flow_id = max(find_max_flow_id(g, ttl), next_flow_id_overflows)
                        # Adapt the batch depending on how much probe we can send without reaching ICMP Rate limit
                        for i in range(1, adaptive_icmp_rate[ttl]+1-len(overflows)):
                            check_links_probes.append(build_probe(destination, ttl, next_flow_id + i))
                        increment_probe_sent(len(check_links_probes))
                        replies, answered = sr(check_links_probes, timeout=adaptive_timeout[ttl], verbose=verbose)
                        if len(replies) > 0:
                            adapt_sending_rate(adaptive_icmp_rate, last_loss_fraction, adaptive_timeout, ttl, replies, answered)
                        discovered = 0
                        links_probes_sent += len(check_links_probes)
                        if len(replies) > 0:
                            responding = True
                        for probe, reply in replies:
                            src_ip = extract_src_ip(reply)
                            flow_id = extract_flow_id_reply(reply)
                            probe_ttl = extract_ttl(probe)
                            if has_discovered_edge(g, src_ip, probe_ttl, flow_id):
                                discovered = discovered + 1
                            # Update the graph
                            g = update_graph(g, src_ip, probe_ttl, flow_id)
                        # With the new flows generated, find the missing flows at ttl-1
                        check_missing_flow_probes = []
                        missing_flows = find_missing_flows(g, ttl, ttl-1)
                        for flow in missing_flows:
                            check_missing_flow_probes.append(build_probe(destination, ttl - 1, flow))
                        increment_probe_sent(len(check_missing_flow_probes))
                        replies, answered = sr(check_missing_flow_probes, timeout=adaptive_timeout[ttl], verbose=verbose)
                        if len(replies) > 0:
                            responding = True
                        for probe, reply in replies:
                            src_ip = extract_src_ip(reply)
                            flow_id = extract_flow_id_reply(reply)
                            probe_ttl = extract_ttl(probe)
                            # Update the graph
                            if has_discovered_edge(g, src_ip, probe_ttl, flow_id):
                                discovered = discovered + 1
                            g = update_graph(g, src_ip, probe_ttl, flow_id)
                        links_probes_sent += len(check_missing_flow_probes)
                        #dump_flows(g)

    # Final reconnection in case we have weird stuff
    for lb in llb:
        # Filter the ttls where there are multiple predecessors
        for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            reconnect_predecessors(g, destination, ttl)
            reconnect_successors(g, destination, ttl)

    # Apply final heuristics based on symmetry to infer links
    if with_inference:
        remove_parallel_edges(g)
        for lb in llb:
            # Filter the ttls where there are multiple predecessors
            for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
                apply_symmetry_heuristic(g, ttl, 2)
    remove_parallel_edges(g)



def resolve_aliases(destination, llb, g):
    aliases = {}

    for lb in llb:
        # Filter the ttls where there are multiple predecessors
        for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            # This commented line uses "common neighbor" heuristic to reduce the number of pairs
            # alias_candidates = find_alias_candidates(g, ttl)
            vertices_by_ttl = find_vertex_by_ttl(g, ttl)

            ###################### Use MIDAR alias resolution technique #####################
            # Estimation stage
            elimination_stage_candidates, full_alias_candidates = estimation_stage(g, vertices_by_ttl, ttl, destination)
            # Elimination stage
            corroboration_stage_candidates = elimination_stage(g, elimination_stage_candidates, full_alias_candidates, ttl, destination)
            # Do not do the corroboratino stage as the subgraphs are already small in elimination stage
            aliases.update(corroboration_stage_candidates)
            ####################### End of MIDAR #########################
    return aliases

def reconnect_stars(g):
    # If some vertices are discovered at a given hop with
    # a certain flow and previous or next hop is only star, reconnect it
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v].startswith("*"):
            for ttl, flow_ids in ttls_flow_ids[v].iteritems():
                max_flow_id = max(find_max_flow_id(g, ttl+1), find_max_flow_id(g, ttl-1))
                for i in range(0, max_flow_id):
                    update_graph(g, ip_address[v], ttl, i)


def check_if_option(s, l, opts):
    for opt, arg in opts:
        if opt in (s, l):
            return True
    return False
def main(argv):
    origin = time.time()
    # default values
    source_name = ""
    protocol = "udp"
    total_budget = 200000
    limit_edges = 2000
    vertex_confidence = 99
    output_file = ""
    with_inference = False
    save_flows_infos = False

    with_alias_resolution = True
    usage = 'Usage : 3-phase-mda.py <options> <destination>\n' \
                  'options : \n' \
                  '-o --ofile <outputfile> (*.xml, default: draw_graph) \n' \
                  '-c --vertex-confidence <vertex-confidence> (95, 99) Give the failure probability to use in the discovered topology\n' \
                  '-b --edge-budget <edge-budget> (default:5000) Budget used to discover the links when there is meshing in the topology\n' \
                  '-s --save-edge-flows Save in the serialized graph the which flows have discovered which interface (in case of remeasuring)\n' \
                  '-S --source <source> source ip to use in the packets\n' \
                  '-a --with-alias do alias resolution on load balancers found\n'
    try:
        opts, args = getopt.getopt(argv, "ho:c:b:isS:a", ["help","ofile=", "vertex-confidence=", "edge-budget=", "with-inference", "save-edge-flows", "source=", "with-alias"])
    except getopt.GetoptError:
        print usage
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print usage

            sys.exit(2)
        elif opt in ("-o", "--ofile"):
            output_file = arg
        elif opt in ("-c", "--vertex-confidence"):
            vertex_confidence = int(arg)
        elif opt in ("-b", "--edge-budget"):
            limit_edges = int(arg)
        elif opt in ("-i", "--with-inference"):
            with_inference = True
        elif opt in ("-s", "--save-edge-flows"):
            if check_if_option("-S", "--source", opts):
                save_flows_infos = True
            else:
                print "Please provide a source if you want to save flows edges"
                exit(2)
        elif opt in ("-S", "--source"):
            source_name = arg
        elif opt in ("-a", "--with-alias"):
            with_alias_resolution = True
    if len(args) != 1:
        print usage
        sys.exit(2)
    destination  = args[0]


    g = init_graph()
    r_g = None
    # 3 phases in the algorithm :
    # 1-2) hop by hop 6 probes to discover length + position of LB
    # 3) Load balancer discovery

    print "Starting phase 1 and 2 : finding a length to the destination and the place of the diamonds..."
    # Phase 1
    has_exited_on_consecutive_stars = execute_phase1(g, destination, get_nks()[1])

    #graph_topology_draw(g)

    #Phase 2
    llb = extract_load_balancers(g)

    # We assume symmetry until we discover that it is not.
    # First reach the nks for this corresponding hops.
    print "Starting phase 3 : finding the topology of the discovered diamonds"
    verbose = False
    execute_phase3(g, destination, llb, vertex_confidence,total_budget, limit_edges, with_inference, nk99, verbose)
    # g = load_graph("test.xml")
    # llb = extract_load_balancers(g)
    clean_stars(g)
    reconnect_stars(g)
    remove_self_loops(g)
    if with_alias_resolution:
        print "Starting phase 4 : proceeding to alias resolution"
        # THE BEST IDEA I EVER HAD : DO ALIAS RESOLUTION HERE!
        copy_g = Graph(g)
        interfaces = copy_g.new_vertex_property("vector<string>", [])
        copy_g.vertex_properties["interfaces"] = interfaces
        r_g = Graph(copy_g)
        before_alias = time.time()
        aliases = resolve_aliases(destination, llb, r_g)
        print "Duration of alias resolution : " + str(time.time() - before_alias) + " seconds"
        r_g = router_graph(aliases, r_g)
        remove_self_loops(r_g)

    print "Duration of measurement : " + str(time.time() - origin) + " seconds"
    print "Found a graph with " + str(len(g.get_vertices())) +" vertices and " + str(len(g.get_edges())) + " edges"
    print "Total probe sent : " + str(total_probe_sent)
    print "Percentage of edges inferred : " + str(get_percentage_of_inferred(g))  + "%"
    print "Phase 3 finished"

    g_probe_sent = g.new_graph_property("int")
    g_probe_sent[g] = total_probe_sent
    g.graph_properties["probe_sent"] = g_probe_sent



    if output_file == "":
        graph_topology_draw(g)
        if with_alias_resolution:
            graph_router_topology_level_draw(r_g)
    else:
        if save_flows_infos:
            # Get source info
            source_ip = source_name
            enrich_flows(g, source_ip, destination, protocol, sport, dport)
        g.save(output_file)
        if with_alias_resolution:
            r_g.save("router_level_" + output_file)
    dump_results(g, destination)
    #full_mda_g = load_graph("/home/osboxes/CLionProjects/fakeRouteC++/resources/ple2.planet-lab.eu_125.155.82.17.xml")
    #graph_topology_draw(full_mda_g)
if __name__ == "__main__":

    if platform.system() == "Darwin":
        config.conf.L3socket = L3dnetSocket
    elif platform.system() == "Linux":
        config.conf.L3socket = L3RawSocket
    elif platform.system() == "Windows":
        config.conf.L3socket = L3dnetSocket

    main(sys.argv[1:])

