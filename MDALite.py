#!/usr/bin/env python
import logging
import getopt
from scapy import config
config.Conf.load_layers.remove("x509")

###### PLATFORM RELATED SOCKETS########
import platform
if platform.system() == "Darwin":
    config.conf.use_pcap = True
    config.conf.use_dnet = True
    from scapy.all import L3dnetSocket
    config.conf.L3socket = L3dnetSocket
elif platform.system() == "Linux":
    from scapy.all import L3RawSocket
    config.conf.L3socket = L3RawSocket
elif platform.system() == "Windows":
    config.conf.use_pcap = True
    config.conf.use_dnet = True
    from scapy.all import L3dnetSocket
    config.conf.L3socket = L3dnetSocket

from scapy.all import *
from Maths.Bounds import *
from Packets.Utils import *
from Graph.Operations import *
from Graph.Visualization import *
from scapy.contrib.icmp_extensions import *
from Graph.Statistics import *
from Graph.Probabilities import  *
from Alias.Resolution import *

# Link batches
max_batch_link_probe_size = 150

# Batching growth
batching_growth = 0.2

total_probe_sent = 0

total_replies = 0

default_stop_on_consecutive_stars = 3

max_acceptable_asymmetry = 400
# Check if too much negative deltas
default_timeout = 3
default_meshing_link_timeout = 3
default_icmp_rate_limit = 50

# Checking meshing flows
default_check_meshing_flows = 2

max_ttl = 30


# Flows that did not answer by ttl.
black_flows = {}

def increment_replies(n):
    global total_replies
    total_replies += n

def increment_probe_sent(n):
    global total_probe_sent
    total_probe_sent = total_probe_sent + n

def generate_probes(nprobes, destination, ttl, starting_flow_id):

    probes = []
    if nprobes > 0 :
        j = starting_flow_id
        while len(probes) < nprobes:
            j += 1
            if j not in black_flows[ttl - 1]:
                probes.append(build_probe(destination, ttl, j))
    return probes

def send_probes(probes, timeout, verbose = False):
    before = time.time()
    replies, answered = sr(probes, timeout=timeout, verbose=verbose)
    after =  time.time()
    increment_probe_sent(len(probes))
    increment_replies(len(replies.res))
    return replies, answered, before, after

def update_graph_from_replies(g, replies, before, after):
    for probe, reply in replies:
        src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
        ttl_probe, ip_id_probe = extract_probe_infos(probe)
        alias_result = [before, after, ip_id_reply, ip_id_probe]
        # Update the graph
        g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)

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
        # Find a flow that is not in black flow if possible
        candidates_flows = ttls_flow_ids[v][ttl]
        flow_id = None
        for candidate_flow in candidates_flows:
            if candidate_flow not in black_flows[ttl2]:
                flow_id = candidate_flow
                break
        if flow_id is not None:
            check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, unanswered, before, after = send_probes(check_neighbors_probes, default_timeout)
    update_unanswered(unanswered, ttl, False)
    update_graph_from_replies(g, replies, before, after)

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
                    if flow_id not in black_flows[ttl2]:
                        check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, unanswered, before, after = send_probes(check_neighbors_probes, default_timeout)
    update_unanswered(unanswered, ttl, False)
    update_graph_from_replies(g, replies, before, after)


def update_unanswered(unanswered, ttl, is_only_star, g = None):
    for probe in unanswered:
        flow_id = extract_flow_id_probe(probe)
        if is_only_star:
            src_ip = "* * * " + str(ttl)
            # Update the graph
            g = update_graph(g, src_ip, ttl, -1, flow_id, [], None)
        black_flows[ttl].append(flow_id)

def execute_phase1(g, destination, nks):
    global default_stop_on_consecutive_stars
    has_found_longest_path_to_destination = False
    consecutive_only_star = 0
    ttl = 1
    while not has_found_longest_path_to_destination and ttl < max_ttl:
        if consecutive_only_star == default_stop_on_consecutive_stars:
            logging.info(str(default_stop_on_consecutive_stars) + " consecutive hop with only stars found, stopping the algorithm, passing to next step")
            return True
        total_replies_ttl = 0
        replies_only_from_destination = True
        while total_replies_ttl < nks[2]:
            next_flow_id = max(find_max_flow_id(g, ttl), 0)
            phase1_probes = generate_probes(nks[2] - total_replies_ttl, destination, ttl, next_flow_id)
            replies, unanswered, before, after = send_probes(phase1_probes, default_timeout, True)
            total_replies_ttl += len(replies)
            if len(replies) == 0:
                if total_replies_ttl == 0 :
                    consecutive_only_star = consecutive_only_star + 1
                replies_only_from_destination = False
                update_unanswered(unanswered, ttl, True, g)
                break
            else:
                consecutive_only_star = 0
                update_unanswered(unanswered, ttl, False)
            for probe, reply in replies:
                src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
                ttl_probe, ip_id_probe = extract_probe_infos(probe)
                alias_result = [before, after, ip_id_reply, ip_id_probe]                # Update the graph
                g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
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
        # Generate the nprobes, don't use the black flows found at ttl - 1
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered, before, after = send_probes(probes, default_timeout)
        update_unanswered(unanswered, ttl, False)
        for probe, reply in replies:
            src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
            ttl_probe, ip_id_probe = extract_probe_infos(probe)
            alias_result = [before, after, ip_id_reply, ip_id_probe]
            if is_new_ip(g, src_ip):
                hypothesis = hypothesis + 1
            # Update the graph
            g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
        nprobe_sent = nprobe_sent + nprobes

def probe_asymmetry_ttl(g, destination, lb, ttl, nprobe_sent, max_probe_needed, nks):
    while nprobe_sent < max_probe_needed:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = max_probe_needed - nprobe_sent
        # Generate the nprobes
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered, before, after = send_probes(probes, default_timeout)
        update_unanswered(unanswered, ttl, False)
        update_graph_from_replies(g, replies, before, after)
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
def execute_phase3(g, destination, llb, vertex_confidence,total_budget, limit_link_probes, with_inference, nks, meshing_flows):
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
                    reconnect_flows_ttl_predecessor(g, destination, ttl, meshing_flows)
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                    # If we find width asymmetry with no cross edges, adapt nks
                    degrees = out_degrees_ttl(g, ttl - 1)
                else:
                    reconnect_flows_ttl_successor(g, destination, ttl-1, meshing_flows)
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
        logging.info('Meshing round ' + str(meshing_round) + ", sent " + str(total_probe_sent))
        meshing_round += 1
        responding = False
        for lb in llb:

            # Filter the ttls where there are multiple predecessors
            for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
                # First hop of the diamond does not have to be reconnected
                if ttl in ttl_finished:
                    continue
                if ttl == min(lb.get_ttl_vertices_number().keys()):
                    logging.info("TTL " + str(ttl) + " finished. Unmeshed hop.")
                    ttl_finished.append(ttl)
                    continue
                # Check if this TTL is a divergence point or a convergence point
                #probes_sent_to_current_ttl = find_probes_sent(g, ttl)
                if is_a_divergent_ttl(g, ttl):
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                else:
                    has_cross_edges = apply_multiple_successors_heuristic(g, ttl - 1)
                #probes_needed_to_reach_guarantees = max_probes_needed_ttl(g, lb, ttl, nks)
                has_to_probe_more = has_cross_edges
                if not mda_continue_probing_ttl(g, ttl-1, nks) or not has_cross_edges:
                    if not has_cross_edges:
                        logging.info("TTL " + str(ttl) + " finished. Unmeshed hop.")
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
                        nprobes = adaptive_icmp_rate[ttl]+1-len(overflows)
                        supplement_probes = generate_probes(nprobes, destination, ttl, next_flow_id)
                        check_links_probes.extend(supplement_probes)
                        replies, unanswered, before, after = send_probes(check_links_probes, default_timeout)
                        update_unanswered(unanswered, ttl, False)
                        if len(replies) > 0:
                            adapt_sending_rate(adaptive_icmp_rate, last_loss_fraction, adaptive_timeout, ttl, replies, unanswered)
                        discovered = 0
                        links_probes_sent += len(check_links_probes)
                        if len(replies) > 0:
                            responding = True
                        else:
                            logging.info("TTL " + str(ttl) + " finished. Not responding.")
                        for probe, reply in replies:
                            src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
                            ttl_probe, ip_id_probe = extract_probe_infos(probe)
                            alias_result = [before, after, ip_id_reply, ip_id_probe]
                            if has_discovered_edge(g, src_ip, ttl_probe, flow_id):
                                discovered = discovered + 1
                            # Update the graph
                            g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
                        # With the new flows generated, find the missing flows at ttl-1
                        check_missing_flow_probes = []
                        missing_flows = find_missing_flows(g, ttl, ttl-1)
                        for flow in missing_flows:
                            check_missing_flow_probes.append(build_probe(destination, ttl - 1, flow))
                        replies, unanswered, before, after = send_probes(check_missing_flow_probes, default_timeout)
                        update_unanswered(unanswered, ttl, False)
                        if len(replies) > 0:
                            responding = True
                        for probe, reply in replies:
                            src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
                            ttl_probe, ip_id_probe = extract_probe_infos(probe)
                            alias_result = [before, after, ip_id_reply, ip_id_probe]
                            # Update the graph
                            if has_discovered_edge(g, src_ip, ttl_probe, flow_id):
                                discovered = discovered + 1
                            g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
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

    # Get infos on fingerprinting
    echo_replies, unanswered = send_fingerprinting_probes(g)
    update_finger_printing(g, echo_replies)


    # Maintain thwo IP-ID time serie. One with no negative deltas and one with negative deltas.
    ip_ids = g.vertex_properties["ip_ids"]

    for lb in llb:
        # Filter the ttls where there are multiple predecessors
        for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
            # This commented line uses "common neighbor" heuristic to reduce the number of pairs
            # alias_candidates = find_alias_candidates(g, ttl)
            vertices_by_ttl = find_vertex_by_ttl(g, ttl)
            ###################### Use already collected IP-ID to fast discarding ##################
            time_series_by_vertices = { v : ip_ids[v] for v in vertices_by_ttl}
            estimation_stage_candidates, full_alias_candidates = pre_estimation_stage(g, time_series_by_vertices)


            ###################### Use MIDAR alias resolution technique #####################
            # Elimination stage
            #elimination_stage_candidates, full_alias_candidates = estimation_stage(g, vertices_by_ttl, ttl, destination)
            corroboration_stage_candidates, full_alias_candidates =  elimination_stage(g, estimation_stage_candidates, full_alias_candidates,
                                                                                     ttl, destination, None, default_number_mbt)
            # Elimination stage
            # corroboration_stage_candidates, full_alias_candidates = elimination_stage(g, elimination_stage_candidates, full_alias_candidates,
            #                                                                           ttl, destination, None, default_number_mbt - min_nb_serie)
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
                    update_graph(g, ip_address[v], ttl, -1, i, [], None)


def check_if_option(s, l, opts):
    for opt, arg in opts:
        if opt in (s, l):
            return True
    return False

def init_black_flows():
    for i in range(0, max_ttl):
        black_flows[i] = []

def main(argv):
    origin = time.time()
    # default values
    source_name = ""
    protocol = "udp"
    total_budget = 200000
    limit_edges = 20000

    vertex_confidence = 99
    output_file = ""
    with_inference = False
    save_flows_infos = False

    with_alias_resolution = False
    only_alias = False
    log_level = "INFO"

    meshing_flows = default_check_meshing_flows

    usage = 'Usage : 3-phase-mda.py <options> <destination>\n' \
                  'options : \n' \
                  '-o --ofile <outputfile> (*.xml, default: draw_graph) \n' \
                  '-c --vertex-confidence <vertex-confidence> (95, 99) Give the failure probability to use in the discovered topology\n' \
                  '-b --edge-budget <edge-budget> (default:5000) Budget used to discover the links when there is meshing in the topology\n' \
                  '-s --save-edge-flows Save in the serialized graph the which flows have discovered which interface (in case of remeasuring)\n' \
                  '-S --source <source> source ip to use in the packets\n' \
                  '-a --with-alias do alias resolution on load balancers found after MDA-lite\n'\
                  '-R --only-alias do only alias resolution (NOT WORKING ATM)\n'\
                  '-l --log-level set the logging level (Python standard values allowed)\n'\
                  '-f --meshing-flows set the number of flows to send back/forward to detect meshing (minimum is 2)'
    try:
        opts, args = getopt.getopt(argv, "ho:c:b:isS:aRl:f:", ["help","ofile=",
                                                           "vertex-confidence=",
                                                           "edge-budget=",
                                                           "with-inference",
                                                           "save-edge-flows",
                                                           "source=",
                                                           "with-alias",
                                                           "only-alias",
                                                           "log-level",
                                                           "meshing-flows"])
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
        elif opt in ("-R", "--only-alias"):
            only_alias = True
        elif opt in ("-l", "--log-level"):
            log_level = arg
        elif opt in ("-f", "--meshing-flows"):
            meshing_flows = int(arg)
    logging.basicConfig(level=getattr(logging, log_level.upper()))
    if len(args) != 1:
        print usage
        sys.exit(2)
    destination  = args[0]

    if not only_alias:
        init_black_flows()
        g = init_graph()
        r_g = None
        # 3 phases in the algorithm :
        # 1-2) hop by hop 6 probes to discover length + position of LB
        # 3) Load balancer discovery

        logging.info("Starting phase 1 and 2 : finding a length to the destination and the place of the diamonds...")
        # Phase 1
        execute_phase1(g, destination, get_nks()[1])

        #graph_topology_draw(g)

        #Phase 2
        llb = extract_load_balancers(g)

        # We assume symmetry until we discover that it is not.
        # First reach the nks for this corresponding hops.
        logging.info("Starting phase 3 : finding the topology of the discovered diamonds")
        execute_phase3(g, destination, llb, vertex_confidence,total_budget, limit_edges, with_inference, nk99, meshing_flows)
        # g = load_graph("test.xml")
        # llb = extract_load_balancers(g)
        clean_stars(g)
        reconnect_stars(g)
        remove_self_loop_destination(g, destination)
    if with_alias_resolution:
        logging.info("Starting phase 4 : proceeding to alias resolution")
        # HACK FOR DEBUG ###
        if only_alias:
            g = load_graph("test.xml")
            llb = extract_load_balancers(g)
        #############
        copy_g = Graph(g)
        interfaces = copy_g.new_vertex_property("vector<string>", [])
        copy_g.vertex_properties["interfaces"] = interfaces
        r_g = Graph(copy_g)
        before_alias = time.time()
        aliases = resolve_aliases(destination, llb, r_g)
        print "Duration of alias resolution : " + str(time.time() - before_alias) + " seconds"
        r_g = router_graph(aliases, r_g)
        remove_self_loop_destination(r_g, destination)

    print "Duration of measurement : " + str(time.time() - origin) + " seconds"
    print "Found a graph with " + str(len(g.get_vertices())) +" vertices and " + str(len(g.get_edges())) + " edges"
    print "Total probe sent : " + str(total_probe_sent)
    print "Total replies got : " + str(total_replies)
    print "Percentage of edges inferred : " + str(get_percentage_of_inferred(g))  + "%"
    print "Phase 3 finished"

    g_probe_sent = g.new_graph_property("int")
    g_probe_sent[g] = total_probe_sent
    g.graph_properties["probe_sent"] = g_probe_sent

    g_useful_probes = g.new_graph_property("int")
    g_useful_probes[g] = total_replies
    g.graph_properties["useful_probes"] = g_useful_probes

    if save_flows_infos:
        # Get source info
        source_ip = source_name
        enrich_flows(g, source_ip, destination, protocol, sport, dport)

    if output_file == "draw":
        graph_topology_draw(g)
        if with_alias_resolution:
            graph_router_topology_level_draw(r_g)
    elif output_file != "":
        g.save(output_file)
        if with_alias_resolution:
            r_g.save("router_level_" + output_file)
    # Dump results in any case
    dump_results(g, destination)
    if with_alias_resolution:
        dump_routers(r_g)
    #full_mda_g = load_graph("/home/osboxes/CLionProjects/fakeRouteC++/resources/ple2.planet-lab.eu_125.155.82.17.xml")
    #graph_topology_draw(full_mda_g)
if __name__ == "__main__":

    main(sys.argv[1:])
