import logging
from MDALite import *
from Packets.Utils import *
from graph_tool.all import *
from Graph.Operations import *
# RIPE SIMULATION BEHAVIOUR
ripe_max_flow_number = 16
default_stop_on_consecutive_stars = 3
max_ttl = 30
# The algorithm is pretty simple, ripe_max_flow_number by hop.
def execute_ripe_mda(destination):
    init_black_flows()
    g = init_graph()
    global default_stop_on_consecutive_stars
    has_found_longest_path_to_destination = False
    consecutive_only_star = 0
    ttl = 1
    while not has_found_longest_path_to_destination and ttl < max_ttl:
        if consecutive_only_star == default_stop_on_consecutive_stars:
            logging.info(str(
                default_stop_on_consecutive_stars) + " consecutive hop with only stars found, stopping the algorithm, passing to next step")
            return g
        total_replies_ttl = 0
        replies_only_from_destination = True
        while total_replies_ttl < ripe_max_flow_number:
            #next_flow_id = max(find_max_flow_id(g, ttl), 0)
            phase1_probes = generate_probes(ripe_max_flow_number - total_replies_ttl, destination, ttl, 0)
            replies, unanswered, before, after = send_probes(phase1_probes, default_timeout, True)
            total_replies_ttl += len(replies)
            if len(replies) == 0:
                if total_replies_ttl == 0:
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
                alias_result = [before, after, ip_id_reply, ip_id_probe]  # Update the graph
                g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
                # graph_topology_draw(g)
                print src_ip
                if src_ip != destination:
                    replies_only_from_destination = False
        if replies_only_from_destination:
            has_found_longest_path_to_destination = True
        ttl = ttl + 1
    return g

if __name__ == "__main__":
    destination = sys.argv[2]
    output_file = sys.argv[1]
    g = execute_ripe_mda(destination)
    g_probe_sent = g.new_graph_property("int")
    g_probe_sent[g] = total_probe_sent
    g.graph_properties["probe_sent"] = g_probe_sent
    g.save(output_file)
    dump_results(g, destination)