from Utils import *


def probe_until_nk_mda(g, destination, ttl, nprobe_sent, hypothesis, nks):
    while nprobe_sent < nks[hypothesis]:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = nks[hypothesis] - nprobe_sent
        # Generate the nprobes, don't use the black flows found at ttl - 1
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered, before, after = send_probes(probes, default_timeout)
        if len(replies) == 0 and nprobe_sent == 0:
            update_unanswered(unanswered, ttl, True, g)
        else:
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

def mda(g, destination, nks):
    ip_address = g.vertex_properties["ip_address"]


    consecutive_star = 0
    for ttl in range (0, max_ttl):

        vertices_ttl = find_vertex_by_ttl(g, ttl)
        while mda_continue_probing_ttl(g, ttl, nks):
            # If the only vertex at TTL is a star, we dont need stochastic probing. Just send some flows until reach nks.

            if len(vertices_ttl) == 1 and ip_address[vertices_ttl[0]].startswith("*"):
                # 1 for nb successor, +1 for index in table nks
                probe_until_nk_mda(g, destination, ttl+1, 0, 1+1, nks)
                break
            # If not enough flows, do some stochastic probing and Node control.
            # If the stochastic flows are the same during N rounds, stop the ttl.
            same_consecutive_stochastic_flows = 0
            stochastic_flows = node_control_ttl(g, ttl, nks)
            while stochastic_flows > 0:
                stochastic_probing(g, destination, ttl, stochastic_flows)
                next_stochastic_flows = node_control_ttl(g, ttl, nks)
                if stochastic_flows == next_stochastic_flows:
                    same_consecutive_stochastic_flows += 1
                    if same_consecutive_stochastic_flows == 30:
                        break
                stochastic_flows = next_stochastic_flows

            # Then forward these flows the the subsequent hop
            flows = flows_to_forward(g, ttl, nks)
            forward_flows(g, destination, ttl, flows)


        # Return if destination reached.
        only_destination = True
        vertices_successors = find_vertex_by_ttl(g, ttl + 1)

        if len(vertices_successors) == 1 and ip_address[vertices_successors[0]].startswith("*"):
            consecutive_star += 1
            if consecutive_star < default_stop_on_consecutive_stars:
                continue
            else:
                logging.info(str(default_stop_on_consecutive_stars) + " consecutive stars found, stopping the algorithm.")
                return
        else:
            consecutive_star = 0
        for v in vertices_successors:
            if ip_address[v] != destination:
                only_destination = False
                break
        if only_destination:
            return

