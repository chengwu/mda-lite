import threading
from scapy import config

#config.Conf.load_layers.remove("x509")

from graph_tool.all import *
from Graph.Operations import *
from Packets.Utils import  *
from Alias.Mpls import *


midar_unusable_treshold = 0.75
midar_degenerate_treshold = 0.25
midar_negative_delta_treshold = 0.5
# Dumb value here to avoid taking velocity into account
midar_discard_velocity_treshold = 100

default_alias_timeout = 1.5
default_alias_icmp_probe_number = 20
default_number_mbt = 2
default_elimination_alias_timeout = 1.5
default_fingerprinting_timeout = 5



def has_same_fingerprinting(g, v1, v2):
    fingerprinting = g.vertex_properties["fingerprinting"]
    fingerprint1 = fingerprinting[v1]
    fingerprint2 = fingerprinting[v2]

    # To see if they have the same signature, check if the closest power of 2 is the same.
    sig1 = [0, 0]
    sig2 = [0, 0]
    # ttl reply must be between 16 and 255, because the smallest value is 64.
    for i in range(4, 8):
        for j in range(0, len(fingerprint1)):
            if 2**i < fingerprint1[j] and fingerprint1[j] <= 2**(i+1):
                sig1[j] = i+1
            if 2 ** i < fingerprint2[j] and fingerprint2[j] <= 2 ** (i+1):
                sig2[j] = i+1


    for i in range(0, len(sig1)):
        # Handle the case where ICMP echo reply did not respond for one of the interface
        if sig1[i] == 0 or sig2[i] == 0:
            continue
        if sig1[i] != sig2[i]:
            return False

    return True

def send_fingerprinting_probes(g):
    ip_address = g.vertex_properties["ip_address"]
    fingerprinting_probes = []
    for v in g.vertices():
        # Do not send a ping to the source
        if int(v) != 0 and not ip_address[v].startswith("*"):
            dst_ip = ip_address[v]
            probe = build_icmp_echo_request_probe(dst_ip)
            fingerprinting_probes.append(probe)

    replies, unanswered = sr(fingerprinting_probes, timeout=default_fingerprinting_timeout, verbose=False)
    return replies, unanswered

def update_finger_printing(g, echo_replies):
    fingerprinting = g.vertex_properties["fingerprinting"]
    for probe, reply in echo_replies:
        ip_reply = extract_src_ip(reply)
        ttl_reply = extract_ttl(reply)
        v = find_vertex_by_ip(g, ip_reply)
        if v is not None:
            fingerprinting[v][0] = ttl_reply

def find_alias_candidates(g, ttl):
    ip_address = g.vertex_properties["ip_address"]
    vertices_ttl = find_vertex_by_ttl(g, ttl)

    alias_candidates = []

    already_added = []
    for v1 in vertices_ttl:
        if ip_address[v1].startswith("*"):
            already_added.append(v1)
            continue
        for v2 in vertices_ttl:
            if v1 == v2 \
                    or ip_address[v1].startswith("*") \
                    or ip_address[v2].startswith("*")\
                    or v2 in already_added:
                continue
            if has_common_neighbor(v1, v2):
                alias_candidates.append((v1, v2))
        already_added.append(v1)
    return alias_candidates


def get_deducable_alias_rec(v1, aliases, v1_aliases):
    for v, v_aliases in sorted(aliases.iteritems()):
        if v == v1:
            v1_aliases.add(v)
            v1_aliases = v1_aliases.union(v_aliases)
            for v_alias in v_aliases:
                get_deducable_alias_rec(v_alias, aliases, v1_aliases)
    return v1_aliases
def get_deducable_alias(v1, aliases):
    v1_aliases = set()
    if aliases.has_key(v1):
        v1_aliases = get_deducable_alias_rec(v1, aliases, v1_aliases)
    else:
        for v, v_aliases in sorted(aliases.iteritems()):
            has_found_alias = False
            for v_alias in v_aliases:
                if v_alias == v1:
                    v1_aliases = get_deducable_alias_rec(v, aliases, v1_aliases)
                    has_found_alias = True
                    break
            if has_found_alias:
                break
    return v1_aliases


# Returns whether two interfaces are aliases, + the min_key which is an alias to v1 if
def is_deducable_alias(v1, v2, aliases):
    v1_aliases = get_deducable_alias(v1, aliases)

    min_v1_alias = None
    for v1_alias in sorted(v1_aliases):
        if aliases.has_key(v1_alias):
            min_v1_alias = v1_alias
            break
    return v2 in v1_aliases, min_v1_alias


def update_alias(aliases):
    # The goal here is to find all the chains and simplify
    # the dictionnary by removing keys (using transitivity closure)
    alias_to_pop = set()
    already_treated = set()
    for v1, v1_alias in aliases.iteritems():
        for v2, v2_alias in aliases.iteritems():
            if v1 == v2 or v2 in already_treated:
                continue
            else:
                if len(v1_alias.intersection(v2_alias))> 0:
                    v1_alias.add(v2)
                    v1_alias = v1_alias.union(v2_alias)
                    alias_to_pop.add(v2)
        already_treated.add(v1)

    for alias in alias_to_pop:
        del aliases[alias]


# Take a list of list of vertices
def send_parallel_alias_probes(g, l_l_vertices, ttl, destination):
    if len(l_l_vertices) == 0:
        return {}
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]
    time_series_by_vertices = {}

    for l_vertices in l_l_vertices:
        for v in l_vertices:
            time_series_by_vertices[v] = []
    max_len = max([len(l) for l in l_l_vertices])
    # Has to check the ip_address to handle per packet LB, well, anw, it will be discarded
    # in the clean of the velocities
    for i in range(0, default_alias_icmp_probe_number):
        one_round_time_before = time.time()
        for j in range(0, max_len):
            alias_probes = []
            for l_vertices in l_l_vertices:
                if len(l_vertices) > j:
                    v = l_vertices[j]
                    flow_id = ttls_flow_ids[v][ttl][0]
                    alias_udp_probe = build_probe(destination, ttl, flow_id)
                    alias_probes.append(alias_udp_probe)
            before = time.time()
            replies, unanswered = sr(alias_probes, timeout=default_elimination_alias_timeout, verbose = False)
            after = time.time()
            if len(replies) == 0:
                continue
            for probe, reply in replies:
                reply_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
                ttl_probe, ip_id_probe = extract_probe_infos(probe)
                alias_result = [before, after, ip_id_reply, ip_id_probe]

                if ip_address[v] != reply_ip:
                    #print "Flow changed during measurement! Or it is may be not a per-flow load-balancer..."
                    update_graph(g, reply_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
                    other_v = find_vertex_by_ip(g, reply_ip)
                    if not time_series_by_vertices.has_key(other_v):
                        time_series_by_vertices[other_v] = [[before, after, ip_id_reply, ip_id_probe]]
                    else:
                        time_series_by_vertices[other_v].append([before, after, ip_id_reply, ip_id_probe])
                    continue
                time_series_by_vertices[v].append([before, after, ip_id_reply, ip_id_probe])
        if i %10 == 0:
            print str(i+1) + " round took " + (str(time.time() - one_round_time_before)) + " seconds, "\
                  + str(default_alias_icmp_probe_number - (i+1)) + " rounds remaining"
    return time_series_by_vertices

def send_alias_probes_multi_thread(g, v, ttl, destination, shared_dict):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]

    time_serie = []
    # Has to check the ip_address to handle per packet LB, well, anw, it will be discarded
    # in the clean of the velocities
    for i in range(0, default_alias_icmp_probe_number):
        one_round_time_before = time.time()
        flow_id = ttls_flow_ids[v][ttl][0]
        alias_udp_probe = build_probe(destination, ttl, flow_id)
        before = time.time()
        reply = sr1(alias_udp_probe, timeout=default_alias_timeout, verbose=False)
        after = time.time()
        if reply is None:
            continue
        ip_id = extract_ip_id(reply)
        reply_ip = extract_src_ip(reply)
        ttl_reply = extract_ttl(reply)

        if ip_address[v] != reply_ip:
            # print "Flow changed during measurement! Or it is may be not a per-flow load-balancer..."
            update_graph(g, reply_ip, ttl, ttl_reply, flow_id, [])
            continue
        time_serie.append([before, after, ip_id])
        if i % 10 == 0:
            print str(i + 1) + " round took " + (str(time.time() - one_round_time_before)) + " seconds, " \
                  + str(default_alias_icmp_probe_number - (i + 1)) + " rounds remaining"
    # Seems to not need a lock in python as they don't access the same key
    shared_dict[v] = time_serie

def compute_negative_delta(time_serie):
    for i in range(0, len(time_serie)-1):
        while time_serie[i][2] > time_serie[i+1][2]:
            time_serie[i+1][2] += 2**16

def is_unusable_probe_treshold(time_serie, default_icmp_probe_number):
    # Check if enough ip_id
    return len(time_serie) < midar_unusable_treshold * default_icmp_probe_number

def is_degenerate_treshold(ip_ids):
    # Check if enough distinct ip_id
    return len(set(ip_ids)) < midar_degenerate_treshold * len(ip_ids)

def is_recopy(ip_ids_probes, ip_ids):
    # Check if the ip ids we got are not just a recopy of those that we had sent (in Cisco Routers)
    is_copy = True
    for i in range(0, len(ip_ids)):
        if ip_ids[i] != ip_ids_probes[i]:
            is_copy = False
    return is_copy

def is_too_much_negative_deltas(time_serie):
    ip_ids_delta = [time_serie[i][2] - time_serie[i - 1][2] for i in range(1, len(time_serie))]

    # Check if too much negative deltas
    negative_deltas = list(filter(lambda x: x <= 0, ip_ids_delta))

    return len(negative_deltas) > midar_negative_delta_treshold * len(time_serie)

def compute_velocity_and_filter(time_serie, default_icmp_probe_number = default_alias_icmp_probe_number):
    # Do some checking to elapse "unusable" serie
    if is_unusable_probe_treshold(time_serie, default_icmp_probe_number):
        return None
    # Check if degenerate treshold
    ip_ids = [x[2] for x in time_serie]
    if is_degenerate_treshold(ip_ids):
        return None

    # Check if the ip ids we got are not just a recopy of those that we had sent (in Cisco Routers)
    ip_ids_probes = [x[3] for x in time_serie]
    if is_recopy(ip_ids_probes, ip_ids):
        return None

    ip_ids_delta = [time_serie[i][2] - time_serie[i-1][2] for i in range(1, len(time_serie))]

    # Take "after" time
    time_deltas = [time_serie[i][1] - time_serie[i-1][1] for i in range(1, len(time_serie))]

    # Check if too much negative deltas
    negative_deltas = list(filter(lambda x : x <= 0, ip_ids_delta))

    if len(negative_deltas) > midar_negative_delta_treshold * len(time_serie):
        return None

    for i in range(0, len(time_serie)-1):
        while time_serie[i][2] > time_serie[i+1][2]:
            time_serie[i+1][2] += 2**16

    ip_ids_delta = [time_serie[i][2] - time_serie[i-1][2] for i in range(1, len(time_serie))]

    # Compute velocity
    time_delta_sum = sum(time_deltas)
    ip_ids_delta_sum = float(sum(ip_ids_delta))
    if time_delta_sum != 0 and ip_ids_delta_sum != 0:
        return ip_ids_delta_sum / time_delta_sum
    else:
        return -1

def filter_candidates(velocities):
    candidates = []
    for i in range(0, len(velocities)-1):
        for j in range(i+1, len(velocities)):
            max_velocity = max(velocities[i][1], velocities[j][1])
            min_velocity = min(velocities[i][1], velocities[j][1])

            if (float(max_velocity)/min_velocity) > midar_discard_velocity_treshold:
                continue
            else:
                candidates.append((velocities[i][0], velocities[j][0]))
    return candidates

def is_overlapping(before1, after1, before2, after2):
    if (before1 < before2 and before2 < after1) :
        return True
    elif (before2 < before1 and before1 < after2):
        return True
    return False

def monotonic_bound_test(time_serie1, original_time_serie2):
    # Merge the two time series into 1
    time_serie = []
    time_serie2 = []
    # Tag with the number of time serie
    for l in time_serie1:
        copy_l = list(l)
        copy_l.append(1)
        time_serie.append(copy_l)
    for l in original_time_serie2:
        copy_l = list(l)
        copy_l.append(2)
        time_serie2.append(copy_l)
    # # Insert the timeserie2 to the right places
    # for i in range(0, len(time_serie2)):
    #     before2 = time_serie2[i][0]
    #     after2 = time_serie2[i][1]
    #     # Find the right place
    #     overlapping_indexes = []
    #     right_index = -1
    #     found_overlapping = False
    #     for j in range(0, len(time_serie)):
    #         before1 = time_serie[j][0]
    #         after1 = time_serie[j][1]
    #         if with_overlapping:
    #             has_overlapping = is_overlapping(before1, after1, before2, after2)
    #             if has_overlapping:
    #                 found_overlapping = True
    #                 overlapping_indexes.append(j)
    #                 continue
    #             if found_overlapping:
    #                 break
    #         if j == 0:
    #             if after2 < before1:
    #                 right_index = 0
    #         if j == len(time_serie) - 1:
    #             if after1 < before2:
    #                 right_index = -2
    #             else:
    #                 right_index = j
    #             break
    #         # Between j and j+1
    #         if after1 <= before2 and after2 <= time_serie[j+1][0]:
    #             right_index = j + 1
    #             break
    #     if with_overlapping:
    #         if len(overlapping_indexes) > 0:
    #             # Handle the case where there is an after overlaping probe that has been already put
    #             last_overlapping_index = overlapping_indexes[len(overlapping_indexes) - 1]
    #             before2 = time_serie2[i][0]
    #             has_found_after_overlaping = False
    #             # Find the last element from time_serie2
    #             serie2_inserted_elements = list(filter(lambda x : x[3] == 2, time_serie[last_overlapping_index:]))
    #             if len(serie2_inserted_elements) > 0:
    #                 last_serie2_element = serie2_inserted_elements[len(serie2_inserted_elements)-1]
    #             else:
    #                 last_serie2_element = None
    #             if last_serie2_element is not None:
    #                 for j in range(last_overlapping_index, len(time_serie)):
    #                     if last_serie2_element == time_serie[j]:
    #                         has_found_after_overlaping = True
    #                         if j == len(time_serie) - 1:
    #                             time_serie.append(time_serie2[i])
    #                         time_serie.insert(j+1, time_serie2[i])
    #                         break
    #                 if has_found_after_overlaping:
    #                     continue
    #             for k in range(0, len(overlapping_indexes)):
    #                 if k == 0:
    #                     if time_serie2[i][2] < time_serie[overlapping_indexes[k]][2]:
    #                         time_serie.insert(overlapping_indexes[k], time_serie2[i])
    #                 if k == len(overlapping_indexes) - 1:
    #                     if time_serie2[i][2] > time_serie[overlapping_indexes[k]][2]:
    #                         if overlapping_indexes[k] == len(time_serie) - 1:
    #                             time_serie.append(time_serie2[i])
    #                         else:
    #                             time_serie.insert(overlapping_indexes[k] + 1, time_serie2[i])
    #                 elif time_serie2[i][2] > time_serie[overlapping_indexes[k]][2] \
    #                         and time_serie2[i][2] < time_serie[overlapping_indexes[k+1]][2]:
    #                     time_serie.insert(overlapping_indexes[k]+1, time_serie2[i])
    #             continue
    #     if right_index == -2:
    #         time_serie.append(time_serie2[i])
    #     else:
    #         time_serie.insert(right_index, time_serie2[i])




    time_serie.extend(time_serie2)
    # Sort by ip_id
    time_serie.sort(key=lambda x: x[2])
    # Sort by before time (stable, guaranteed by python)
    time_serie.sort(key=lambda x : x[0])

    ip_id_serie = [x[2] for x in time_serie]
    sorted_ip_id_serie = sorted(ip_id_serie)

    for i in range(0, len(ip_id_serie)):
        if ip_id_serie[i] != sorted_ip_id_serie[i]:
            return False
    return True

def apply_mbt_fingerprinting_ttl(g, time_serie_by_v):
    ip_address = g.vertex_properties["ip_address"]
    mpls = g.vertex_properties["mpls"]
    candidates = []
    for v, time_serie in time_serie_by_v.iteritems():
        # This does filter on ip id series that are not usable... That sould be renamed.
        velocity = compute_velocity_and_filter(time_serie, len(time_serie))
        if velocity is not None:
            candidates.append((v, velocity))
        else:
            # Take MPLS candidates as they respect different rules.
            if len(mpls[v]) > 0:
                candidates.append((v, -1))
    # Filter those which have too much different velocity
    # TODO This should be an option as it is an optimization
    alias_candidates = filter_candidates(candidates)

    next_stage_candidates = {}
    full_alias_candidates = {}
    for v1, v2 in alias_candidates:
        if not full_alias_candidates.has_key(v1):
            full_alias_candidates[v1] = set()
        if not full_alias_candidates.has_key(v2):
            full_alias_candidates[v2] = set()
    for v1, v2 in alias_candidates:
        #print "Estimation stage : Applying MBT to candidates " + ip_address[v1] + " and " + ip_address[v2]
        time_serie1 = time_serie_by_v[v1]
        time_serie2 = time_serie_by_v[v2]

        has_monotonicity_requirement = monotonic_bound_test(time_serie1, time_serie2)
        same_fingerprinting = has_same_fingerprinting(g, v1, v2)
        same_mpls_label = is_mpls_alias(g, v1, v2)
        if (has_monotonicity_requirement and same_fingerprinting) or same_mpls_label:
            print ip_address[v1] + " and " + ip_address[v2] + " passed the estimation stage!"
            full_alias_candidates[v1].add(v2)
            full_alias_candidates[v2].add(v1)
            min_alias = min(v1, v2)
            max_alias = max(v1, v2)
            if next_stage_candidates.has_key(min_alias):
                next_stage_candidates[min_alias].add(max_alias)
            else:
                next_stage_candidates[min_alias] = set()
                next_stage_candidates[min_alias].add(max_alias)
            update_alias(next_stage_candidates)
    return next_stage_candidates, full_alias_candidates


def get_already_collected_time_series_by_vertices(g, vertices_by_ttl):
    time_series_by_vertices = {}
    for v in vertices_by_ttl:
        time_series_by_vertices[v] = split_ip_id_series(g, v)
    return time_series_by_vertices
def split_ip_id_series(g, v):
    ip_ids = g.vertex_properties["ip_ids"]
    flat_serie = ip_ids[v]
    series = []
    for i in range (0, len(flat_serie), default_alias_icmp_probe_number):
        serie = []
        for j in range(i, i + default_alias_icmp_probe_number):
            if len(flat_serie) > j :
                serie.append(flat_serie[j])
            else:
                break
        series.append(serie)
    return series

def remove_mpls_alias(g, l_l_subgraphs):
    mpls_all_alias_subgraphs = []
    for l_subgraph in l_l_subgraphs:
        mpls_all_alias = True
        for i in range(0, len(l_subgraph) - 1):
            if not is_mpls_alias(g, l_subgraph[i], l_subgraph[i + 1]):
                mpls_all_alias = False
                break
        if mpls_all_alias:
            mpls_all_alias_subgraphs.append(l_subgraph)
    for mpls_subgroup in mpls_all_alias_subgraphs:
        l_l_subgraphs.remove(mpls_subgroup)

def pre_estimation_stage(g, time_serie_by_v):
    return apply_mbt_fingerprinting_ttl(g, time_serie_by_v)

def elimination_stage(g, elimination_stage_candidates, full_alias_candidates, ttl, destination, already_collected_time_series = None, nb_round = default_number_mbt):
    assert(already_collected_time_series is None or nb_round == 1)
    ip_address = g.vertex_properties["ip_address"]
    mpls = g.vertex_properties["mpls"]
    elimination_to_remove = set()
    if len(elimination_stage_candidates) > 0:
        for k in range(0, nb_round):
            print str(k) + " on " + str(nb_round-1) + " rounds of elimination stage..."
            print str(len(elimination_stage_candidates)) + " subgroups of ips to test for elimination stage"
            l_l_subgraphs = []
            for elimination_candidate, set_candidates in elimination_stage_candidates.iteritems():
                candidates = list(set_candidates)
                candidates.sort()
                candidates.append(elimination_candidate)
                l_l_subgraphs.append(candidates)
            # If there is subgroup with all MPLS alias in a subgroup, do not probe this group.
            remove_mpls_alias(g, l_l_subgraphs)
            #print "Applying elimination stage to " + str(len(candidates)) + " candidates... This can take few minutes"
            if already_collected_time_series is None:
                time_series_by_candidate = send_parallel_alias_probes(g, l_l_subgraphs, ttl, destination)
            else:
                time_series_by_candidate = already_collected_time_series


            candidates_to_remove_treshold = []
            for v, time_serie in time_series_by_candidate.iteritems():
                compute_negative_delta(time_serie)
                ip_ids = [x[2] for x in time_serie]
                ip_ids_probes = [x[3] for x in time_serie]
                if is_degenerate_treshold(ip_ids):
                    candidates_to_remove_treshold.append(v)
                    continue
                if is_recopy(ip_ids_probes, ip_ids):
                    candidates_to_remove_treshold.append(v)
                    continue

            for candidates in l_l_subgraphs:

                    # # For debug
                    # ip_ids = [x[2] for x in time_serie]
                    # sorted_ip_ids = sorted(ip_ids)
                    # for i in range(0, len(ip_ids)):
                    #     if sorted_ip_ids[i] != ip_ids[i]:
                    #         print "Error of sorting during negative deltas"
                for i in range(0, len(candidates)):
                    time_serie1 = time_series_by_candidate[candidates[i]]
                    for j in range(i + 1, len(candidates)):
                        min_candidate = min(candidates[i], candidates[j])
                        max_candidate = max(candidates[i], candidates[j])
                        time_serie2 = time_series_by_candidate[candidates[j]]
                        # print "Elimination stage : Applying MBT to candidates "\
                        #       + ip_address[candidates[i]] + \
                        #       " and " + ip_address[candidates[j]]
                        # This condition almost guarantees that they are aliases
                        if len(mpls[candidates[i]]) > 0 and len(mpls[candidates[j]]) > 0:
                            same_mpls_label = is_mpls_alias(g, candidates[i], candidates[j])
                            if not same_mpls_label:

                                elimination_to_remove.add((min_candidate, max_candidate))
                            # No need to look at MBT in case of MPLS
                            continue
                        pass_mbt = monotonic_bound_test(time_serie1, time_serie2)

                        if not pass_mbt \
                                or candidates[i] in candidates_to_remove_treshold\
                                or candidates[j] in candidates_to_remove_treshold:
                            #print ip_address[candidates[i]] + " and " + ip_address[candidates[j]] + " discarded from the elimination stage!"
                            elimination_to_remove.add((min_candidate, max_candidate))

            for candidate1, candidate2 in elimination_to_remove:
                full_alias_candidates[candidate1].discard(candidate2)
                full_alias_candidates[candidate2].discard(candidate1)
                if len(full_alias_candidates[candidate1]) == 0:
                    #print "Full alias candidate" + str(full_alias_candidates)
                    if elimination_stage_candidates.has_key(candidate1):
                        elimination_stage_candidates.pop(candidate1, None)
                        #print "Elimination of candidate : " + str(candidate1)
                        #print str(elimination_stage_candidates)
                if len(full_alias_candidates[candidate2]) == 0:
                    #print "Full alias candidate" + str(full_alias_candidates)
                    if elimination_stage_candidates.has_key(candidate2):
                        elimination_stage_candidates.pop(candidate2, None)
                       # print "Elimination of candidate : " + str(candidate2)
                       # print str(elimination_stage_candidates)

        for elimination_candidate, candidates in elimination_stage_candidates.iteritems():
            candidates.discard(elimination_candidate)
            for candidate in candidates :
                if candidate != elimination_candidate:
                    print ip_address[elimination_candidate] + " and " + ip_address[candidate] + " passed the elimination stage!"
    #print "After elimination... : " + str(elimination_stage_candidates)
    return elimination_stage_candidates, full_alias_candidates


def remove_self_loop_destination(g, destination):

    v_destination = find_vertex_by_ip(g, destination)
    if v_destination is not None:
        edge_to_remove = g.edge(v_destination, v_destination)
        if edge_to_remove is not None:
            g.remove_edge(edge_to_remove)

def router_graph(aliases, g):
    vertices_to_be_removed = set()
    for v1, v1_aliases in aliases.iteritems():
        for v1_alias in v1_aliases:
            if v1 != v1_alias:
                merge_vertices(g, v1, v1_alias)
                vertices_to_be_removed.add(v1_alias)
    for v in reversed(sorted(vertices_to_be_removed)):
        g.remove_vertex(v)
    return g


if __name__ == "__main__" :
    time_serie1 = [[1522017310.698866, 1522017310.759052, 45777], [1522017310.761394, 1522017310.887182, 45782], [1522017310.891868, 1522017310.974049, 45791], [1522017311.087585, 1522017311.144181, 45800], [1522017311.146305, 1522017311.208234, 45807], [1522017311.211479, 1522017311.297533, 45812], [1522017311.421824, 1522017311.48208, 45832], [1522017311.485019, 1522017311.594683, 45837], [1522017311.597857, 1522017311.72943, 45848], [1522017311.935086, 1522017311.992369, 45863], [1522017311.995046, 1522017312.058773, 45875], [1522017312.063074, 1522017312.283871, 45881], [1522017312.405538, 1522017312.552792, 45899], [1522017312.555223, 1522017312.613298, 45908], [1522017312.616858, 1522017312.687449, 45915], [1522017312.977399, 1522017313.039613, 45931], [1522017313.044398, 1522017313.131288, 45940], [1522017313.134536, 1522017313.20177, 45944], [1522017313.322574, 1522017313.385278, 45956], [1522017313.388336, 1522017313.450243, 45964], [1522017313.4552, 1522017313.543724, 45970], [1522017313.662402, 1522017313.718402, 45984], [1522017313.720806, 1522017313.777442, 45988], [1522017313.781156, 1522017313.844563, 45994], [1522017314.020803, 1522017314.077421, 46012], [1522017314.080178, 1522017314.151039, 46017], [1522017314.154903, 1522017314.219311, 46023], [1522017314.33768, 1522017314.40725, 46031], [1522017314.409904, 1522017314.468005, 46037], [1522017314.471469, 1522017314.538047, 46045], [1522017314.683387, 1522017314.78567, 46065], [1522017314.788094, 1522017314.896561, 46071], [1522017314.899978, 1522017315.008034, 46079], [1522017315.183507, 1522017315.240655, 46094], [1522017315.243339, 1522017315.329069, 46101], [1522017315.332381, 1522017315.395747, 46105], [1522017315.521421, 1522017315.657785, 46120], [1522017315.660391, 1522017315.753283, 46130], [1522017315.756383, 1522017315.889357, 46135], [1522017316.004589, 1522017316.060325, 46152], [1522017316.062946, 1522017316.171537, 46159], [1522017316.175554, 1522017316.238951, 46164], [1522017316.350817, 1522017316.409786, 46177], [1522017316.412941, 1522017316.471497, 46182], [1522017316.474725, 1522017316.532457, 46189], [1522017316.649757, 1522017316.704355, 46205], [1522017316.70697, 1522017316.769681, 46210], [1522017316.773398, 1522017316.842047, 46217], [1522017316.948229, 1522017317.007123, 46229], [1522017317.00978, 1522017317.124128, 46235], [1522017317.128334, 1522017317.194094, 46242], [1522017317.308686, 1522017317.363969, 46251], [1522017317.367396, 1522017317.480462, 46255], [1522017317.484892, 1522017317.639786, 46266], [1522017317.76884, 1522017317.874718, 46283], [1522017317.877088, 1522017317.937662, 46289], [1522017317.941086, 1522017318.006205, 46293], [1522017318.106888, 1522017318.185611, 46304], [1522017318.188148, 1522017318.24754, 46309], [1522017318.250988, 1522017318.370831, 46319]]




    time_serie2 = [[1522017310.761394, 1522017310.887182, 45780], [1522017310.891868, 1522017310.974049, 45789], [1522017311.146305, 1522017311.208234, 45805], [1522017311.211479, 1522017311.297533, 45811], [1522017311.485019, 1522017311.594683, 45835], [1522017311.597857, 1522017311.72943, 45845], [1522017311.995046, 1522017312.058773, 45874], [1522017312.063074, 1522017312.283871, 45879], [1522017312.555223, 1522017312.613298, 45907], [1522017312.616858, 1522017312.687449, 45913], [1522017313.044398, 1522017313.131288, 45938], [1522017313.134536, 1522017313.20177, 45945], [1522017313.388336, 1522017313.450243, 45962], [1522017313.4552, 1522017313.543724, 45969], [1522017313.720806, 1522017313.777442, 45989], [1522017313.781156, 1522017313.844563, 45993], [1522017314.080178, 1522017314.151039, 46015], [1522017314.154903, 1522017314.219311, 46020], [1522017314.409904, 1522017314.468005, 46038], [1522017314.471469, 1522017314.538047, 46043], [1522017314.788094, 1522017314.896561, 46069], [1522017314.899978, 1522017315.008034, 46078], [1522017315.243339, 1522017315.329069, 46100], [1522017315.332381, 1522017315.395747, 46103], [1522017315.660391, 1522017315.753283, 46128], [1522017315.756383, 1522017315.889357, 46136], [1522017316.062946, 1522017316.171537, 46157], [1522017316.175554, 1522017316.238951, 46165], [1522017316.412941, 1522017316.471497, 46183], [1522017316.474725, 1522017316.532457, 46190], [1522017316.70697, 1522017316.769681, 46211], [1522017316.773398, 1522017316.842047, 46215], [1522017317.00978, 1522017317.124128, 46234], [1522017317.128334, 1522017317.194094, 46241], [1522017317.367396, 1522017317.480462, 46254], [1522017317.484892, 1522017317.639786, 46263], [1522017317.877088, 1522017317.937662, 46288], [1522017317.941086, 1522017318.006205, 46294], [1522017318.188148, 1522017318.24754, 46308], [1522017318.250988, 1522017318.370831, 46318]]



    assert (monotonic_bound_test(time_serie1, time_serie2))
    time_serie1 = [[1521765740.574121, 1521765740.85391, 58735], [1521765740.856793, 1521765741.133759, 58794], [1521765741.135618, 1521765741.400234, 58801], [1521765741.400823, 1521765741.673021, 58861], [1521765741.673791, 1521765741.910665, 58929], [1521765741.911525, 1521765742.121136, 58962], [1521765742.124138, 1521765742.373575, 58984], [1521765742.374328, 1521765742.667429, 58996], [1521765742.668358, 1521765742.927068, 59010], [1521765742.928, 1521765743.202223, 59012], [1521765743.20344, 1521765743.513158, 59077], [1521765743.531633, 1521765743.802154, 59156], [1521765743.803213, 1521765744.00471, 59188], [1521765744.009941, 1521765744.313797, 59227], [1521765744.314439, 1521765744.516593, 59270], [1521765744.517182, 1521765744.759956, 59319], [1521765744.762354, 1521765744.998487, 59379], [1521765744.999178, 1521765745.262332, 59408], [1521765745.26306, 1521765745.572959, 59459], [1521765745.573662, 1521765745.749304, 59517], [1521765745.750173, 1521765745.949354, 59526], [1521765745.950874, 1521765746.30047, 59561], [1521765746.301371, 1521765746.449778, 59565], [1521765746.452786, 1521765746.545202, 59595], [1521765746.546475, 1521765746.683006, 59604], [1521765746.686395, 1521765746.743163, 59620], [1521765746.745772, 1521765746.802531, 59630], [1521765746.803523, 1521765746.861579, 59640], [1521765746.862792, 1521765746.910679, 59649], [1521765746.911778, 1521765746.950112, 59650]]
    time_serie2 = [[1521765740.677916, 1521765740.987718, 51208], [1521765740.989298, 1521765741.214548, 51265], [1521765741.215242, 1521765741.504743, 51283], [1521765741.505357, 1521765741.785454, 51291], [1521765741.786376, 1521765741.889876, 51333], [1521765741.909854, 1521765742.125637, 51346], [1521765742.12663, 1521765742.384633, 51391], [1521765742.394436, 1521765742.738914, 51455], [1521765742.744668, 1521765743.016611, 51506], [1521765743.01741, 1521765743.315387, 51544], [1521765743.317169, 1521765743.585733, 51592], [1521765743.588204, 1521765743.705631, 51647], [1521765743.707362, 1521765743.925208, 51664], [1521765743.925994, 1521765744.130475, 51703], [1521765744.131409, 1521765744.37247, 51716], [1521765744.376166, 1521765744.642112, 51748], [1521765744.643104, 1521765744.768343, 51765], [1521765744.769261, 1521765744.875911, 51777], [1521765744.876553, 1521765745.186713, 51794], [1521765745.188376, 1521765745.270207, 51821], [1521765745.271241, 1521765745.480966, 51833], [1521765745.492889, 1521765745.824302, 51876], [1521765745.832986, 1521765746.005268, 51899], [1521765746.010414, 1521765746.135123, 51935], [1521765746.139311, 1521765746.225639, 51948], [1521765746.250071, 1521765746.397855, 51955], [1521765746.39869, 1521765746.524796, 51979], [1521765746.525592, 1521765746.652564, 51986], [1521765746.653889, 1521765746.740783, 51991], [1521765746.741627, 1521765746.812151, 52014]]
    pass_mbt = monotonic_bound_test(time_serie1, time_serie2)
    assert(not pass_mbt)
