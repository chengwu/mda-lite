import threading

from graph_tool.all import *
from Graph.Operations import *
from Packets.Utils import  *

midar_unusable_treshold = 0.75
midar_degenerate_treshold = 0.25
midar_negative_delta_treshold = 0.3
# Dumb value here to avoid taking velocity into account
midar_discard_velocity_treshold = 100

default_alias_timeout = 0.5
default_alias_icmp_probe_number = 20
default_number_mbt = 10


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

def send_alias_probes(g, vertices, ttl, destination):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]
    time_series_by_vertices = {}

    for v in vertices:
        time_series_by_vertices[v] = []

    # Has to check the ip_address to handle per packet LB, well, anw, it will be discarded
    # in the clean of the velocities
    for i in range(0, default_alias_icmp_probe_number):
        one_round_time_before = time.time()
        for v in vertices:
            flow_id = ttls_flow_ids[v][ttl][0]
            alias_udp_probe = build_probe(destination, ttl, flow_id)
            before = time.time()
            reply = sr1(alias_udp_probe, timeout=default_alias_timeout, verbose = False)
            after = time.time()
            if reply is None:
                continue
            ip_id = extract_ip_id(reply)
            reply_ip = extract_src_ip(reply)

            if ip_address[v] != reply_ip:
                #print "Flow changed during measurement! Or it is may be not a per-flow load-balancer..."
                update_graph(g, reply_ip, ttl, flow_id)
                other_v = find_vertex_by_ip(g, reply_ip)
                if not time_series_by_vertices.has_key(other_v):
                    time_series_by_vertices[other_v] = [[before, after, ip_id]]
                else:
                    time_series_by_vertices[other_v].append([before, after, ip_id])

                continue
            time_series_by_vertices[v].append([before, after, ip_id])
        if i == 0:
            print "First round took " + (str(time.time() - one_round_time_before)) + " seconds"
    return time_series_by_vertices

def send_velocity_probes_multi_thread(g, v, ttl, destination, shared_dict):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]
    time_series = []
    flow_id = ttls_flow_ids[v][ttl][0]
    alias_udp_probe = build_probe(destination, ttl, flow_id)
    is_per_flow_stable = True
    for i in range(0, default_alias_icmp_probe_number):
        before = time.time()
        reply = sr1(alias_udp_probe, timeout=default_alias_timeout)
        if reply is None:
            continue
        if extract_src_ip(reply) != ip_address[v]:
            is_per_flow_stable = False
            break
        after = time.time()
        ip_id = extract_ip_id(reply)
        time_series.append([before, after, ip_id])

    # Seems to not need a lock in python as they don't access the same key
    if is_per_flow_stable:
        shared_dict[v] = time_series
    else:
        shared_dict[v] = None

def compute_negative_delta(time_serie):
    for i in range(0, len(time_serie)-1):
        while time_serie[i][2] > time_serie[i+1][2]:
            time_serie[i+1][2] += 2**16
def compute_velocity(time_serie):
    # Do some checking to elapse "unusable" serie
    # Check if responsive treshold
    if len(time_serie) < midar_unusable_treshold * default_alias_icmp_probe_number:
        return None
    # Check if degenerate treshold
    ip_ids = [x[2] for x in time_serie]
    if len(set(ip_ids)) < midar_degenerate_treshold * len(time_serie):
        return None

    ip_ids_delta = [time_serie[i][2] - time_serie[i-1][2] for i in range(1, len(time_serie))]

    # Take "after" time
    time_deltas = [time_serie[i][1] - time_serie[i-1][1] for i in range(1, len(time_serie))]

    # Check if too much negative deltas
    negative_deltas = filter(lambda x : x <= 0, ip_ids_delta)

    if len(negative_deltas) > midar_negative_delta_treshold * len(time_serie):
        return None

    for i in range(0, len(time_serie)-1):
        while time_serie[i][2] > time_serie[i+1][2]:
            time_serie[i+1][2] += 2**16

    ip_ids_delta = [time_serie[i][2] - time_serie[i-1][2] for i in range(1, len(time_serie))]

    # Compute velocity
    return float(sum(ip_ids_delta))/sum(time_deltas)

def filter_candidates_by_velocity(velocities):
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
    if before1 < before2 and after2 < after1:
        return True
    return False

def monotonic_bound_test(time_serie1, time_serie2):
    # Merge the two time series into 1
    time_serie = list(time_serie1)

    # Insert the timeserie2 to the right places
    for i in range(0, len(time_serie2)):
        before2 = time_serie2[i][0]
        after2 = time_serie2[i][1]
        # Find the right place
        #last_overlapping_index = -1
        right_index = -1
        for j in range(0, len(time_serie)):
            before1 = time_serie[j][0]
            after1 = time_serie[j][1]
            # if is_overlapping(before1, after1, before2, after2):
            #     last_overlapping_index = j
            #     continue
            if j == 0:
                if after2 < before1:
                    right_index = 0
            if j == len(time_serie) - 1:
                if after1 < before2:
                    right_index = -2
                else:
                    right_index = j
                break
            # Between j and j+1
            if after1 <= before2 and after2 <= time_serie[j+1][0]:
                right_index = j + 1
                break
        if right_index == -2:
            time_serie.append(time_serie2[i])
        else:
            time_serie.insert(right_index, time_serie2[i])


        # if last_overlapping_index != -1:
        #     if time_serie2[i][2] < time_serie[last_overlapping_index][2]:
        #         time_serie.insert(last_overlapping_index, time_serie2[i])
        #     else:
        #         time_serie.insert(last_overlapping_index + 1, time_serie2[i])
        #     continue

    ip_id_serie = [x[2] for x in time_serie]
    sorted_ip_id_serie = sorted(ip_id_serie)

    for i in range(0, len(ip_id_serie)):
        if ip_id_serie[i] != sorted_ip_id_serie[i]:
            return False
    return True


def estimation_stage(g, vertices_by_ttl, ttl, destination):
    ip_address = g.vertex_properties["ip_address"]
    print "Applying estimation stage to " + str(len(vertices_by_ttl)) + " candidates... This can take few minutes"
    time_serie_by_v = send_alias_probes(g, vertices_by_ttl, ttl, destination)

    if False:
        threads = []
        for v in vertices_by_ttl:
            # Cut the vertices in batches of 5
            print ip_address[v]
            try:
                t = threading.Thread(target=send_alias_probes, args=(g, v, ttl, destination, time_serie_by_v,))
                threads.append(t)
                # send_velocity_probes(g, v, ttl, destination, time_serie_by_v)
            except Exception as e:
                print e
                print "Error: unable to start thread"

        for t in threads:
            t.start()
            # Handle concurrent access to sockets?
            time.sleep(0.1)
        for t in threads:
            t.join()
    velocities = []
    for v, time_serie in time_serie_by_v.iteritems():
        velocity = compute_velocity(time_serie)
        if velocity is not None:
            velocities.append((v, velocity))
    # Filter those which have too much different velocity
    # TODO This should be an option as it is an optimization
    alias_candidates = filter_candidates_by_velocity(velocities)


    elimination_stage_candidates = {}
    for v1, v2 in alias_candidates:
        # print "Estimation stage : Applying MBT to candidates " + ip_address[v1] + " and " + ip_address[v2]
        time_serie1 = time_serie_by_v[v1]
        time_serie2 = time_serie_by_v[v2]
        has_monotonicity_requirement = monotonic_bound_test(time_serie1, time_serie2)
        if has_monotonicity_requirement:
            print ip_address[v1] + " and " + ip_address[v2] + " passed the estimation stage!"
            min_alias = min(v1, v2)
            max_alias = max(v1, v2)
            if elimination_stage_candidates.has_key(min_alias):
                elimination_stage_candidates[min_alias].add(max_alias)
            else:
                elimination_stage_candidates[min_alias] = set()
                elimination_stage_candidates[min_alias].add(max_alias)
            update_alias(elimination_stage_candidates)

    return elimination_stage_candidates


def elimination_stage(g, elimination_stage_candidates, ttl, destination):
    ip_address = g.vertex_properties["ip_address"]
    elimination_to_remove = set()
    for elimination_candidate, set_candidates in elimination_stage_candidates.iteritems():
        candidates = list(set_candidates)
        candidates.sort()
        candidates.append(elimination_candidate)
        time_series_by_candidate = send_alias_probes(g, candidates, ttl, destination)
        for v, time_serie in time_series_by_candidate.iteritems():
            compute_negative_delta(time_serie)
            # For debug
            ip_ids = [x[2] for x in time_serie]
            sorted_ip_ids = sorted(ip_ids)
            for i in range(0, len(ip_ids)):
                if sorted_ip_ids[i] != ip_ids[i]:
                    print "Error of sorting during negative deltas"
        for k in range(0, default_number_mbt):
            for i in range(0, len(candidates)):
                time_serie1 = time_series_by_candidate[candidates[i]]
                for j in range(i + 1, len(candidates)):
                    time_serie2 = time_series_by_candidate[candidates[j]]
                    # print "Elimination stage : Applying MBT to candidates "\
                    #       + ip_address[candidates[i]] + \
                    #       " and " + ip_address[candidates[j]]
                    pass_mbt = monotonic_bound_test(time_serie1, time_serie2)
                    if not pass_mbt:
                        print ip_address[candidates[i]] + " and " + ip_address[candidates[j]] + " discarded from the elimination stage!"
                        if k > 5:
                            print time_serie1
                            print time_serie2
                        min_candidate = min(candidates[i], candidates[j])
                        max_candidate = max(candidates[i], candidates[j])
                        elimination_to_remove.add((min_candidate, max_candidate))

    for candidate1, candidate2 in elimination_to_remove:
        if elimination_stage_candidates.has_key(candidate1):
            elimination_stage_candidates[candidate1].discard(candidate2)
        elif elimination_stage_candidates.has_key(candidate2):
            elimination_stage_candidates[candidate2].discard(candidate1)
    for elimination_candidate, candidates in elimination_stage_candidates.iteritems():
        candidates.discard(elimination_candidate)
        for candidate in candidates :
            if candidate != elimination_candidate:
                print ip_address[elimination_candidate] + " and " + ip_address[candidate] + " passed the elimination stage!"

    return elimination_stage_candidates


def router_graph(aliases, g):
    vertices_to_be_removed = set()
    for v1, v1_aliases in aliases.iteritems():
        for v1_alias in v1_aliases:
            merge_vertices(g, v1, v1_alias)
            vertices_to_be_removed.add(v1_alias)
    for v in reversed(sorted(vertices_to_be_removed)):
        g.remove_vertex(v)
    return g