from graph_tool.all import *
from Operations import *
from Visualization import *


# This function gives the max probes needed to statistically reach nk's in case
# of asymmetry
# d is the diamond
def max_probes_needed_ttl(g, lb, hop, nks):
    probabilities_to_reach = {}
    for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
        # First is the ttl with 1 interface, so skip it
        vertices_ttl = find_vertex_by_ttl(g, ttl)
        if ttl == min(lb.get_ttl_vertices_number().keys()):
            start_diamond_v = find_vertex_by_ttl(g, ttl-1)[0]
            probabilities_to_reach[start_diamond_v] = 1
        for v in vertices_ttl:
            predecessors = find_predecessors_ttl(g, v, ttl)
            probabilities_succ_pred = {}
            probabilities_to_reach[v] = 0
            for pred in predecessors:
                probabilities_succ_pred[pred] = len(find_successors_ttl(g, pred, ttl-1))
                probabilities_to_reach[v] += probabilities_to_reach[pred] * 1.0/probabilities_succ_pred[pred]

    vertices_hop = find_vertex_by_ttl(g, hop-1)
    max_probes_needed = 0
    for v in vertices_hop:
        v_successors = find_successors_ttl(g, v, hop-1)
        probes_needed = int(1/probabilities_to_reach[v]) * nks[len(v_successors)+1]
        if max_probes_needed < probes_needed:
            max_probes_needed = probes_needed
    return max_probes_needed
