from graph_tool.all import *
from Graph.Operations import *


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
