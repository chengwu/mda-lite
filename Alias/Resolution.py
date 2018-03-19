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


def reduce_candidates_to_test(g, ttl, non_responsive_ip_id_ips):

    alias_candidates = find_alias_candidates(g, ttl)

    # Remove blacklisted non responsive routers to ip ids
    vertices_to_remove_from_aliases = []
    for v1, v2 in alias_candidates:
        if v1 in non_responsive_ip_id_ips or v2 in non_responsive_ip_id_ips:
            vertices_to_remove_from_aliases.append((v1, v2))

    for v1, v2 in vertices_to_remove_from_aliases:
        alias_candidates.remove((v1, v2))

    # Apply transitivity rule :
    # if IP1 is alias with IP2 and IP2 alias with IP3, IP1 is alias with IP3
    reduced_alias_candidates = []

    for v1, v2 in alias_candidates:
        # Check if two pairs of alias contains the two aliases
        # that we will be able to deduce by transitivity
        deducable = set()
        for rv1, rv2 in reduced_alias_candidates:
            if rv1 == v1 or rv1 == v2:
                deducable.add(rv1)
            if rv2 == v1 or rv2 == v2:
                deducable.add(rv2)
            if len(deducable) == 2:
                break
        if len(deducable) != 2 :
            reduced_alias_candidates.append((v1,v2))

    return reduced_alias_candidates
