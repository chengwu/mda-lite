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
    # the dictionnary by removing keys
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