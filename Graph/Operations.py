from graph_tool.all import *

def init_graph():
    g = Graph()
    ip_address = g.new_vertex_property("string")
    flow_ids = g.new_vertex_property("vector<int>", [])
    ttls = g.new_vertex_property("vector<int>", [])

    g.vertex_properties["ip_address"] = ip_address
    g.vertex_properties["flow_ids"] = flow_ids
    g.vertex_properties["ttls"] = ttls

    source = g.add_vertex()
    ip_address[source] = "127.0.0.1"
    for i in range (1, 5000):
        flow_ids[source].append(i)
    ttls[source].append(1)
    return g


def find_vertex_by_ttl_flow_id(g, ttl, flow_id):
    flow_ids = g.vertex_properties["flow_ids"]
    ttls = g.vertex_properties["ttls"]
    for v in g.vertices():
        if ttl in ttls[v] and flow_id in flow_ids[v]:
            return v
    return None


def update_neigbours(g, v, ttl, flow_id):
    flow_ids = g.vertex_properties["flow_ids"]
    ttls = g.vertex_properties["ttls"]
    flow_ids[v].append(flow_id)
    if ttl not in ttls[v]:
        ttls[v].append(ttl)
    # Add the corresponding edges if there are to be added
    successor = find_vertex_by_ttl_flow_id(g, flow_id, ttl + 1)
    if successor is not None:
        # Multiple edges are possible here
        g.add_edge(v, successor)
    predecessor = find_vertex_by_ttl_flow_id(g, flow_id, ttl - 1)
    if predecessor is not None:
        g.add_edge(predecessor, v)

def init_vertex(g, v, ip, ttl, flow_id):
    ip_address = g.vertex_properties["ip_address"]
    flow_ids = g.vertex_properties["flow_ids"]
    ttls = g.vertex_properties["ttls"]

    ip_address[v] = ip
    flow_ids[v].append(flow_id)
    ttls[v].append(ttl)
def add_new_vertex(g, ip, ttl, flow_id):
    v = g.add_vertex()
    # Initialize the vertex
    init_vertex(g, v, ip, ttl, flow_id)
    return v

def update_graph(g, ip, flow_id, ttl):
    ip_address = g.vertex_properties["ip_address"]

    already_discovered = False
    for v in g.vertices():
        if ip_address[v] == ip:
            update_neigbours(g, v, ttl, flow_id)
            already_discovered = True
            break

    if not already_discovered:
        v = add_new_vertex(g, ip,  ttl, flow_id)
        update_neigbours(g, v, ttl, flow_id)

    return g