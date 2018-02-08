from graph_tool.all import *
from Graph.LoadBalancer import *
def init_graph():
    g = Graph()
    ip_address = g.new_vertex_property("string")
    ttls_flow_ids = g.new_vertex_property("python::object")

    inferred = g.new_edge_property("bool", False)

    g.vertex_properties["ip_address"] = ip_address
    g.vertex_properties["ttls_flow_ids"] = ttls_flow_ids
    g.edge_properties["inferred"] = inferred
    source = g.add_vertex()
    ip_address[source] = "127.0.0.1"
    ttls_flow_ids[source] = {}
    ttls_flow_ids[source][0] = []
    for i in range (1, 5000):
        ttls_flow_ids[source][0].append(i)
    return g

def find_vertex_by_ttl(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    vertices_ttl = []
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                vertices_ttl.append(v)
    return vertices_ttl

def find_vertex_by_ttl_flow_id(g, ttl, flow_id):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl and flow_id in flow_ids:
                return v
    return None

def find_max_flow_id(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    max_flow_id = -1
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                for flow_id in flow_ids:
                    if flow_id > max_flow_id:
                        max_flow_id = flow_id
    return max_flow_id

def find_probes_sent(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    count = 0
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                count = count + len(flow_ids)
    return count

def update_neigbours(g, v, ttl, flow_id):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    if ttls_flow_ids[v].has_key(ttl):
        ttls_flow_ids[v][ttl].append(flow_id)
    else:
        ttls_flow_ids[v][ttl] = [flow_id]
    # Add the corresponding edges if there are to be added
    successor = find_vertex_by_ttl_flow_id(g, ttl+1, flow_id)
    if successor is not None:
        # Multiple edges are possible here
        g.add_edge(v, successor)
    predecessor = find_vertex_by_ttl_flow_id(g, ttl-1, flow_id)
    if predecessor is not None:
        g.add_edge(predecessor, v)

def init_vertex(g, v, ip, ttl, flow_id):
    ip_address = g.vertex_properties["ip_address"]
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]

    ip_address[v] = ip
    ttls_flow_ids[v] = {}

def add_new_vertex(g, ip, ttl, flow_id):
    v = g.add_vertex()
    # Initialize the vertex
    init_vertex(g, v, ip, ttl, flow_id)
    return v

def update_graph(g, ip, ttl, flow_id):
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

def dict_vertices_by_ttl(g):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    dict_vertices_by_ttl = {}
    for v in g.vertices():
        for ttl, flow_ids in ttls_flow_ids[v].iteritems():
            if ttl not in dict_vertices_by_ttl:
                dict_vertices_by_ttl[ttl] = [v]
            else:
                dict_vertices_by_ttl[ttl].append(v)

    return dict_vertices_by_ttl

def find_consecutive_sequence(s):
    ll = []
    l= []
    for i in range(0, len(s)):
        if i == 0 or s[i - 1] + 1 == s[i]:
            l.append(s[i])
        else:
            ll.append(list(l))
            l = []
            l.append(s[i])
    ll.append(l)
    return ll

def find_consecutive_ttls(ttls_vertices):
    ttls = []
    for ttl, vertices in ttls_vertices:
        ttls.append(ttl)
    sorted_ttls = sorted(ttls)
    return find_consecutive_sequence(sorted_ttls)


def extract_load_balancers(g):
    vertices_by_ttl = dict_vertices_by_ttl(g)
    ttls = filter(lambda (ttl, vertices): len(vertices) > 1, vertices_by_ttl.iteritems())
    load_balancers = []
    consecutive_ttls = find_consecutive_ttls(ttls)
    for l in consecutive_ttls:
        lb = {}
        for ttl in l :
            lb[ttl] = len(vertices_by_ttl[ttl])
        load_balancers.append(LoadBalancer(lb))
    return load_balancers


def apply_converging_heuristic(g, ttl):

    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]

    inferred = g.edge_properties["inferred"]
    lv_successor = find_vertex_by_ttl(g, ttl+1)
    if len(lv_successor) > 1 or len(lv_successor) == 0:
        raise Exception
    lv_predecessor = find_vertex_by_ttl(g, ttl - 1)
    if len(lv_predecessor) > 1 or len(lv_predecessor) == 0:
        raise Exception
    v_successor = lv_successor[0]
    v_successor_flow_ids = ttls_flow_ids[v_successor][ttl+1]

    v_predecessor = lv_predecessor[0]
    v_predecessor_flow_ids = ttls_flow_ids[v_predecessor][ttl - 1]
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                if len(set(flow_ids).intersection(v_successor_flow_ids)) == 0:
                    e = g.add_edge(v, v_successor)
                    inferred[e] = True
                if len(set(flow_ids).intersection(v_predecessor_flow_ids)) == 0:
                    e = g.add_edge(v_predecessor, v)
                    inferred[e] = True

def is_new_ip(g, ip):
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v] == ip:
            return False
    return True

if __name__ == "__main__":
    seq = [1, 2, 4, 5, 7, 8]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2], [4, 5], [7,8]]
    seq = [1, 2, 4, 5, 7, 9]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2], [4, 5], [7], [9]]
    seq = [1, 2, 4, 6, 7, 9]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2],[4], [6, 7], [9]]