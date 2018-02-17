from graph_tool.all import *
from Graph.LoadBalancer import *

max_ttl = 30

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

def find_vertex_by_ip(g, ip):
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v] == ip:
            return v
    return None

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

def find_flows(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    flows_ids_ttl = []
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                flows_ids_ttl.extend(flow_ids)
    return flows_ids_ttl

# Find flows that are
def find_missing_flows(g, ttl, ttl2):
    flows_ids_ttl = sorted(find_flows(g, ttl))
    flows_ids_ttl2 = sorted(find_flows(g, ttl2))

    missing_flows = []
    for flow1 in flows_ids_ttl:
        if flow1 not in flows_ids_ttl2:
            missing_flows.append(flow1)
    return sorted(missing_flows)


def dump_flows(g):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    for i in range(1, 30):
        print sorted(find_flows(g, i))
    return
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

def dict_vertices_by_ttl_without_useless_stars(g):
    # Don't take stars into account except if it is the only interface seen at this hop
    ip_address    = g.vertex_properties["ip_address"]
    vertices_by_ttl = dict_vertices_by_ttl(g)
    for ttl, vertices in vertices_by_ttl.iteritems():
        wstar_vertices = filter(lambda v : not ip_address[v].startswith("* * *"), vertices)
        if len(wstar_vertices) != 0:
            vertices_by_ttl[ttl] = wstar_vertices
    return vertices_by_ttl

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
    vertices_by_ttl = dict_vertices_by_ttl_without_useless_stars(g)
    ttls = filter(lambda (ttl, vertices): len(vertices) > 1, vertices_by_ttl.iteritems())
    load_balancers = []
    consecutive_ttls = find_consecutive_ttls(ttls)
    for l in consecutive_ttls:
        lb = {}
        for ttl in l :
            lb[ttl] = len(vertices_by_ttl[ttl])
        load_balancers.append(LoadBalancer(lb))
    return load_balancers

def find_no_predecessor_vertices(g, ttl):
    result = []
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    for v in vertices_ttl:
        if v.in_degree() == 0:
            result.append(v)
    return result

def find_no_successor_vertices(g, ttl):
    result = []
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    for v in vertices_ttl:
        if v.out_degree() == 0:
            result.append(v)
    return result

def apply_multiple_predecessors_heuristic(g, ttl):
    # Find if the the interfaces at ttl have common predecessors

    interfaces = find_vertex_by_ttl(g, ttl)
    max_in_neighbor = 0
    for interface in interfaces:
        distinct_neighbors = set(interface.in_neighbors())
        if len(distinct_neighbors) > max_in_neighbor:
            max_in_neighbor = len(distinct_neighbors)
    return max_in_neighbor > 1

def apply_multiple_successors_heuristic(g, ttl):
    # Find if the the interfaces at ttl have common predecessors

    interfaces = find_vertex_by_ttl(g, ttl)
    max_out_neighbor = 0
    for interface in interfaces:
        distinct_neighbors = set(interface.out_neighbors())
        if len(distinct_neighbors) > max_out_neighbor:
            max_out_neighbor = len(distinct_neighbors)
    return max_out_neighbor > 1

def apply_converging_heuristic(g, ttl, forward, backward):
    # This heuristic just infer divergence and then reconvergence
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]

    inferred = g.edge_properties["inferred"]
    lv_successor = find_vertex_by_ttl(g, ttl+1)

    lv_predecessor = find_vertex_by_ttl(g, ttl - 1)
    v_successor = lv_successor[0]
    v_successor_flow_ids = ttls_flow_ids[v_successor][ttl+1]

    v_predecessor = lv_predecessor[0]
    v_predecessor_flow_ids = ttls_flow_ids[v_predecessor][ttl - 1]
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].iteritems():
            if hop == ttl:
                if forward:
                    if len(set(flow_ids).intersection(v_successor_flow_ids)) == 0:
                        e = g.add_edge(v, v_successor)
                        inferred[e] = True
                if backward:
                    if len(set(flow_ids).intersection(v_predecessor_flow_ids)) == 0:
                        e = g.add_edge(v_predecessor, v)
                        inferred[e] = True

# max_diff_degree_arg represents the level of inference that we want to put
def apply_symmetry_heuristic(g, ttl, max_diff_degree_arg):
    inferred = g.edge_properties["inferred"]
    vertices_ttl = find_vertex_by_ttl(g, ttl)

    neighbors_by_vertices = {}
    for v in vertices_ttl:
        neighbors_by_vertices[v] = list(v.out_neighbors())
    # If a node has more than strength neigbors in common, infer links
    for v1, out_neighbors1 in neighbors_by_vertices.iteritems():
        for v2, out_neighbors2 in neighbors_by_vertices.iteritems():
            if v1 == v2:
                continue
            difference = set(out_neighbors1).difference(out_neighbors2)
            if len(difference) < max_diff_degree_arg and len(out_neighbors1) > 3:
                # Add the inferences
                for d in difference:
                    e = g.add_edge(v2, d)
                    inferred[e] = True

def is_a_divergent_ttl(g, ttl):
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    vertices_ttl_pred = find_vertex_by_ttl(g, ttl -1)
    return len(vertices_ttl) >= len(vertices_ttl_pred)

def is_new_ip(g, ip):
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v] == ip:
            return False
    return True

def has_discovered_edge(g, ip, ttl, flow_id):
    v = find_vertex_by_ip(g, ip)
    if v is None :
        return True
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    potential_predecessors = find_vertex_by_ttl(g, ttl - 1)
    for p in potential_predecessors:
        for hop, flow_ids in ttls_flow_ids[p].iteritems():
            if hop == ttl - 1 and flow_id in flow_ids:
                if v not in p.out_neighbors():
                    return True
    return False

def clean_stars(g):
    ip_address = g.vertex_properties["ip_address"]
    display = g.new_vertex_property("bool", True)
    g.vertex_properties["display"] = display
    for ttl in range(1, max_ttl+1):
        vertices = find_vertex_by_ttl(g, ttl)
        has_only_star = True
        filter = []
        for v in vertices:
            if not ip_address[v].startswith("* * *"):
                has_only_star = False
            else:
                filter.append(v)
        # Do not display these stars
        if not has_only_star:
            for v in filter:
                display[v] = False


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