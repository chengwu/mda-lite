from graph_tool.all import *
red_color          = [0.5, 0, 0, 0.9]
blue_color         = [0, 0, 0.5, 0.9]
default_edge_color = [0.179, 0.203,0.210, 0.8]
def graph_topology_draw_with_inferred(g):
    inferred   = g.edge_properties["inferred"]
    color_edge = g.new_edge_property("vector<float>")
    for e in g.edges():
        if inferred[e]:
            color_edge[e] = blue_color
        else:
            color_edge[e] = default_edge_color
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               , edge_color=color_edge
               )

def graph_topology_draw(g):
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               )

def graph_router_topology_level_draw(g):
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)

    interfaces = g.vertex_properties["interfaces"]

    vertex_color = g.new_vertex_property("vector<float>")
    g.vertex_properties["vertex_color"] = vertex_color
    for v in g.vertices():
        if len(interfaces[v]) > 1:
            vertex_color[v] = blue_color
        else:
            vertex_color[v] = red_color
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               , vertex_fill_color = g.vertex_properties["vertex_color"]
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               )