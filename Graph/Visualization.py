from graph_tool.all import *

def graph_topology_draw(g):
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               )