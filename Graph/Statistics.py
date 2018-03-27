from graph_tool.all import *

def get_percentage_of_inferred(g):
    inferred = g.edge_properties["inferred"]

    total_edges = len(g.get_edges())
    inferred_edges = 0.0
    for e in g.edges():
        if inferred[e] :
            inferred_edges = inferred_edges + 1

    return 100 * inferred_edges/total_edges