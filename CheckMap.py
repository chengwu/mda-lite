from Graph.Visualization import *
from graph_tool.all import *

if __name__ == "__main__":
    g = load_graph("test2.xml")
    graph_topology_draw(g)