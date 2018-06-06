import requests
import time
import datetime
from graph_tool.all import *
from _pybgpstream import BGPStream, BGPRecord, BGPElem

from collections import defaultdict

def ripe_ip2as(g):
    ip_address = g.vertex_properties["ip_address"]
    ripe_asns = g.new_vertex_property("python::object")
    g.vertex_properties["ripe_asns"] = ripe_asns

    distinct_asns = set()

    # Get the IP to AS informations from two sources: https://stat.ripe.net/data/prefix-overview/ and https://bgpstream.caida.org/docs/tutorials/pybgpstream
    ripe_ip2as_url = "https://stat.ripe.net/data/prefix-overview/data.json?resource="

    for v in g.vertices():
        result = requests.get(ripe_ip2as_url+ ip_address[v])
        as_infos = result.json()["data"]
        if as_infos.has_key("asns"):
            asns = as_infos["asns"]
            ripe_asns[v] = asns
            if len(asns) > 0:
                for asn_infos in asns:
                    asn = asn_infos["asn"]
                    distinct_asns.add(asn)


    ripe_distinct_asns = g.new_graph_property("python::object")
    g.graph_properties["ripe_asns"] = ripe_distinct_asns
    ripe_distinct_asns[g] = list(distinct_asns)

def bgp_stream_ip_to_as(g, measurement_starting_time):
    ip_address = g.vertex_properties["ip_address"]
    bgp_stream_asns = g.new_vertex_property("python::object")
    g.vertex_properties["bgp_stream_asns"] = bgp_stream_asns



    # Create a new bgpstream instance and a reusable bgprecord instance
    stream = BGPStream()
    rec = BGPRecord()

    # Consider Route Views Singapore only
    #stream.add_filter('collector', 'route-views.sg')

    # Consider RIBs dumps only
    stream.add_filter('record-type', 'ribs')
    for v in g.vertices():
        stream.add_filter('prefix', ip_address[v]+"/24")
        print ip_address[v]
    # Consider this time interval:
    # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
    # Get the last hour record.
    now = datetime.datetime.now()
    bgp_last_record_date = datetime.datetime(now.year, now.month, now.day,16)
    stream.add_interval_filter(int(time.mktime(bgp_last_record_date.timetuple())), 0)

    # Start the stream
    stream.start()

    # <prefix, origin-ASns-set > dictionary
    prefix_origin = defaultdict(set)

    # Get next record
    while (stream.get_next_record(rec)):
        elem = rec.get_next_elem()
        while (elem):
            # Get the prefix
            pfx = elem.fields['prefix']
            # Get the list of ASes in the AS path
            ases = elem.fields['as-path'].split(" ")
            if len(ases) > 0:
                # Get the origin ASn (rightmost)
                origin = ases[-1]
                # Insert the origin ASn in the set of
                # origins for the prefix
                prefix_origin[pfx].add(origin)
            elem = rec.get_next_elem()

    # Print the list of MOAS prefix and their origin ASns
    for pfx in prefix_origin:
        if len(prefix_origin[pfx]) > 1:
            print pfx, ",".join(prefix_origin[pfx])


