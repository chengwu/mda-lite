import paramiko
import sys
import time
import select
import rethinkdb as r
from rethinkdb.errors import RqlRuntimeError, RqlDriverError, RqlError, RqlTimeoutError
import os
import subprocess
import paramiko
from datetime import datetime
import logging
import json

localport = 28015

logging.basicConfig(level=logging.ERROR,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    filename="/var/log/router_survey.log", filemode="a")

logger = logging.getLogger(__name__)

if __name__ == '__main__':


    db_server = 'localhost'
    db_name   = "myops2"
    db_port   = localport
    c         = r.connect(db_server, db_port)

    sources = ["mars.planetlab.haw-hamburg.de",
                   "planet4.cs.huji.ac.il",
                   "ple2.cesnet.cz",
                   "puri.mimuw.edu.pl",
                   "stella.planetlab.ntua.gr",
                   "aladdin.planetlab.extranet.uni-passau.de",
                   "ple44.planet-lab.eu",
                   "planetlab13.net.in.tum.de",
                   "ple43.planet-lab.eu",
                   "ple1.cesnet.cz",
                   "planetlab-2.cs.ucy.ac.cy",
                   "ple41.planet-lab.eu",
                   "kulcha.mimuw.edu.pl",
                   "nuc1.planet-lab.eu",
                   "ple2.planet-lab.eu",
                   "vicky.planetlab.ntua.gr",
                   "onelab2.pl.sophia.inria.fr",
                   "ple2.hpca.ual.es",
                   "pl-node-1.technion.ac.il"]
    destinations = {}
    for source in sources:
        destinations[source] = []
        at_least_one_lb = r.db(db_name).table("diamond_survey2"). \
            filter(r.row["node"].eq(source)
                   .and_(r.row["nb_lb"].ge(1))).run(c)

        for path in at_least_one_lb:
            destination = path["parameters"]["dst"]
            if destination not in destinations[source]:
                destinations[source].append(destination)
    for source, destinations in destinations.iteritems():
        # hitlists directory must exist...
        with open("hitlists/" + source + "_hitlist", "a+") as f:
            for dst in destinations:
                f.write(dst + "\n")
