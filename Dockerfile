FROM ubuntu

MAINTAINER Paul Blischak <blischak.4@osu.edu>

# Get g++ for compiling, wget to download Boost, git to clone source code repo,
# and make to automate program compilation with Makefile provided
RUN apt-get update \
  && apt-get install -y git \
                        g++ \
                        make \
                        wget

# Download boost, untar, setup install with bootstrap and only do the Program Options library,
# and then install
RUN cd /home && wget http://downloads.sourceforge.net/project/boost/boost/1.60.0/boost_1_60_0.tar.gz \
  && tar xfz boost_1_60_0.tar.gz \
  && rm boost_1_60_0.tar.gz \
  && cd boost_1_60_0 \
  && ./bootstrap.sh --prefix=/usr/local --with-libraries=program_options \
  && ./b2 install \
  && cd /home \
  && rm -rf boost_1_60_0

# Clone git repository with dummy C++ program, use make to compile, install it, then remove the repo
RUN cd /home \
  && git clone https://github.com/pblischak/boost-docker-test.git \
  && cd /home/boost-docker-test \
  && make linux \
  && make install \
  && cd .. \
  && rm -rf boost-docker-test

RUN apt-get install -y libboost-all-dev

RUN apt-get install -y python2.7

RUN apt-get install -y python-pip python-dev build-essential
RUN apt-get install -y libgmp3-dev
RUN apt-get install -y libcgal-dev
RUN apt-get install -y libsparsehash-dev

RUN pip install scapy numpy scipy 
RUN wget https://downloads.skewed.de/graph-tool/graph-tool-2.27.tar.bz2 && \
tar xvf graph-tool-2.27.tar.bz2 && \
rm -rf graph-tool-2.27.tar.bz2 && \
cd graph-tool-2.27 && \
./configure --disable-cairo && make && make install 
RUN pip install requests netifaces
ARG CACHE_DATE=2016-01-01
RUN git clone https://gitlab.planet-lab.eu/cartography/multilevel-mda-lite.git
RUN python multilevel-mda-lite/setup.py install
