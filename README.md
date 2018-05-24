# Multilevel MDA-Lite Paris Traceroute (MMLPT)

Multilevel MDA-Lite Paris Traceroute is a portable (Linux, MacOS, Windows) traceroute-like tool capable of both giving IP and router level view.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

MMLPT is written in Python, and uses different libraries to work.

To craft, send and parse packets, it uses scapy:
```
sudo pip install scapy
```

To provide a rich graph view, and to compute the IP and router level graphs, MMLPT uses graph-tool, which is a boost C++ library with a python wrapper.   

Follow the instructions in the following link to install graph-tool. As the C++ Library makes an extensive use of metaprogramming and templates, it can take a while (up to 30 minutes on a recent laptop) to compile graph-tool: 

[Graph-tool](https://graph-tool.skewed.de)

### Installing

To install then, just tap:

```
sudo python setup.py install
```

## Running
To run a simple MDA-Lite traceroute at IP level, tap
```
sudo python MDALite.py destination
```
To run MDA-Lite traceroute at both IP and router level, tap:
```
sudo python MDALite.py -a destination
```
You can tap the following command for the different options

```
sudo python MDALite.py --help
```

Recall that on very large topologies, the measurement can take few minutes, up to 10-15 on very complex topologies.

<!--- ## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc
-->
