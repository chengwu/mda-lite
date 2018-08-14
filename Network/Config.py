from netifaces import AF_INET, AF_INET6
import netifaces as ni

ip_version = "IPv4"

def set_ip_version(new_ip_version):
    global ip_version
    ip_version = new_ip_version

def get_ip_version():
    return ip_version

default_interface = ni.interfaces()[1]
default_ip_address = ni.ifaddresses(default_interface)[AF_INET][0]['addr']
default_ip_address_6 = ni.ifaddresses(default_interface)[AF_INET6][0]['addr']

