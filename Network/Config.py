from netifaces import AF_INET, AF_INET6
import netifaces as ni

ip_version = "IPv4"

def set_ip_version(new_ip_version):
    global ip_version
    ip_version = new_ip_version

def get_ip_version():
    return ip_version

default_interface = None
default_ip_address = None
default_ip_address_6 = None
# Find the first default interface with an IPv4 and an IPv6 address
interfaces = ni.interfaces()
for interface in interfaces:
    if interface.startswith("lo"):
        continue
    if ni.ifaddresses(interface).has_key(AF_INET):
        if ni.ifaddresses(interface)[AF_INET][0].has_key('addr'):
            default_interface = interface
            default_ip_address = ni.ifaddresses(default_interface)[AF_INET][0]['addr']
        if ni.ifaddresses(interface).has_key(AF_INET6):
            if ni.ifaddresses(interface)[AF_INET6][0].has_key('addr'):
                default_ip_address_6 = ni.ifaddresses(default_interface)[AF_INET6][0]['addr']
                break

print "default IP interface: " + default_interface
print 'default IPv4 address: ' + default_ip_address
print "default IPv6 address: " + default_ip_address_6

def set_interface(interface):
    global default_interface
    global default_ip_address
    global default_ip_address_6
    default_interface = interface
    if ni.ifaddresses(interface).has_key(AF_INET):
        default_ip_address = ni.ifaddresses(default_interface)[AF_INET][0]['addr']
    if ni.ifaddresses(interface).has_key(AF_INET6) and interface[AF_INET6][0].haskey('addr'):
        default_ip_address_6 = ni.ifaddresses(default_interface)[AF_INET6][0]['addr']
def get_interface():
    return default_interface

def set_ip_address(ip):
    global default_ip_address
    default_ip_address = ip

def set_ip_address6(ip):
    global default_ip_address_6
    default_ip_address_6 = ip