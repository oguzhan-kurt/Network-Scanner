import netifaces
from time import sleep
from createProtocols import ARP,Ether
from helper_methods import get_mac_address,subnet_creator,get_ip_address
from parseProtocols import NetworkPacket
from optparse import OptionParser
from threading import Thread
from rich.progress import track

ethernet = Ether()
arp = ARP()
send_and_listen = NetworkPacket()

def get_user_parameter():
    parse_options = OptionParser()
    parse_options.add_option("-n","--network"  ,dest="sub_network",help="Enter Network Address \n[+] Example : 192.168.1.0/24")
    parse_options.add_option("-i","--interface",dest="interface",help="Enter Your Interface")

    options = parse_options.parse_args()[0]

    interfaces = netifaces.interfaces()
    
    if not options.interface and not options.sub_network:
        print("\nPlease Enter Parameters. You can '--help' parameters!")

    if options.interface not in interfaces:
        print("\nThere is no such your iterface")

    if not options.sub_network:
        print("\nEnter Network Address")
   
    return options


user_params = get_user_parameter()
user_network = user_params.sub_network
user_interface = user_params.interface


#Create Subnet
ip_list = subnet_creator(user_network)

def eth_packet(interface):
    ethernet.src_mac_addr = get_mac_address(interface)
    raw_data = ethernet.eth_packet()
    return raw_data


def arp_packet(interface,dst_ip):
    arp.dst_mac_addr = "00:00:00:00:00:00"
    arp.src_mac_addr = get_mac_address(interface)
    arp.src_ip       = get_ip_address(interface)
    arp.dst_ip       = dst_ip
    raw_data         = arp.arp_packet()
    return raw_data

def send_packet():
    for ip in track(ip_list," ==> Sending data..."):
        raw_packet = eth_packet(user_interface) + arp_packet(interface=user_interface,dst_ip=ip)
        send_and_listen.send_packet(user_interface,raw_packet)
    print("Done!")

def listen_packet():
    send_and_listen.main()


t1 = Thread(target=listen_packet,daemon=True)
t2 = Thread(target=send_packet)


print("\nResults  ==>> ")
print("---------------")
print("\n")

t1.start()

sleep(0.5)
t2.start()
