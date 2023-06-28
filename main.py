from createProtocol import ARP, EthernetII
from parseProtocol import Parser
from optparse import OptionParser
from helper import subnet_creator, get_mac_address, get_ip_address
from rich.progress import track
from time import sleep

import socket
import netifaces
import threading

def get_user_parameters():
    parse_options = OptionParser()
    parse_options.add_option("-n", "--network", dest="sub_network", help="Enter Network Address \n[+] Example : 192.168.1.0/24")
    parse_options.add_option("-i", "--interface", dest="interface", help="Enter Your Interface")

    options, _ = parse_options.parse_args()

    interfaces = netifaces.interfaces()

    if not options.interface and not options.sub_network:
        print("\nPlease enter parameters. You can use '--help' for parameters.")

    if options.interface not in interfaces:
        print("\nThere is no such interface.")

    if not options.sub_network:
        print("\nEnter network address.")

    return options


def send_packet(interface, ip):
    ethernet = EthernetII(src_mac=get_mac_address(interface))
    arp = ARP(dst_mac="00:00:00:00:00:00", src_mac=get_mac_address(interface), src_ip=get_ip_address(interface))

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((interface, 0x0806))
    arp._dst_ip = ip
    packet = ethernet() + arp()
    sock.send(packet)


def receive_packet(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((interface, 0x0806))
    parser = Parser()

    while True:
        data, _ = sock.recvfrom(65535)
        _, _, _, otherData = parser.ethernetFrame(data)
        opcode, dst_mac, dst_ip, src_mac, src_ip = parser.arp_frame(otherData)
        if opcode == 2:
            parser.print_frame(dst_mac=dst_mac, dst_ip=dst_ip)


def main():
    user_params = get_user_parameters()
    user_network = user_params.sub_network
    user_interface = user_params.interface
    ip_list = subnet_creator(user_network)

    receive_thread = threading.Thread(target=receive_packet, args=(user_interface,), daemon=True)
    receive_thread.start()
    
    sleep(1.5)

    for ip in track(ip_list, "Sending Packet => "):
        send_packet(user_interface,ip)


if __name__ == "__main__":
    main()