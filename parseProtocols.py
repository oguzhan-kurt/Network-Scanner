import socket
from struct import unpack
from binascii import hexlify
from helper_methods import beauty_mac_address
from rich import print as rprint

class NetworkPacket(object):

    def main(self):
        while True:
            data = self.connect()
            src,dst,proto,otherData = self.ethernet_frame(data)
            opcode,dst_mac,dst_ip,src_mac,src_ip = self.arp_frame(otherData)
            if opcode == 2:
                self.print_packet(dst_mac=dst_mac,dst_ip=dst_ip)

    def connect(self):
        sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))
        data,junk = sock.recvfrom(65535)
        return data

    def ethernet_frame(self,data):
        raw_data = data[0:14]
        eth_raw_data = unpack("!6s6sH",raw_data)
        src_mac  = hexlify(eth_raw_data[0]).decode("unicode_escape")
        dst_mac  = hexlify(eth_raw_data[1]).decode("unicode_escape")
        protocol = hex(eth_raw_data[2])
        other_data = data[14:]
        return src_mac,dst_mac,protocol,other_data

    def arp_frame(self,data):
        raw_data = data[0:28]
        arp_raw_data = unpack("!HHBBH6s4s6s4s",raw_data)
        opcode = arp_raw_data[4]
        dst_mac = hexlify(arp_raw_data[5]).decode("unicode_escape")
        dst_ip = socket.inet_ntoa(arp_raw_data[6])
        src_mac= hexlify(arp_raw_data[7]).decode("unicode_escape")
        src_ip = socket.inet_ntoa(arp_raw_data[8])
        return opcode,dst_mac,dst_ip,src_mac,src_ip

    def print_packet(self,dst_mac,dst_ip):
        rprint(f"[red][+] MAC : {beauty_mac_address(dst_mac)}       ==> ", f"     [blue]IP : {dst_ip}")
    
    def send_packet(self,interface,raw_data):
        sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x806))
        sock.bind((interface,socket.htons(0x0806)))
        sock.send(raw_data)

if __name__ == "__main__":
    a = NetworkPacket()
    a.main()