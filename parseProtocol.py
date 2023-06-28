from binascii import hexlify
from struct import unpack
from socket import inet_ntoa
from helper import beauty_mac_address
from rich import print as rprint

class Parser:

    def ethernetFrame(self,data):
        rawData = unpack("!6s6sH",data[0:14])
        src_mac  = hexlify(rawData[0]).decode("unicode_escape")
        dst_mac  = hexlify(rawData[1]).decode("unicode_escape")
        protocol = hex(rawData[2])

        return src_mac,dst_mac,protocol,data[14:]

    def arp_frame(sefl,data):
        arp_raw_data = unpack("!HHBBH6s4s6s4s",data[0:28])
        opcode = arp_raw_data[4]
        dst_mac = hexlify(arp_raw_data[5]).decode("unicode_escape")
        dst_ip = inet_ntoa(arp_raw_data[6])
        src_mac= hexlify(arp_raw_data[7]).decode("unicode_escape")
        src_ip = inet_ntoa(arp_raw_data[8])
        return opcode,dst_mac,dst_ip,src_mac,src_ip

    def print_frame(self,dst_mac,dst_ip):
        rprint(f"[red][+] [purple] MAC : {beauty_mac_address(dst_mac)}       ==> ", f"     [blue]IP : {dst_ip}")



if __name__ == "__main__":
    pass
