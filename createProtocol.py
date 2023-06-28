from struct import pack, error
from helper import mac_to_binary
from socket import inet_aton


class EthernetII:

    #Protocol Types
    __ETH_P_IP       = "0x800"     # Internet Protocol Protocol (IPv4)
    __ETH_P_IPv6     = "0x86DD"    # Internet Protocol Protocol (IPv6)
    __ETH_P_ARP      = "0x806"     # Address Resolution Protocol
    __ETH_P_SNMP     = "0x814C"    # Simple Network Message Protocol
    __ETH_P_RARP     = "0x8035"    # Reverse Address Resolution Protocol
    __ETH_P_802q     = "0x8100"    # VLAN Tagged Frame

    #initialize class
    def __init__(self,src_mac="00:00:00:00:00:00",dst_mac="FF:FF:FF:FF:FF:FF",protocol=__ETH_P_ARP):
        self._src_mac = src_mac
        self._dst_mac = dst_mac
        self._protocol = protocol
        self.__call__()


    def __call__(self):
        try:
            raw_data = pack("!6s6sH",mac_to_binary(self._dst_mac),mac_to_binary(self._src_mac),int(self._protocol,0))
        except error:
            print("\nBad Character!!")
            quit()
        
        return raw_data

    @property
    def show_properties(self):
        print(f"""
EthernetII Header\n-------------------------\n
Source Mac => {self._src_mac}\n
Dest   Mac => {self._dst_mac}\n
Protocol   => {self._protocol}\n
""")





class ARP():
    _hardware_type = 1
    _protocol_type = 0x0800
    _hardware_size = 6
    _protocol_size = 4
    _opcode = 1

    def __init__(self, 
                src_ip="0.0.0.0", 
                dst_ip="0.0.0.0",
                src_mac   ="00:00:00:00:00:00",
                dst_mac   ="00:00:00:00:00:00", 
                hrdwr_type=None,
                prtcl_type=None,
                hrdwr_size=None,
                prtcl_size=None,
                opcode    =None):
        self._src_ip     = src_ip
        self._dst_ip     = dst_ip
        self._src_mac    = src_mac
        self._dst_mac    = dst_mac
        self._hrdw_type  = hrdwr_type if hrdwr_type is not None else ARP._hardware_type
        self._prtcl_type = prtcl_type if prtcl_type is not None else ARP._protocol_type
        self._hrdwr_size = hrdwr_size if hrdwr_size is not None else ARP._hardware_size
        self._prtcl_size = prtcl_size if prtcl_size is not None else ARP._protocol_size
        self._opcode     = opcode if opcode is not None else ARP._opcode
        self.__call__()


    def __call__(self):
        raw_data = pack("!HHBBH6s4s6s4s",
                        self._hrdw_type,
                        self._prtcl_type,
                        self._hrdwr_size,
                        self._prtcl_size,
                        self._opcode,
                        mac_to_binary(self._src_mac),
                        inet_aton(self._src_ip),
                        mac_to_binary(self._dst_mac),
                        inet_aton(self._dst_ip))
        return raw_data


    #packet properties
    @property
    def show_properties(self):
        print(f"""
\n----ARP Header----\n

HRDWR TYPE : {self._hrdw_type}\n
PRTCL TYPE : {self._prtcl_type}\n
HRDWR SIZE : {self._hrdwr_size}\n
PRTCL SIZE : {self._prtcl_size}\n
SRC MAC    : {self._src_mac}\n
SRC IP     : {self._src_ip}\n
DST MAC    : {self._dst_mac}\n
DST IP     : {self._dst_ip}\n
OPCODE     : {self._opcode}
""")





if __name__ == "__main__":
    pass