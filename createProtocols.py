from struct import pack,error
from socket import inet_aton
from helper_methods import mac_to_binary

class Ether:

    #Protocol Types
    
    ETH_P_IP       = "0x800"     # Internet Protocol Protocol (IPv4)
    ETH_P_IPv6     = "0x86DD"    # Internet Protocol Protocol (IPv6)
    ETH_P_ARP      = "0x806"     # Address Resolution Protocol
    ETH_P_SNMP     = "0x814C"    # Simple Network Message Protocol
    ETH_P_RARP     = "0x8035"    # Reverse Address Resolution Protocol
    ETH_P_802q     = "0x8100"    # VLAN Tagged Frame 

    
    def __init__(self,src_mac="00:00:00:00:00:00",dst_mac="FF:FF:FF:FF:FF:FF",protocol="0x806"):
        self._src_mac = src_mac
        self._dst_mac = dst_mac
        self._protocol = protocol
        self.eth_packet()
        
    
    ## SHOW PROPERTIES
    @property
    def packet_details(self):
        print(f"""\nSRC MAC           : {self._src_mac}\nDST MAC           : {self._dst_mac}\n\nPROTOCOL          : {self._protocol}""")

    @property
    def show_raw_data(self):
        try:
            print(self.eth_packet())
        except UnboundLocalError:
            print("\nBad Character!!")

    ## SOURCE MAC ADDRESS
    @property
    def src_mac_addr(self):
        return self._src_mac

    @src_mac_addr.setter
    def src_mac_addr(self,new_mac_addr):
        self._src_mac = new_mac_addr
        
        

    ## DESTINATION MAC ADDRESS
    @property
    def dst_mac_addr(self):
        return self._dst_mac

    @dst_mac_addr.setter
    def dst_mac_addr(self,new_mac_addr):
        self._dst_mac = new_mac_addr
        

    ## PROTOCOL TYPES
    @property
    def protocol_type(self):
        return self._protocol

    @protocol_type.setter
    def protocol_type(self,protocols):
        self._protocol = protocols

    #Ethernet        : 14 Bytes
    #--------------------------
    #Source MAC      : 6 Bytes              
    #Destination MAC : 6 Bytes
    #Protocol Type   : 2 Bytes 

    def eth_packet(self):
        try:
            raw_data = pack("!6s6sH",mac_to_binary(self._dst_mac),mac_to_binary(self._src_mac),int(self._protocol,0))
        except error:
            print("\nBad Character!!")
            quit()
        
        return raw_data


class ARP(Ether):
    _hardware_type = 1
    _protocol_type = 0x0800
    _hardware_size = 6 
    _protocol_size = 4
    _opcode = 1
    
    #CREATE INSTANCE
    def __init__(self,*args,src_ip="0.0.0.0",dst_ip="0.0.0.0",
    hrdwr_type = _hardware_type,
    prtcl_type = _protocol_type,
    hrdwr_size = _hardware_size,
    prtcl_size = _protocol_size,
    opcode = _opcode):

        super().__init__(*args)
        self._src_ip = src_ip      
        self._dst_ip = dst_ip   
        self._hrdw_type  = hrdwr_type 
        self._prtcl_type = prtcl_type 
        self._hrdwr_size = hrdwr_size 
        self._prtcl_size = prtcl_size
        self._opcode = opcode
        self.arp_packet()
        

    #SHOW PACKET DETAILS
    @property
    def packet_details(self):
        super().packet_details
        print(f"\nHRDWR TYPE        : {self._hrdw_type}\nPRTCL TYPE        : {self._prtcl_type}")
        print(f"\nHRDWR SIZE        : {self._hrdwr_size}\nPRTCL SIZE        : {self._prtcl_size}")
        print(f"\nSRC IP            : {self._src_ip}   \nDST IP            : {self._dst_ip}\n\nOPCODE            : {self._opcode}")

    #SHOW RAW DATA
    @property
    def show_raw_data(self):
        print(self.arp_packet())

    #SOURCE IP
    @property
    def src_ip(self):
        return self._src_ip
    
    @src_ip.setter
    def src_ip(self,ip_addr):
        self._src_ip = ip_addr

    #DESTINATION IP
    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self,ip_addr):
        self._dst_ip = ip_addr


    #OPCODE
    @property
    def opcode(self):
        return self._opcode

    @opcode.setter
    def opcode(self,value):
        self._opcode = value


    #HARDWARE TYPE
    @property
    def hardware_type(self):
        return self._hrdw_type
    
    @hardware_type.setter
    def hardware_type(self,value):
        self._hrdw_type = value
    
    #HARDARE SIZE
    @property
    def hardware_size(self):
        return self._hrdwr_size

    @hardware_size.setter
    def hardware_size(self,value):
        self._hrdwr_size = value

    #PROTOCOL TYPE
    @property
    def protocol_type(self):
        return super().protocol_type #!Ether Inherit
        
    #PROTOCOL SIZE
    @property
    def protocol_size(self):
        return self._prtcl_size

    @protocol_size.setter
    def protocol_size(self,value):
        self._prtcl_size = value



    #ARP HEADER           : 28 Bytes
    #---------------------------------------
    #HARDWARE TYPE        : 2 Bytes
    #PROTOCOL TYPE        : 2 Byte
    #HARDWARE SIZE        : 1 Byte
    #PROTOCOL SIZE        : 1 Byte
    #OPCODE               : 2 Bytes
    #SOURCE MAC           : 6 Bytes
    #SOURCE IP            : 4 Bytes
    #DESTINATION MAC      : 6 Bytes
    #DESTINATION IP       : 4 Bytes

    def arp_packet(self):
        hrdwr_type = self._hrdw_type
        prtcl_type = self._prtcl_type 
        hrdwr_size = self._hrdwr_size
        prtcl_size = self._prtcl_size
        opcode     = self._opcode   
        src_mac    = mac_to_binary(self._src_mac) 
        src_ip     = inet_aton(self._src_ip)
        dst_mac    = mac_to_binary(self._dst_mac)
        dst_ip     = inet_aton(self._dst_ip)



        raw_data = pack("!HHBBH6s4s6s4s",hrdwr_type,prtcl_type,hrdwr_size,prtcl_size,opcode,src_mac,src_ip,dst_mac,dst_ip)
        return raw_data


if __name__ == "__main__":
    pass
