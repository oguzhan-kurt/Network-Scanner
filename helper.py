from ipaddress import IPv4Network
from re import findall,search,compile
from struct import pack
from subprocess import check_output
from fcntl import ioctl
from binascii import unhexlify,Error
import socket

def subnet_creator(ip_block):
    ip_list = [str(ip) for ip in IPv4Network(str(ip_block))]
    return ip_list[1:len(ip_list)-1]

def get_mac_address(interface):
    _ifconfig = check_output(["ifconfig",interface])
    _mac_regex = compile(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})')
    _mac_addr = findall(_mac_regex, str(_ifconfig))

    if _mac_addr:
        return _mac_addr[0].upper()
    else:
        _mac_regex_2 = search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(_ifconfig))
        return _mac_regex_2.group(0).upper()

def get_ip_address(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(ioctl(
        s.fileno(),
        0x8915,     #SIOCGIFADDR
        pack('256s',interface[:15].encode("utf-8"))
    )[20:24])

def mac_to_binary(mac_addr):
        #Mac Address to Binary for raw_data
        try:
            mac_addr = unhexlify(mac_addr.replace(':', ''))
            if len(mac_addr) != 6:
                print("\nBad Character!!")
                quit()
            
        except Error:
            print("\nBad Character!!")
            quit()

        except ValueError:
            print("\nBad Character!!")
            quit()
        
        return mac_addr

def beauty_mac_address(mac_addr):
    mac = [mac_addr[i:i + 2] for i in range(0, len(mac_addr), 2)]
    return ":".join(map(str, mac)).upper()


if __name__ == "__main__":
    pass