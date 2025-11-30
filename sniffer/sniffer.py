#!/usr/bin/env python3
import ipaddress
import socket
import struct

## Currently runs via command line, I would like to switch it to have it run via the main program.


class Packet:
    def __init__(self, data):
        self.packet = data

        header = struct.unpack("<BBHHHBBH4s4s", self.packet[0:20])

        # Breaking down the header to identify traffic
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        # Type of Service
        self.tos = header[1]
        # Source IP address
        self.src = header[8]
        # Desination IP address
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        # protocol mapping
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def print_header(self):
        print(f"{self.src_addr} -> {self.dst_addr}\t")

    # Use this to get source IP address for reference check.
    def get_src_ip(self):
        return self.src_addr


def sniff(host):


    sockets = []

    try:
        # TCP socket
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        tcp_socket.bind((host, 0))
        tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sockets.append(tcp_socket)
        
        # UDP socket (for DNS traffic)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        udp_socket.bind((host, 0))
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sockets.append(udp_socket)
        
        # ICMP socket
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.bind((host, 0))
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sockets.append(icmp_socket)
        
    except PermissionError:
        print("Error: Root privileges required for raw socket access")
        return
    except Exception as e:
        print(f"Socket error: {e}")
        return
    
                    
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    finally:
        # Clean up sockets
        for sock in sockets:
            sock.close()




