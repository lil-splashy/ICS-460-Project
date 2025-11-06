#!/usr/bin/env python3


import ipaddress
import socket
import sys
import argparse


parser = argparse.ArgumentParser(description="Packet Sniffer")
parser.add_argument("--ip", help="IP address to sniff on", required=True)
opts = parser.parse_args()


class Packet:
    def __init__(self, data):
        self.packet = data

        header = struct.unpack("<BBHHHBBH4s4s", self.packet[0:20])

        # Breaking down the header to identify traffic
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        # Type of Service
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.off = header[5]
        # Protocol
        self.pro = header[6]
        # Checksum
        self.num = header[7]
        # Source IP address
        self.src = header[8]
        # Desination IP address
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)
        # Mapping to ICMP
        self.protocol_map = {1: "ICMP"}

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f"{e} No protocol for {self.pro}")
            self.protocol = str(self.pro)


def sniff(host):

    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    # Not bindint to any port to catch all traffic
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_ICMP, socket.IP_HDRINCL, 1)


if __name__ == "__main__":
    # Command line argument for designating IP
    sniff(opts.ip)
