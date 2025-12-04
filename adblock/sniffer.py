#!/usr/bin/env python3
import ipaddress
from datetime import datetime
import socket
import threading
from collections import defaultdict
import struct

class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack("<BBHHHBBH4s4s", self.packet[0:20])

        # Breaking down the header to identify traffic
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        # Type of Service
        self.tos = header[1]
        self.protocol = header[6]
        # Source IP address
        self.src = header[8]
        # Desination IP address
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        # protocol mapping
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol_name = self.protocol_map.get(self.protocol, f"Unknown({self.protocol})")

    def print_header(self):
        print(f"{self.src_addr} -> {self.dst_addr}\t")

    # Use this to get source IP address for reference check.
    def get_src_ip(self):
        return self.src_addr
    
    def get_dst_ip(self):
        return self.dst_addr
    
    def get_protocol(self):
        return self.protocol_name


class NetworkSniffer:
    def __init__ (self, host='0.0.0.0', resolver = None):
        self.host = host
        self.resolver = resolver
        self.running = False
        self.thread = None
        self.sockets = []

        # stats
        self.packet_count = defaultdict(int)
        self.ip_traffic = defaultdict(int)
        self.total_packets = 0



    def start(self):
        if self.running:
            print("Sniffer is already running")
            return
        # start sniffing w/ threads
        self.running = True
        self.thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.thread.start()
        print(f"Sniffer started on {self.host}")


    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.cleanup_sockets()
        print("Sniffer stopped")


    def setup_sockets(self):
        try:
            # TCP socket
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            tcp_socket.settimeout(0.1)
            self.sockets.append(('TCP', tcp_socket))
            
            # UDP socket (for DNS traffic)
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            udp_socket.settimeout(0.1)
            self.sockets.append(('UDP', udp_socket))
            
            # ICMP socket
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            icmp_socket.settimeout(0.1)
            self.sockets.append(('ICMP', icmp_socket))
            
            return True
            
        except PermissionError:
            print("Sniffer Error: Root privileges required for raw socket access")
            return False
        except Exception as e:
            print(f"Sniffer Socket error: {e}")
            return False
        

    def cleanup_sockets(self):
        for name, sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets = []
    
    # Main sniff loop
    def sniff_loop(self):
        if not self.setup_sockets():
            self.running = False
            return

        print(f"[Sniffer] Listening for packets...")
        
        try:
            while self.running:
                for name, sock in self.sockets:
                    try:
                        data, addr = sock.recvfrom(65565)
                        packet = Packet(data)
                        self.process_packet(packet)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        # Silently skip malformed packets
                        continue
                        
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup_sockets()

    def process_packet(self, packet):
        # Update statistics
        self.total_packets += 1
        self.packet_count[packet.get_protocol()] += 1
        self.ip_traffic[str(packet.get_src_ip())] += 1
        self.ip_traffic[str(packet.get_dst_ip())] += 1
        
        # can toggle line to see packets
        # packet.print_header()
        
        # If we have a resolver, try to match IPs to domains
        if self.resolver and hasattr(self.resolver, 'ip_to_domain'):
            src_domain = self.resolver.ip_to_domain.get(str(packet.get_src_ip()), None)
            dst_domain = self.resolver.ip_to_domain.get(str(packet.get_dst_ip()), None)
            
            if src_domain or dst_domain:
                timestamp = datetime.now().strftime("%H:%M:%S")
                if src_domain:
                    print(f"[{timestamp}] {packet.get_protocol():4} {src_domain} ({packet.get_src_ip()}) -> {packet.get_dst_ip()}")
                elif dst_domain:
                    print(f"[{timestamp}] {packet.get_protocol():4} {packet.get_src_ip()} -> {dst_domain} ({packet.get_dst_ip()})")

    def get_stats(self):
        return {
            'total_packets': self.total_packets,
            'by_protocol': dict(self.packet_count),
            'top_ips': sorted(self.ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        }

    def print_stats(self):
        """Print formatted statistics"""
        print("\n" + "="*60)
        print("SNIFFER STATISTICS")
        print("="*60)
        print(f"Total packets captured: {self.total_packets}")
        print("-"*60)
        print("Packets by protocol:")
        for protocol, count in self.packet_count.items():
            print(f"  {protocol:6} : {count:>8} packets")
        print("-"*60)
        print("Top 10 IPs by traffic:")
        for ip, count in self.get_stats()['top_ips']:
            # Try to resolve domain if available
            domain = ""
            if self.resolver and hasattr(self.resolver, 'ip_to_domain'):
                domain = self.resolver.ip_to_domain.get(ip, "")
            
            if domain:
                print(f"  {ip:15} ({domain[:30]:30}) : {count:>6} packets")
            else:
                print(f"  {ip:15} : {count:>6} packets")
        print("="*60 + "\n")







if __name__ == "__main__":
    import sys
    
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    
    # Check for root
    import os
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo)")
        sys.exit(1)
    


