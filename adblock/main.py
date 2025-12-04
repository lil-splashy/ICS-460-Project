#!/usr/bin/env python3
"""
Main / Demo file for presenting the netowrk Ad-blocker
"""

import os
import sys
import time
import threading
import argparse

from dns_sinkhole import DNSSinkholeServer
from blocklist import load_blocklist
from sniffer import NetworkSniffer
from dnsreport import DNSReporter, print_banner


class DemoRunner:
    """Runs automated demo queries to test the DNS sinkhole"""
    
    def __init__(self, dns_server="127.0.0.1", dns_port=53):
        self.dns_server = dns_server
        self.dns_port = dns_port
        
    def send_test_queries(self):
        """Send test DNS queries to demonstrate the sinkhole"""
        import socket
        from dnslib import DNSRecord, QTYPE
        
        print("\n" + "="*60)
        print("RUNNING DEMO QUERIES")
        print("="*60)
        
        # Test domains
        test_domains = [
            ("google.com", "legitimate site"),
            ("doubleclick.net", "ad network - should be blocked"),
            ("github.com", "legitimate site"),
            ("googlesyndication.com", "ad network - should be blocked"),
            ("python.org", "legitimate site"),
            ("analytics.google.com", "tracking - should be blocked"),
            ("stackoverflow.com", "legitimate site"),
            ("pagead2.googlesyndication.com", "ads - should be blocked"),
        ]
        
        for domain, description in test_domains:
            print(f"\nTesting: {domain}")
            print(f"Description: {description}")
            
            try:
                # Create DNS query
                query = DNSRecord.question(domain)
                
                # Send to local DNS server
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(query.pack(), (self.dns_server, self.dns_port))
                
                # Get response
                data, _ = sock.recvfrom(4096)
                response = DNSRecord.parse(data)
                sock.close()
                
                # Check result
                if response.rr:
                    ip = str(response.rr[0].rdata)
                    if ip == "0.0.0.0":
                        print("Result: BLOCKED (0.0.0.0)")
                    else:
                        print("Result: ALLOWED ({ip})")
                else:
                    print("Result: No answer")
                    
            except socket.timeout:
                print(f"   Result: Timeout")
            except Exception as e:
                print(f"Error: {e}")
            
            time.sleep(0.5)
        
        print("\n" + "="*60)
        print("Demo queries completed!")
        print("="*60 + "\n")


