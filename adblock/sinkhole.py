#!/usr/bin/env python3
# DNS Sinkhole - blocks ads by returning 0.0.0.0
# Forwards legitimate DNS queries to upstream resolver at Cloudflare DNS (1.1.1.1)
import os
import sys
import time
import socket
import threading
from blocklist import load_blocklist, is_blocked, check_and_categorize
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from sniffer import NetworkSniffer
from dnsreport import DNSReporter, print_banner

class AdBlockResolver(BaseResolver):

    def __init__(self, blocklist, reporter=None, benign_path=None):
        self.blocklist = blocklist
        self.upstream_dns = "1.1.1.1"  # Cloudflare DNS
        self.blocked_count = 0
        self.allowed_count = 0
        self.ip_to_domain = {}
        self.reporter = reporter
        self.benign_path = benign_path or os.path.join(os.path.dirname(__file__), "..", "benign_domains.txt")  

    def resolve(self, request, handler):
        reply = request.reply()
        domain = str(request.q.qname).lower().rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # Check and categorize the domain
        category = check_and_categorize(domain, self.blocklist, self.benign_path)

        # blocked domain
        if category == "blocked":
            self.blocked_count += 1
            print(f"[BLOCKED] {domain} ({qtype})")

            if self.reporter:
                self.reporter.log_blocked(domain)

            if request.q.qtype == QTYPE.A:
                reply.add_answer(
                    RR(rname=request.q.qname, rtype=QTYPE.A, rdata=A("0.0.0.0"), ttl=60)
                )
            elif request.q.qtype == QTYPE.AAAA:
                pass
            return reply

        # not blocked - benign (automatically added to benign list)
        self.allowed_count += 1
        print(f"[ALLOWED] {domain} ({qtype}) - added to benign list")

        if self.reporter:
            self.reporter.log_allowed(domain)
        
        try:
            response = self.forward_to_dns(request)
            
            # Store IP to domain mapping for sniffer correlation
            if response and hasattr(response, 'rr'):
                for rr in response.rr:
                    if rr.rtype == QTYPE.A:
                        ip = str(rr.rdata)
                        self.ip_to_domain[ip] = domain
                        print(f"[MAPPING] {ip} -> {domain}")
            
            return response
        except Exception as e:
            print(f"[ERROR] Failed to forward DNS query: {e}")
            return reply

    def forward_to_dns(self, request):
        try:
            # Send DNS query to Cloudflare DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)

            # Send the request
            sock.sendto(request.pack(), (self.upstream_dns, 53))

            # Receive the response
            data, _ = sock.recvfrom(8192)
            sock.close()

            # Parse the DNS response
            response = DNSRecord.parse(data)
            return response

        except socket.timeout:
            print(f"[TIMEOUT] DNS query to {self.upstream_dns} timed out")
            return None
        except Exception as e:
            print(f"[ERROR] DNS forwarding failed: {e}")
            return None

    def is_blocked(self, domain):
        return is_blocked(domain, self.blocklist)

    def get_stats(self):
        return {
            "blocked": self.blocked_count,
            "allowed": self.allowed_count,
            "total": self.blocked_count + self.allowed_count,
        }

class DNSSinkholeServer:

    def __init__(self, blocklist, host="0.0.0.0", port=5353, reporter=None, benign_path=None):
        self.blocklist = blocklist
        self.host = host
        self.port = port
        self.resolver = AdBlockResolver(blocklist, reporter=reporter, benign_path=benign_path)
        self.server = None

    def start(self):
        self.server = DNSServer(self.resolver, port=self.port, address=self.host)
        self.server.start_thread()


    def stop(self):
        if self.server:
            self.server.stop()

    def get_stats(self):
        return self.resolver.get_stats()


