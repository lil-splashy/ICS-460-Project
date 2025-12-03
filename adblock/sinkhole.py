#!/usr/bin/env python3
# DNS Sinkhole - blocks ads by returning 0.0.0.0
# Forwards legitimate DNS queries to upstream resolver at Google DNS (8.8.8.8)
import os
import sys
import time
import threading
from blocklist import load_blocklist
import socket
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from sniffer import sniff
from dnsreport import DNSReporter, print_banner


class AdBlockResolver(
    BaseResolver
):  # handle DNS requests - block ads and forward others upstream

    
    def __init__(self, blocklist):
        self.blocklist = blocklist
        self.upstream_dns = "8.8.8.8"
        self.blocked_count = 0
        self.allowed_count = 0
        # Cache to map IPs to domain names
        self.ip_to_domain = {}


    # Handle DNS request
    def resolve(self, request, handler):
        reply = request.reply()
        domain = str(request.q.qname).lower().rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # blocked domain
        if self.is_blocked(domain):
            self.blocked_count += 1
            print(f"[BLOCKED] {domain} ({qtype})")
            if request.q.qtype == QTYPE.A: # ipv4 - reroute to 0.0.0.0
                reply.add_answer(
                    RR(rname=request.q.qname, rtype=QTYPE.A, rdata=A("0.0.0.0"), ttl=60)
                )
            elif request.q.qtype == QTYPE.AAAA: #ipv6 doesn't need to reroute to 0.0.0.0. empty response works as a block
                pass
            return reply

        # not blocked
        self.allowed_count += 1
        print(f"[ALLOWED] {domain} ({qtype})")
        try:
            return self.forward_to_dns(request)
        except:
            return reply

    def is_blocked(self, domain):  # check if domain is in blocklist
        domain = domain.lower()

        if domain in self.blocklist:
            return True

        # also check parent domains
        parts = domain.split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocklist:
                return True

        return False
    

    def forward_to_dns(self, request):
        # forward to upstream DNS resolver (Google DNS)
        # Google DNS then contacts the authoritative servers for where the requested domain is
        # and returns the real IP address
        # this is what pi-hole and other dns resolvers do
        # https://docs.pi-hole.net/guides/dns/upstream-dns-providers/
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        try:
            sock.sendto(request.pack(), (self.upstream_dns, 53))
            data, _ = sock.recvfrom(
                4096
            )  # get response from upstream resolver (sender is ignored its google dns)
            response = DNSRecord.parse(data)
            return response
        finally:
            sock.close()


        # Lookup ip to match with domain
    def lookup_domain(self, ip):
        return self.ip_to_domain.get(str(ip), "Unknown")

    def get_stats(self):
        return {
            "blocked": self.blocked_count,
            "allowed": self.allowed_count,
            "total": self.blocked_count + self.allowed_count,
        }


class DNSSinkholeServer:

    def __init__(self, blocklist, host="127.0.0.1", port=5353):
        self.blocklist = blocklist
        self.host = host
        self.port = port
        self.resolver = AdBlockResolver(blocklist)
        self.server = None

    def start(self):
        self.server = DNSServer(self.resolver, port=self.port, address=self.host)
        self.server.start_thread()


    def start_sniffer(self):
        try:
            sniff(self.host)
        except Exception as e:
            print(f"Sniffer error: {e}")


    def stop(self):
        if self.server:
            self.server.stop()

    def get_stats(self):
        return self.resolver.get_stats()


if __name__ == "__main__":



   

    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        sys.exit(1)

    blocklist_path = os.path.join(os.path.dirname(__file__), "..", "blocklist.txt")
    blocklist_path = os.path.abspath(blocklist_path)

    try:
        blocklist = load_blocklist(blocklist_path)
        print(f"Loaded {len(blocklist)} blocked domains")
    except FileNotFoundError:
        print(f"Error: Blocklist file not found at {blocklist_path}")
        sys.exit(1)

    server = DNSSinkholeServer(blocklist, host="0.0.0.0", port=53)

    try:
        print("\n[Server] Starting DNS Sinkhole at 0.0.0.0:53")

        server.start()
        time.sleep(1)

        ''' Start report handler '''
        reporter = DNSReporter(server.resolver)
        print_banner()
        # sniffer_thread = threading.Thread(target=server.start_sniffer, daemon=True)
        # sniffer_thread.start()
        # time.sleep(0.5)

        print("Monitoring DNS Traffic through 18.116.242.142")
        # Command Loop
        while True:
            cmd = input("\n> ").strip().lower()
    
            if cmd == 'stats':
                reporter.print_summary()
            elif cmd == 'report':
                reporter.print_full_report()
            elif cmd == 'blocked':
                reporter.print_top_blocked()
            elif cmd == 'allowed':
                reporter.print_top_allowed()
            elif cmd == 'export':
                reporter.export_csv()
            elif cmd == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')
            elif cmd == 'exit':
                break

    except KeyboardInterrupt:
        server.stop()
        print("Server stopped.")