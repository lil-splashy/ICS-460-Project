#!/usr/bin/env python3
# DNS Sinkhole - blocks ads by returning 0.0.0.0
# Forwards legitimate DNS queries to upstream resolver at Google DNS (8.8.8.8)
import os
import sys
import time
import threading
from blocklist import load_blocklist
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from sniffer import NetworkSniffer
from dnsreport import DNSReporter, print_banner

class AdBlockResolver(BaseResolver):
    
    def __init__(self, blocklist, reporter=None):
        self.blocklist = blocklist
        self.upstream_dns = "8.8.8.8"
        self.blocked_count = 0
        self.allowed_count = 0
        self.ip_to_domain = {}
        self.reporter = reporter  # ADD THIS LINE

    def resolve(self, request, handler):
        reply = request.reply()
        domain = str(request.q.qname).lower().rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # blocked domain
        if self.is_blocked(domain):
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

        # not blocked
        self.allowed_count += 1
        print(f"[ALLOWED] {domain} ({qtype})")
        
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
        except:
            return reply
        

    def get_stats(self):
        return {
            "blocked": self.blocked_count,
            "allowed": self.allowed_count,
            "total": self.blocked_count + self.allowed_count,
        }

class DNSSinkholeServer:

    def __init__(self, blocklist, host="127.0.0.1", port=5353, reporter=None):
        self.blocklist = blocklist
        self.host = host
        self.port = port
        self.resolver = AdBlockResolver(blocklist, reporter=reporter) 
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