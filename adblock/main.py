#!/usr/bin/env python3

"""
Main script to run the DNS Sinkhole server.
"""
if __name__ == "__main__":
    import os
    import sys
    import time
    from blocklist import load_blocklist
    from sniffer import NetworkSniffer
    from dnsreport import DNSReporter, print_banner
    from sinkhole import DNSSinkholeServer

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

    # Create server
    server = DNSSinkholeServer(blocklist, host="0.0.0.0", port=53)
    
    # Create sniffer
    sniffer = NetworkSniffer(host="0.0.0.0", resolver=server.resolver)
    
    # Create reporter
    reporter = DNSReporter(server.resolver)
    
    # Link reporter to resolver
    server.resolver.reporter = reporter

    try:
        print("\n[Server] Starting DNS Sinkhole at 0.0.0.0:53")
        server.start()
        time.sleep(1)

        sniffer.start()
        time.sleep(0.5)

        print_banner()
        print("Monitoring DNS Traffic through 18.116.242.142")
        
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        server.stop()
        print("Server stopped.")