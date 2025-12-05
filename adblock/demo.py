#!/usr/bin/env python3
import os
import sys
import socket
import struct
import random
import time
from scapy.all import IP, TCP, Raw, conf
conf.verb = 0
'''
Functions to generate and send DNS queries and HTTP/HTTPS packets for demo purposes.
'''
def generate_random_ip():
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if ip.startswith("10."):
            continue
        if ip.startswith("192.168."):
            continue
        if ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31:
            continue
        if ip.startswith("127."):
            continue
        if ip.startswith("169.254."):
            continue

        return ip

# Send a DNS query to the sinkhole and parse its response
def send_dns_query(domain, dns_server, dns_port=53):
    try:
        from dnslib import DNSRecord
        q = DNSRecord.question(domain, qtype="A")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(q.pack(), (dns_server, dns_port))

        # Receive response
        try:
            response_data, _ = sock.recvfrom(512)
            sock.close()

            # Parse response to confirm it was received
            response = DNSRecord.parse(response_data)
            return True
        except socket.timeout:
            sock.close()
            print(f"  (Timeout - no response from DNS server)")
            return False

    except Exception as e:
        print(f"Error sending DNS query: {e}")
        return False

# generate random HTTP GET packet to send
def generate_http_packet(dst_ip, dst_port=80, src_port=None):
    if src_port is None:
        src_port = random.randint(49152, 65535)
    packet = IP(dst=dst_ip)
    packet = packet / TCP(sport=src_port, dport=dst_port, flags="S")
    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packet = packet / Raw(load=http_request)

    return packet
# https
def generate_https_packet(dst_ip, dst_port=443, src_port=None):
    if src_port is None:
        src_port = random.randint(49152, 65535)
    packet = IP(dst=dst_ip)
    packet = packet / TCP(sport=src_port, dport=dst_port, flags="S")
    tls_hello = b"\x16\x03\x01\x00\x00"  
    packet = packet / Raw(load=tls_hello)

    return packet

def run_traffic_demo(duration=60, packet_rate=2.0, dns_server="127.0.0.1", dns_port=53):
    print("="*70)
    print("DNS TRAFFIC SIMULATOR")
    print("="*70)
    print(f"Duration: {duration}s")
    print(f"Query rate: {packet_rate} queries/second")
    print(f"Target DNS: {dns_server}:{dns_port}")
    print("Generating DNS queries to test ad blocking...")
    print("="*70 + "\n")

    # Load domain lists
    import os
    from blocklist import load_blocklist, load_benign_list

    blocklist_path = os.path.join(os.path.dirname(__file__), "..", "blocklist.txt")
    blocklist_path = os.path.abspath(blocklist_path)

    benign_path = os.path.join(os.path.dirname(__file__), "..", "benign_domains.txt")
    benign_path = os.path.abspath(benign_path)

    # Load ad domains from blocklist
    try:
        blocklist = load_blocklist(blocklist_path)
        # Use a random sample from the blocklist
        ad_domains = random.sample(list(blocklist), min(100, len(blocklist)))
    except FileNotFoundError:
        print(f"Error: Blocklist not found at {blocklist_path}")
        return
    except ValueError:
        # If blocklist is empty
        ad_domains = []
    # Load benign domains
    benign_domains = list(load_benign_list(benign_path))
    if not benign_domains:
        # If no benign domains exist, use some common ones
        benign_domains = ["google.com", "github.com", "wikipedia.org", "reddit.com", "twitter.com"]

    print(f"Loaded {len(ad_domains)} ad domains and {len(benign_domains)} benign domains\n")

    start_time = time.time()
    query_count = 0
    delay = 1.0 / packet_rate

    try:
        while time.time() - start_time < duration:
            # 40% chance to query ad domain, 60% benign
            if random.random() < 0.4:
                domain = random.choice(ad_domains)
                domain_type = "ad"
            else:
                domain = random.choice(benign_domains)
                domain_type = "benign"

            query_count += 1

            print(f"[Query #{query_count}] Querying {domain} ({domain_type})")

            try:
                send_dns_query(domain, dns_server, dns_port)
                print(f"  → Query sent")
            except Exception as e:
                print(f"  → Error: {e}")

            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\nDemo stopped by user")

    elapsed = time.time() - start_time
    print("\n" + "="*70)
    print("TRAFFIC GENERATION SUMMARY")
    print("="*70)
    print(f"Duration: {elapsed:.1f}s")
    print(f"DNS queries sent: {query_count}")
    print(f"Actual rate: {query_count/elapsed:.2f} queries/second")
    print("="*70)


def run_with_main():
    # Run the demo with the main DNS sinkhole server
    import os
    import sys
    import threading
    from blocklist import load_blocklist
    from sniffer import NetworkSniffer
    from dnsreport import DNSReporter, print_banner
    from sinkhole import DNSSinkholeServer

    blocklist_path = os.path.join(os.path.dirname(__file__), "..", "blocklist.txt")
    blocklist_path = os.path.abspath(blocklist_path)

    try:
        blocklist = load_blocklist(blocklist_path)
        print(f"Loaded {len(blocklist)} blocked domains")
    except FileNotFoundError:
        print(f"Error: Blocklist file not found at {blocklist_path}")
        sys.exit(1)

    reporter = None
    server = DNSSinkholeServer(blocklist, host="0.0.0.0", port=53, reporter=None)
    reporter = DNSReporter(server.resolver)
    server.resolver.reporter = reporter
    sniffer = NetworkSniffer(host="0.0.0.0", resolver=server.resolver)

    try:
        print("\n[Server] Starting DNS Sinkhole at 0.0.0.0:53")
        server.start()
        time.sleep(1)

        sniffer.start()
        time.sleep(0.5)

        print_banner()
        print("Monitoring DNS Traffic")
        print("\nDemo mode: Traffic generation is available in background")
        print("Use 'generate' command to start traffic generation\n")

        # Traffic generation thread
        traffic_thread = None
        traffic_running = False

        while True:
            cmd = input("cmds: 'stats', 'report', 'blocked', 'allowed', 'export', 'generate', 'clear', or 'exit'\n> ").strip().lower()

            if cmd == "stats":
                reporter.print_summary()

            elif cmd == "report":
                reporter.print_full_report()

            elif cmd == "blocked":
                reporter.print_top_blocked()

            elif cmd == "allowed":
                reporter.print_top_allowed()

            elif cmd == "export":
                filename = input("Enter filename (default: dns_report.csv): ").strip()
                if not filename:
                    filename = "dns_report.csv"
                reporter.export_csv(filename)

            elif cmd == "generate":
                if traffic_running:
                    print("Traffic generation already running!")
                else:
                    duration_input = input("Duration in seconds (default: 60): ").strip()
                    rate_input = input("Packets per second (default: 2.0): ").strip()

                    duration_val = int(duration_input) if duration_input else 60
                    rate_val = float(rate_input) if rate_input else 2.0

                    print(f"Starting traffic generation: {duration_val}s at {rate_val} pkt/s")
                    traffic_running = True

                    def run_traffic():
                        nonlocal traffic_running
                        run_traffic_demo(duration_val, rate_val)
                        traffic_running = False
                        print("\n\nTraffic generation completed!")
                        print("Type a command to continue...\n")

                    traffic_thread = threading.Thread(target=run_traffic, daemon=True)
                    traffic_thread.start()

            elif cmd == "clear":
                os.system('clear' if os.name == 'posix' else 'cls')
                print_banner()

            elif cmd == "exit":
                print("Shutting down...")
                break

            else:
                print("Unknown command. Available: stats, report, blocked, allowed, export, generate, clear, exit")

    except KeyboardInterrupt:
        print("\n\nShutting down...")
    finally:
        sniffer.stop()
        server.stop()
        print("Server stopped.")


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (sudo)")
        print("Packet injection requires root privileges")
        sys.exit(1)

    print("\n")

    run_with_main()

    print("\nInteractive mode commands:")
    print("  stats      - Show summary statistics")
    print("  report     - Show full report")
    print("  blocked    - Show top blocked domains")
    print("  allowed    - Show top allowed domains")
    print("  export     - Export report to CSV")
    print("  generate   - Start traffic generation")
    print("  clear      - Clear screen")
    print("  exit       - Stop and exit")
    print("\nNote: This script requires root privileges for packet injection")