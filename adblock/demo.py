#!/usr/bin/env python3
"""
Demo script to simulate network traffic for testing the DNS sinkhole sniffer.
This script generates packets with random IP addresses to simulate real traffic.
"""

import socket
import struct
import random
import time
from scapy.all import IP, TCP, UDP, Raw, send, conf

# Disable verbose output from scapy
conf.verb = 0

def generate_random_ip():
    # Avoid private ranges and loopback
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Skip private IP ranges
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

def generate_known_ad_ips():
    """Generate IPs from known ad domains for testing"""
    ad_ips = []

    # Common ad server IPs (examples - these may change)
    known_domains = [
        "doubleclick.net",
        "googlesyndication.com",
        "facebook.com",
        "ads.yahoo.com",
    ]

    for domain in known_domains:
        try:
            ip = socket.gethostbyname(domain)
            ad_ips.append(ip)
        except:
            pass

    return ad_ips

def generate_http_packet(dst_ip, dst_port=80, src_port=None):
    if src_port is None:
        src_port = random.randint(49152, 65535)

    # Create IP packet
    packet = IP(dst=dst_ip)

    # Add TCP layer
    packet = packet / TCP(sport=src_port, dport=dst_port, flags="S")

    # Add payload
    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packet = packet / Raw(load=http_request)

    return packet

def generate_https_packet(dst_ip, dst_port=443, src_port=None):
    if src_port is None:
        src_port = random.randint(49152, 65535)

    # Create IP packet
    packet = IP(dst=dst_ip)

    # Add TCP layer (TLS handshake)
    packet = packet / TCP(sport=src_port, dport=dst_port, flags="S")

    # Add minimal TLS client hello payload
    tls_hello = b"\x16\x03\x01\x00\x00"  # Simplified TLS header
    packet = packet / Raw(load=tls_hello)

    return packet

def run_traffic_demo(duration=60, packet_rate=2.0):
    """
    Generate simulated network traffic

    Args:
        duration: How long to run (seconds)
        packet_rate: Packets per second
    """

    print("="*70)
    print("NETWORK TRAFFIC SIMULATOR")
    print("="*70)
    print(f"Duration: {duration}s")
    print(f"Packet rate: {packet_rate} packets/second")
    print("Generating packets with random IPs...")
    print("The sniffer will perform reverse DNS lookups via Cloudflare")
    print("="*70 + "\n")

    # Get some known ad server IPs
    known_ad_ips = generate_known_ad_ips()
    if known_ad_ips:
        print(f"Loaded {len(known_ad_ips)} known ad server IPs for testing\n")

    start_time = time.time()
    packet_count = 0
    delay = 1.0 / packet_rate

    try:
        while time.time() - start_time < duration:
            # 30% chance to use known ad IP, 70% random
            if known_ad_ips and random.random() < 0.3:
                dst_ip = random.choice(known_ad_ips)
                source = "known ad server"
            else:
                dst_ip = generate_random_ip()
                source = "random"

            # Random choice between HTTP and HTTPS
            if random.random() < 0.5:
                packet = generate_http_packet(dst_ip)
                protocol = "HTTP"
            else:
                packet = generate_https_packet(dst_ip)
                protocol = "HTTPS"

            packet_count += 1

            print(f"[Packet #{packet_count}] Sending {protocol} packet to {dst_ip} ({source})")

            try:
                send(packet, verbose=False)
                print(f"Sent successfully")
            except Exception as e:
                print(f"Error: {e}")

            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\nDemo stopped by user")

    elapsed = time.time() - start_time
    print("\n" + "="*70)
    print("TRAFFIC GENERATION SUMMARY")
    print("="*70)
    print(f"Duration: {elapsed:.1f}s")
    print(f"Packets sent: {packet_count}")
    print(f"Actual rate: {packet_count/elapsed:.2f} packets/second")
    print("="*70)

def run_quick_test():
    """Send a few test packets to verify setup"""

    print("="*70)
    print("QUICK PACKET TEST")
    print("="*70 + "\n")

    test_ips = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("142.250.80.14", "Google"),
    ]

    # Add known ad IPs
    ad_ips = generate_known_ad_ips()
    for ip in ad_ips[:3]:
        test_ips.append((ip, "Known ad server"))

    for dst_ip, description in test_ips:
        print(f"Sending packet to {dst_ip} ({description})")

        packet = generate_http_packet(dst_ip)

        try:
            send(packet, verbose=False)
            print(f"Sent successfully\n")
        except Exception as e:
            print(f"Error: {e}\n")

        time.sleep(1)

    print("="*70)

def run_burst_test(burst_size=10):
    """Send a burst of packets quickly"""

    print("="*70)
    print(f"BURST TEST - Sending {burst_size} packets")
    print("="*70 + "\n")

    for i in range(burst_size):
        dst_ip = generate_random_ip()
        packet = generate_http_packet(dst_ip)

        print(f"[{i+1}/{burst_size}] Sending to {dst_ip}")

        try:
            send(packet, verbose=False)
        except Exception as e:
            print(f"  Error: {e}")

        time.sleep(0.2)

    print("\n" + "="*70)
    print("Burst complete!")
    print("="*70)

def run_with_main():
    """Run the demo with the main DNS sinkhole server for interactive statistics"""
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
    import sys
    import os

    # Check if running as root (required for packet injection)
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (sudo)")
        print("Packet injection requires root privileges")
        sys.exit(1)

    # Parse command line arguments
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = "interactive"

    print("\n")

    if mode == "interactive" or mode == "main":
        print("Starting interactive mode with DNS sinkhole...")
        run_with_main()

    elif mode == "quick":
        print("Running quick test...")
        run_quick_test()

    elif mode == "burst":
        burst_size = 10
        if len(sys.argv) > 2:
            burst_size = int(sys.argv[2])
        print(f"Running burst test with {burst_size} packets...")
        run_burst_test(burst_size)

    elif mode == "demo":
        duration = 60
        rate = 2.0

        if len(sys.argv) > 2:
            duration = int(sys.argv[2])
        if len(sys.argv) > 3:
            rate = float(sys.argv[3])

        print("Running traffic demo...")
        print("Press Ctrl+C to stop\n")
        time.sleep(2)
        run_traffic_demo(duration, rate)

    else:
        print("Usage:")
        print("  sudo python3 demo.py                       - Interactive mode with stats (default)")
        print("  sudo python3 demo.py interactive           - Same as above")
        print("  sudo python3 demo.py quick                 - Send a few test packets")
        print("  sudo python3 demo.py burst [count]         - Send burst of packets")
        print("  sudo python3 demo.py demo [dur] [rate]     - Traffic generation only")
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