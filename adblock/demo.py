"""
Demo script to test the DNS sinkhole functionality
"""
import os
import time
import socket
import threading
from dnslib import DNSRecord
from adblock import load_blocklist, DNSSinkholeServer





def test_dns_query(domain, dns_server='127.0.0.1', dns_port=5353):
    """
    Send a DNS query and print the result
    """
    try:
        query = DNSRecord.question(domain) # create DNS query

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(query.pack(), (dns_server, dns_port)) # send to server

        data, _ = sock.recvfrom(4096) #get response from google dns resolver
        response = DNSRecord.parse(data)
        sock.close()

        print(f"\nQuery: {domain}")
        if response.rr:
            for rr in response.rr:
                print(f"  Answer: {rr.rdata}")
        else:
            print("  No answer")

        return response
    except Exception as e:
        print(f"Error querying {domain}: {e}")
        return None


def main():
    print("\n- Loading blocklist")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    blocklist_path = os.path.join(os.path.dirname(script_dir), 'blocklist.txt')
    blocklist = load_blocklist(blocklist_path)
    print(f"{len(blocklist)} blocked domains")

    print("\n- Starting sinkhole server")
    sinkhole = DNSSinkholeServer(blocklist, host='127.0.0.1', port=5353)

    #start server in seperate thread
    thread = threading.Thread(target=sinkhole.start, daemon=True)
    thread.start()
    time.sleep(1)
    print("127.0.0.1:5353")

    print("\n- Blocked domains (return 0.0.0.0)")
    test_dns_query('ads.com')
    time.sleep(0.5)
    test_dns_query('tracker.com')
    time.sleep(0.5)
    test_dns_query('www.ads.com')

    print("\n- Legit domains")
    test_dns_query('google.com')
    time.sleep(0.5)
    test_dns_query('github.com')

    time.sleep(2)

    stats = sinkhole.get_stats()
    print(f"\nBlocked: {stats['blocked']}")
    print(f"Allowed: {stats['allowed']}")
    print(f"Total: {stats['total']}")

    sinkhole.stop()

if __name__ == "__main__":
    main()