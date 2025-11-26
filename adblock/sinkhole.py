# DNS Sinkhole - blocks ads by returning 0.0.0.0
# Forwards legitimate DNS queries to upstream resolver at Google DNS (8.8.8.8)
import socket
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver


class AdBlockResolver(BaseResolver): # handle DNS requests - block ads and forward others upstream

    def __init__(self, blocklist):
        self.blocklist = blocklist
        self.upstream_dns = "8.8.8.8" # google dns
        self.blocked_count = 0
        self.allowed_count = 0

    def resolve(self, request, handler):
        reply = request.reply() # grab request
        domain = str(request.q.qname).lower().rstrip('.') # request domain name

        if self.is_blocked(domain): # check if domain is blocked
            self.blocked_count += 1

            if request.q.qtype == QTYPE.A: # if it's asking for ipv4, send to 0.0.0.0 to block it
                reply.add_answer(RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rdata=A("0.0.0.0"),
                    ttl=60
                ))
            return reply

        # not blocked
        self.allowed_count += 1
        try:
            return self.forward_to_dns(request)
        except:
            return reply

    def is_blocked(self, domain): #check if domain is in blocklist
        domain = domain.lower()

        if domain in self.blocklist:
            return True

        # also check parent domains
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
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
            data, _ = sock.recvfrom(4096) # get response from upstream resolver (sender is ignored its google dns)
            response = DNSRecord.parse(data)
            return response
        finally:
            sock.close()

    def get_stats(self):
        return {
            'blocked': self.blocked_count,
            'allowed': self.allowed_count,
            'total': self.blocked_count + self.allowed_count
        }


class DNSSinkholeServer:

    def __init__(self, blocklist, host="127.0.0.1", port=5353, upstream_dns="8.8.8.8"):
        self.blocklist = blocklist
        self.host = host
        self.port = port
        self.resolver = AdBlockResolver(blocklist)
        self.server = None

    def start(self):
        self.server = DNSServer(self.resolver, port=self.port, address=self.host)
        self.server.start()

    def stop(self):
        if self.server:
            self.server.stop()

    def get_stats(self):
        return self.resolver.get_stats()