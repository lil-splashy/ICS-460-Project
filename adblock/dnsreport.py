#!/usr/bin/env python3
import time
from datetime import datetime
from collections import defaultdict


class DNSReporter:
    
    def __init__(self, resolver):
        self.resolver = resolver
        self.start_time = time.time()
        self.blocked_domains = defaultdict(int)  # Track frequency of blocked domains
        self.allowed_domains = defaultdict(int)  # Track frequency of allowed domains
        
    def log_blocked(self, domain):
        self.blocked_domains[domain] += 1
        
    def log_allowed(self, domain):
        self.allowed_domains[domain] += 1
    
    def print_summary(self):
        stats = self.resolver.get_stats()
        uptime = time.time() - self.start_time
        
        print("\n" + "="*60)
        print("DNS SINKHOLE SUMMARY REPORT")
        print("="*60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Uptime: {self._format_uptime(uptime)}")
        print("-"*60)
        print(f"Total Queries:    {stats['total']:>8}")
        print(f"Blocked Queries:  {stats['blocked']:>8} ({self._percent(stats['blocked'], stats['total'])}%)")
        print(f"Allowed Queries:  {stats['allowed']:>8} ({self._percent(stats['allowed'], stats['total'])}%)")
        print("-"*60)
        
        if stats['total'] > 0:
            qps = stats['total'] / uptime if uptime > 0 else 0
            print(f"Queries per second: {qps:.2f}")
        print("="*60 + "\n")
    
    def print_top_blocked(self, n=10):
        """Print top N blocked domains"""
        if not self.blocked_domains:
            print("No blocked domains yet.\n")
            return
            
        print("\n" + "="*60)
        print(f"TOP {n} BLOCKED DOMAINS")
        print("="*60)
        
        sorted_domains = sorted(
            self.blocked_domains.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:n]
        
        for i, (domain, count) in enumerate(sorted_domains, 1):
            print(f"{i:2}. {domain:<45} {count:>5} hits")
        print("="*60 + "\n")
    
    def print_top_allowed(self, n=10):
        """Print top N allowed domains"""
        if not self.allowed_domains:
            print("No allowed domains yet.\n")
            return
            
        print("\n" + "="*60)
        print(f"TOP {n} ALLOWED DOMAINS")
        print("="*60)
        
        sorted_domains = sorted(
            self.allowed_domains.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:n]
        
        for i, (domain, count) in enumerate(sorted_domains, 1):
            print(f"{i:2}. {domain:<45} {count:>5} hits")
        print("="*60 + "\n")
    
    def print_full_report(self):
        """Print a comprehensive report"""
        self.print_summary()
        self.print_top_blocked()
        self.print_top_allowed()
    
    def print_hourly_summary(self):
        """Print a compact hourly summary"""
        stats = self.resolver.get_stats()
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        print(f"[{timestamp}] Total: {stats['total']:>5} | "
              f"Blocked: {stats['blocked']:>5} ({self._percent(stats['blocked'], stats['total'])}%) | "
              f"Allowed: {stats['allowed']:>5}")
    
    def print_realtime_stats(self):
        """Print real-time statistics in a compact format"""
        stats = self.resolver.get_stats()
        uptime = time.time() - self.start_time
        
        print(f"\r[STATS] Queries: {stats['total']} | "
              f"Blocked: {stats['blocked']} | "
              f"Allowed: {stats['allowed']} | "
              f"Uptime: {self._format_uptime(uptime)}", 
              end='', flush=True)
    
    def export_csv(self, filename="dns_report.csv"):
        """Export blocked domains to CSV"""
        try:
            with open(filename, 'w') as f:
                f.write("Domain,Hit Count,Type\n")
                
                for domain, count in sorted(self.blocked_domains.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"{domain},{count},blocked\n")
                    
                for domain, count in sorted(self.allowed_domains.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"{domain},{count},allowed\n")
                    
            print(f"\nReport exported to {filename}")
        except Exception as e:
            print(f"\nError exporting CSV: {e}")
    
    @staticmethod
    def _format_uptime(seconds):
        """Format uptime in human-readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    @staticmethod
    def _percent(part, total):
        """Calculate percentage safely"""
        if total == 0:
            return 0.0
        return round((part / total) * 100, 1)


def print_banner():
    """Print startup banner"""
    print("\n" + "="*60)
    print("    DNS SINKHOLE - Ad Blocking DNS Server")
    print("="*60)
    print("Commands:")
    print("  stats     - Show summary statistics")
    print("  report    - Show full report with top domains")
    print("  blocked   - Show top blocked domains")
    print("  allowed   - Show top allowed domains")
    print("  export    - Export report to CSV")
    print("  clear     - Clear screen")
    print("  exit      - Stop server and exit")
    print("="*60 + "\n")