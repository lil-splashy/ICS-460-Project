#!/usr/bin/env python3
from typing import Set

def load_blocklist(path: str) -> Set[str]:
    entries: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            # Remove comments
            line = raw.split("#", 1)[0].strip().lower()
            if not line:
                continue

            # Handle hosts file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)
            parts = line.split()
            if len(parts) >= 2 and (parts[0] == "0.0.0.0" or parts[0] == "127.0.0.1"):
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
            else:
                continue

            # Only add valid domain names
            if domain and "." in domain:
                entries.add(domain)

    return entries

def is_blocked(url: str, entries: Set[str]) -> bool:
    """Check if URL/domain is in blocklist.
    Also checks parent domains (e.g., if ads.example.com is queried,
    it checks both ads.example.com and example.com)
    """
    url = url.lower().rstrip(".")

    # Direct match
    if url in entries:
        return True

    # Check parent domains
    parts = url.split(".")
    for i in range(len(parts)):
        parent = ".".join(parts[i:])
        if parent in entries:
            return True

    return False