#!/usr/bin/env python3
from typing import Set
import os

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

def load_benign_list(path: str) -> Set[str]:
    """Load benign domains list"""
    entries: Set[str] = set()
    if not os.path.exists(path):
        return entries

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip().lower()
            if line and "." in line:
                entries.add(line)

    return entries

def add_to_benign_list(domain: str, path: str):
    """Add a domain to the benign list if it's not already there"""
    domain = domain.lower().rstrip(".")

    # Check if domain already in benign list
    benign_list = load_benign_list(path)
    if domain in benign_list:
        return False

    # Append to file
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{domain}\n")

    return True

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

def check_and_categorize(domain: str, blocklist: Set[str], benign_path: str) -> str:
    """
    Check if a domain is blocked. If not blocked, add it to benign list.
    Returns: "blocked" if in blocklist, "benign" if not
    """
    domain = domain.lower().rstrip(".")

    if is_blocked(domain, blocklist):
        return "blocked"
    else:
        # Add to benign list
        add_to_benign_list(domain, benign_path)
        return "benign"