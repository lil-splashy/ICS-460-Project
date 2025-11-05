from typing import Set

def load_blocklist(path: str) -> Set[str]:
    entries: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip().lower()
            if not line:
                continue
            entries.add(line)
    return entries

def is_blocked(url: str, entries: Set[str]) -> bool:
    url = url.lower()
    return url in entries