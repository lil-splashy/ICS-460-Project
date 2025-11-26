from . import blocklist
from .blocklist import is_blocked, load_blocklist
from .sinkhole import DNSSinkholeServer, AdBlockResolver

__all__ = ["is_blocked", "load_blocklist", "blocklist", "DNSSinkholeServer", "AdBlockResolver"]
