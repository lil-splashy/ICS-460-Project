#!/usr/bin/env python3
import socket
import time
import sys
from urllib.parse import urlparse

class Client:
    def __init__(self):
        self.url = None
        self.