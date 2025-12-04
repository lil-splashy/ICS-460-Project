# ICS-460-Project
Aidan Mahlberg + Benjamin Wall

# Initial project proposal:

- Network-wide Ad-block

Similar to Pi-Hole, `https://docs.pi-hole.net/`, create a network that filters
advertisements before they reach end-user devices. We propose to create our own DNS as
a host to identify and reroute or block traffic associated with known ad domains. Unlike
common browser extensions, this solution would operate on the network level, protecting
all devices connected to it. We aim to provide a more secure and bandwidth-efficient
internet browsing experience by reducing intrusions and limiting non-essential cookie
tracking. We will measure ad-blocking accuracy (ads that get though/false positives) by
either browsing the internet on a custom network or simulating routine internet traffic in a
lab environment. A stretch goal for this project would be to implement a machine learning
model to identify previously unseen or unfiltered ad servers. There are a few
implementations of adware filtering and detection algorithms that use DNS sinkholes,
sending the unwanted traffic to another server: e.g. `https://ieeexploredev.ieee.org/document/10569643`, pi-hole, AdGuard Home, NextDNS



### What this project contains

Top-level files:
- `blocklist.txt` - list of domains to block (one per line, supports subdomain matching)
- `benign_domains.txt` - domains that have been auto-classified as benign or added manually
- `install.sh` - helper to install dependencies on a Linux host
- `adblock/` - Python package containing the sinkhole, sniffer, demo and reporting tools

Inside `adblock/`:
- `sinkhole.py` - DNSSinkholeServer and AdBlockResolver classes. Resolves queries by checking the blocklist and either returning 0.0.0.0 for blocked A-records or forwarding the query to an upstream resolver (Cloudflare 1.1.1.1). Keeps simple statistics and a mapping of resolved IP -> domain.
- `sniffer.py` - NetworkSniffer that listens for network traffic and correlates IP <-> domain using the resolver's mapping. Exports CSVs for later analysis.
- `demo.py` - Demo and test harness. Can run an interactive sinkhole + CLI, or generate DNS traffic against the DNS server.
- `dnsreport.py` - Reporter that aggregates allowed/blocked counts and prints reports and top lists.
- `blocklist.py` - Helpers to load blocklist and benign lists and perform matching logic.


## Quick start (Linux host / server)

These instructions assume you will run the sinkhole on a Linux machine (e.g. the provided EC2 t3.micro @ 18.116.242.142). The sinkhole needs to bind to UDP port 53 and therefore requires root privileges.

1. Upload any updated local files to server

```powershell
scp -i "sinkhole-key.pem" -r C:\..\ICS-460-Project ubuntu@18.116.242.142:~/ICS-460-Project/
```

2. SSH to the server:

```powershell
ssh -i "sinkhole-key.pem" ubuntu@18.116.242.142
```

3. Install dependencies (first run):

```bash
cd ~/ICS-460-Project
chmod +x install.sh
./install.sh
```

The `install.sh` script installs required Python packages (dnslib, scapy, etc.) into the system Python environment or a virtualenv.

4. Run the sinkhole server:

```bash
sudo python3 adblock/main.py
# or run the main/demo which launches sinkhole + sniffer + reporter as an interactive program
sudo python3 adblock/demo.py
```

If you run `adblock/main.py` directly, it will create a DNSSinkholeServer that listens on UDP port 53 by default and uses Cloudflare (1.1.1.1) as upstream.


## Running the demo and tests (local or on server)

`adblock/demo.py` provides multiple modes to exercise the sinkhole and traffic generation.
It supports the following modes (run with sudo when using interactive/main since packet sniffing or injection may require privileges):

- Interactive mode (default):
  sudo python3 adblock/demo.py
  This starts the sinkhole, the sniffer, and an interactive CLI. Commands available:
    - stats     : Show summary statistics
    - report    : Show the full report with top domains
    - blocked   : Show top blocked domains
    - allowed   : Show top allowed domains
    - export    : Export the current report to a CSV file
    - generate  : Start background traffic generation (prompts for duration and rate)
    - clear     : Clear the screen
    - exit      : Stop and exit


## How to test a single domain manually (nslookup / dig)

From any machine that can reach the sinkhole:

PowerShell (Windows):

```powershell
# Query a blocked domain - should return 0.0.0.0 for A records
nslookup gateway.foresee.com 18.116.242.142

# Query a benign domain - should be forwarded upstream and return the real IP
nslookup google.com 18.116.242.142
```

```bash
dig @18.116.242.142 gateway.foresee.com A +short
dig @18.116.242.142 google.com A +short
```

If the domain is present in `blocklist.txt` (or matches a blocked subdomain rule), the sinkhole will respond with 0.0.0.0 for A queries. Otherwise the query is forwarded to the upstream (Cloudflare) and the real answer is returned.

## Files worth editing for customization

- `blocklist.txt` - add or remove domains you want to block. The loader supports subdomain matching (example.com will match ads.example.com). Follow format "0.0.0.0 {url}"
- `benign_domains.txt` - domains that should be treated as allowed (the code may auto-add allowed queries here).
- `adblock/sinkhole.py` - change `upstream_dns` to use a different resolver (e.g. Google @ 8.8.8.8)



## Example workflow

1. Start sinkhole on server:

```bash
sudo python3 adblock/main.py
```

2. From a client machine, test a blocked and allowed domain:

```powershell
nslookup some-ad-tracker.com 18.116.242.142
nslookup example.com 18.116.242.142
```

3. In the server console you should see logs such as:

[DNSHandler:AdBlockResolver] Request: [45.153.34.227:48669] (udp) / 'sl.' (ANY) [ALLOWED] sl (ANY) - added to benign list
[DNSHandler:AdBlockResolver] Reply: [45.153.34.227:48669] (udp) / 'sl.' (ANY) / NOTIMP