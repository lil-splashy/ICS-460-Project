# ICS-460-Project

# Project Proposal:

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

- Strech goal: Adding ML/LLM to supplement and increase reliability of filtering
- Professor said this proposal with the stretch goal included is good.

### Sniffer.py

Scans network traffic, breaks them up into chunks, and writes the following to a CSV file within the sniffer directory.

- Source IP
- Destination IP
- Protocol
- Type of service

If needed we can add more or less to the array that will export to the CSV.
This is so we can see if the scripting misses any traffic and make adjustments. Possibly adding in a "Blocked" segment to the file to indicate.


### Sinkhole.py

DNS sinkhole (currently on 127.0.0.1) that intercepts DNS requests and blocks known ad domains (anything in blocklist.txt)
Redirects them to 0.0.0.0

Any domains not in the blocklist are sent upstream to googles DNS server at 8.8.8.8
Demo script in demo.py shows what it is doing and prints logs from the python dnslib.

Sniffer can identify new traffic that can be added to the block list.

Run filter.py to start up the sinkhole server on 127.0.0.1

### AWS EC2 t3.micro Instance
- https://us-east-2.console.aws.amazon.com/ec2/home?region=us-east-2#InstanceDetails:instanceId=i-025a45e673ae0b765
- 18.116.242.142

***Deploy:***

To upload any updated project files
```powershell
cd C:\...\ICS-460-Project
scp -i "sinkhole-key.pem" -r * ubuntu@18.116.242.142:~/ICS-460-Project/
```

Connect
```powershell
ssh -i "sinkhole-key.pem" ubuntu@18.116.242.142
```

Install dependencies (first run)
```powershell
cd ~/ICS-460-Project
chmod +x deploy.sh
./deploy.sh
```

Run sinkhole server 
```powershell
sudo python3 -m adblock.sinkhole
```

From another machine or local, test queries
```bash
nslookup ads.com 18.116.242.142
nslookup google.com 18.116.242.142
```