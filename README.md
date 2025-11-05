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
