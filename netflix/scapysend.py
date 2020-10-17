# This file sends packets when run as root (i.e. sudo scapysend.py)
# Introduction to scapy in python: https://www.mmu.ac.uk/media/mmuacuk/content/documents/school-of-computing-mathematics-and-digital-technology/blossom/PythonScriptingwithScapyLab.pdf

from scapy.all import *

# Send packets at the 3rd protocol layer
send(IP(dst='1.2.3.4')/ICMP())


# Basic sniffing
a=sniff(count=100)
a.nsummary()

# Send and receive packets, print summary
ans,unans=sr(IP(dst="192.168.86.130",ttl=5)/ICMP())
ans.nsummary()
unans.nsummary()
