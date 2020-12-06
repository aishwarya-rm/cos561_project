# This file sends packets when run as root (i.e. sudo scapysend.py)
# Introduction to scapy in python: https://www.mmu.ac.uk/media/mmuacuk/content/documents/school-of-computing-mathematics-and-digital-technology/blossom/PythonScriptingwithScapyLab.pdf

from scapy.all import *
import time, collections, operator, json, subprocess

# # Send packets at the 3rd protocol layer
# send(IP(dst='1.2.3.4')/ICMP())
#
#
# # Basic sniffing
# a=sniff(count=100)
# a.nsummary()
#
# # Send and receive packets, print summary
# ans,unans=sr(IP(dst="192.168.86.130",ttl=5)/ICMP())
# ans.nsummary()
# unans.nsummary()
def getTS(pkt):
	for option in pkt[TCP].options:
		if option[0] == "Timestamp":
			return option[1]

# Sniff packets in general
pkts = sniff(filter="tcp", count=100)
currTime = int(time.time())
# This writes to a file, it's unintelligible
wrpcap("data/sniff_{0}.cap".format(currTime), pkts)

nflxIPs = []
print("Analyzing...")
srcIPs = collections.defaultdict(int)
for pkt in pkts:
	srcIPs[pkt[IP].src] += 1
sortedIPs = sorted(srcIPs.items(), key=operator.itemgetter(1), reverse=True)
for (ip, _) in sortedIPs[:3]:
	print("checking out " + ip)
	p1 = subprocess.Popen(['nslookup', ip], stdout=subprocess.PIPE)
	p2 = subprocess.Popen(['grep', '-e', 'netflix', '-e', 'nflx'], stdin=p1.stdout, stdout=subprocess.PIPE)
	o = p2.communicate()
	if len(o[0]) > 0:
		nflxIPs.append(ip)
nflxPkts = [pkt for pkt in pkts if pkt[IP].src in nflxIPs]
wrpcap("data/analyze_{0}.cap".format(currTime), nflxPkts)

firstTS = getTS(nflxPkts[0])[1]
data = [{'len': x[IP].len, 'ts': getTS(x)[1] - firstTS} for x in nflxPkts]

# with open("sniff_data", 'wb') as oFile:
# 	oFile.write(json.dumps(data))
