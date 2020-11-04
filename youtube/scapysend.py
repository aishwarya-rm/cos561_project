# This file sends packets when run as root (i.e. sudo scapysend.py)
# Introduction to scapy in python: https://www.mmu.ac.uk/media/mmuacuk/content/documents/school-of-computing-mathematics-and-digital-technology/blossom/PythonScriptingwithScapyLab.pdf

from scapy.all import *
import time, collections, operator, json, subprocess

def getTS(pkt):
	for option in pkt[TCP].options:
		if option[0] == "Timestamp":
			return option[1]

# Sniff packets in general
count = 10000 # 10000
pkts = sniff(filter="tcp", count=count)
currTime = int(time.time())

IPs = []
print("Analyzing...")
srcIPs = collections.defaultdict(int)
for pkt in pkts:

	if IP in pkt:
		print('IP in pkt')
		srcIPs[pkt[IP].src] += 1
	if IPv6 in pkt:
		print('IPv6 in pkt')
		srcIPs[pkt[IPv6].src] += 1

sortedIPs = sorted(srcIPs.items(), key=operator.itemgetter(1), reverse=True)
print('sortedIPs', sortedIPs)

for (ip, _) in sortedIPs:
	print("checking out " + ip)
	# print(traceroute(ip))

	p1 = subprocess.Popen(['nslookup', ip], stdout=subprocess.PIPE)
	p2 = subprocess.Popen(['grep', '-e', 'google', '-e', 'cloud', '-e', 'youtube', '-e', 'yout'], stdin=p1.stdout, stdout=subprocess.PIPE)
	o = p2.communicate()
	if len(o[0]) > 0:
		IPs.append(ip)

print('IPs', IPs)

Pkts_IP = [pkt for pkt in pkts if (IP in pkt and pkt[IP].src in IPs)]
print('len(Pkts_IP) only IP', len(Pkts_IP))
# Pkts_IPv6 = [pkt for pkt in pkts if (IPv6 in pkt and pkt[IPv6].src in IPs)]
# print('len(Pkts_IPv6) only IPv6', len(Pkts_IPv6))

Pkts = Pkts_IP

firstTS = getTS(Pkts[0][0])[1]
print('firstTS', firstTS)

# data = [{'len': len(x[IPv6]), 'ts': getTS(x)[1] - firstTS} for x in Pkts if IPv6 in x]
data = [{'len': len(x[IP]), 'ts': getTS(x)[1] - firstTS} for x in Pkts if IP in x]
with open("sniff_data.json", 'w') as oFile:
	oFile.write(json.dumps(data))
