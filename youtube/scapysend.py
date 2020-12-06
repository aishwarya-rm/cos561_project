
from scapy.all import *
import time, collections, operator, json, subprocess

def getTS(pkt):
	for option in pkt[TCP].options:
		if option[0] == "Timestamp":
			return option[1]

# Sniff packets in general
count = = 10000
pkts = sniff(filter="tcp", count=count)
currTime = int(time.time())

print("Analyzing...")
srcIPs = collections.defaultdict(int)
srcIPv6s = collections.defaultdict(int)
for pkt in pkts:
	# pkt.show()
	if IP in pkt:
		srcIPs[pkt[IP].src] += 1
	if IPv6 in pkt:
		srcIPv6s[pkt[IPv6].src] += 1

sortedIPs = sorted(srcIPs.items(), key=operator.itemgetter(1), reverse=True)
sortedIPv6s = sorted(srcIPv6s.items(), key=operator.itemgetter(1), reverse=True)
print('IP sorted by number of packets', sortedIPs)

IPs = []
for (ip, _) in sortedIPs:
	print("\n\tChecking out " + ip)

	p1 = subprocess.Popen(['nslookup', ip], stdout=subprocess.PIPE)
	if True:
		out = p1.communicate()
		for line in out[0].decode("utf-8").split("\n"):
			print('\t\t', line)
	else:
		p2 = subprocess.Popen(['grep', '-e', 'yout', '-e', 'goog'], stdin=p1.stdout, stdout=subprocess.PIPE)
		o = p2.communicate()
		if len(o[0]) > 0:
			IPs.append(ip)
print('\nYoutube IP', IPs)

print('IPv6 sorted by number of packets', sortedIPv6s)
IPv6s = []
for (ip, _) in sortedIPv6s:
	print("\n\tChecking out " + ip)

	p1 = subprocess.Popen(['nslookup', ip], stdout=subprocess.PIPE)
	if True:
		out = p1.communicate()
		for line in out[0].decode("utf-8").split("\n"):
			print('\t\t', line)
	else:
		p2 = subprocess.Popen(['grep', '-e', 'yout', '-e', 'goog'], stdin=p1.stdout, stdout=subprocess.PIPE)
		o = p2.communicate()
		if len(o[0]) > 0:
			IPv6s.append(ip)
print('\nYoutube IPv6', IPv6s)

# Didn't get any IP/IPv6 addresses so switched to Wireshark
