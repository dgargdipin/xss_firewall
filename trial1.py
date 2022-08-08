import sys
import re
from scapy.all import *
from scapy.layers import http

try:
    import scapy.all as scapy
except ImportError:
    import scapy
s = input()
ans =0
f = open(s, "rb")
packets = scapy.rdpcap(f)
for p in packets:
	if p.haslayer("HTTPRequest"):
		ip_layer = p.getlayer('IP')
		http_layer = p.getlayer('HTTPRequest')
		h = ('{0[Path]}'.format(http_layer.fields))
		url = http_layer.Host.decode() + http_layer.Path.decode()
		if(len(h) > 60):
			x = re.findall("\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*",h)
			if x:	
				k = url[:url.find('?')]
				#k = url[url.find('?'):]
				d =str(p[IP].src)
				print("XSS detected")
				print("Source ip:- " + d)
				print("Webpage:- " + k)
				ans +=1
print(ans)
print("\nDone. End of pcap")
