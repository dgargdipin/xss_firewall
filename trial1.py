import sys
import argparse


import re
from scapy.all import *
from scapy.layers.http import *
load_layer("http")




def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_packet(p):
    # print(type(p),type(p).__bases__)
    # # print(p.summary())
    # res=(list(expand(p)))
    # with open("Output.txt", "a") as text_file:
    #     print(res,file=text_file)

    if TCP in p:
        ip_layer = p.getlayer('IP')
        if Raw in p:
            try:
                http_layer=HTTPRequest(p[Raw].load)                
            except:
                return
        else: return

        try:
            h = ('{0[Path]}'.format(http_layer.fields))
            url = http_layer.Host.decode() + http_layer.Path.decode()
            print(url)
        except:
            return
        if(len(h) > 60):
            x = re.findall("\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*",h)
            if x:	
                k = url[:url.find('?')]
                #k = url[url.find('?'):]
                d =str(p[IP].src)
                print("XSS detected")
                print("Source ip:- " + d)
                print("Webpage:- " + k)

def handle_packet_2(x):
    print("\n{} ----HTTP----> {}:{}:\n{}".format(x[IP].src,
                                                         x[IP].dst,
                                                         x[IP].dport, 
                                                         str(bytes(x[TCP].payload))))
def process_tcp_packet(packet):
    '''
    Processes a TCP packet, and if it contains an HTTP request, it prints it.
    '''
    if not packet.haslayer(HTTPRequest):
        # This packet doesn't contain an HTTP request so we skip it
        return
    http_layer = packet.getlayer(HTTPRequest)
    ip_layer = packet.getlayer(IP)
    print('\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields))

def handle_pkt(p):
        if p.haslayer(IP):
            srcIP = p[IP].src
            if p.haslayer(HTTP):
                print(srcIP)
                if p.haslayer(HTTPRequest):
                    print(list(expand(p)), end="\n---------------------------------------------------\n")

parser = argparse.ArgumentParser(description='XSS attack detector')
parser.add_argument('iface', type=str,
                    help='Network interface to sniff on')
args = parser.parse_args()
iface=args.iface

# sniff(prn=handle_packet,iface=iface,session=TCPSession)
sniff(session=TCPSession, prn=handle_packet,iface=iface)