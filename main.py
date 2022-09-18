import sys
import argparse
from scapy.all import sniff, TCPSession, load_layer
from connection import Connection
from firewall import check_xss, handle_packet
import logging

load_layer("http")

CONTROLLER_API_ADDR = "192.168.56.102"
CONTROLLER_API_PORT = 8000

controller = Connection(addr=CONTROLLER_API_ADDR, port=CONTROLLER_API_PORT)

logging.basicConfig(level=logging.INFO)


def main():
    parser = argparse.ArgumentParser(description="XSS attack detector")
    parser.add_argument("iface", type=str, help="Network interface to sniff on")
    args = parser.parse_args()
    iface = args.iface
    sniff(session=TCPSession, prn=handle_packet(controller), iface=iface)


if __name__ == "__main__":
    main()
