import sys
import argparse
from scapy.all import sniff, TCPSession, load_layer
from connection import Connection
from firewall import SniffHandler, check_xss, handle_packet,
import logging

load_layer("http")

# CONTROLLER_API_ADDR = "192.168.56.102"
# CONTROLLER_API_PORT = 8000

# controller = Connection(addr=CONTROLLER_API_ADDR, port=CONTROLLER_API_PORT)

logging.basicConfig(level=logging.INFO)


def get_args():
    parser = argparse.ArgumentParser(description="XSS attack detector")
    parser.add_argument("iface", type=str, help="Network interface to sniff on")
    parser.add_argument("-caddr", type=str, help="IP addr of controller")
    parser.add_argument("-cport", type=str, help="Port on which the controller is working")
    parser.add_argument("-b","--block", action='store_true',help='Enable blocking intruders')
    args = parser.parse_args()
    return args.iface,args.caddr,args.cport,args.block


def main():
    iface,controller_ip,controller_port,should_block=get_args()
    controller_conn=Connection.get_connection(controller_ip,controller_port)
    sniff_handler=SniffHandler(controller_conn,should_block)
    sniff(session=TCPSession, prn=sniff_handler.handle_packet, iface=iface)


if __name__ == "__main__":
    main()
