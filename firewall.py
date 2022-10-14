import logging
import os
import re
import time
from scapy.all import TCP, Raw, IP, wrpcap
from scapy.layers.http import HTTPRequest


class ResultPacket:
    def __init__(self, src, packet, fields) -> None:
        self.src = src
        self.packet = packet
        self.fields = fields


REGEX_STRINGS = [
    # "((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
    # "((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)",
    "\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*",
    # "((%3C)|<)((%2F)|/)*[a-z0-9%]+((%3E)|>)",
    # "((%3C)|<)((%69)|i|(%49))((%6D)|m|(%4D))((%67)|g|(%47))[^\n]+((%3E)|>)",
]


def match_regex(payload):
    for regex_string in REGEX_STRINGS:
        if re.findall(regex_string, payload):
            return True
    return False


def get_http_request(packet):
    if not packet or not TCP in packet:
        return None

    if HTTPRequest in packet:
        return packet[HTTPRequest]
    elif Raw in packet:
        try:
            http_layer = HTTPRequest(packet[Raw].load)
            return http_layer
        except:
            return None
    else:
        return None


def get_http_info(packet):
    http_request = get_http_request(packet)
    if not http_request:
        return None
    try:
        fields = "{0[Path]}".format(http_request.fields)
        url = http_request.Host.decode() + http_request.Path.decode()
        return fields, url
    except:
        return None


def check_xss(packet):
    http_info = get_http_info(packet)
    if not http_info:
        return False
    fields, url = http_info
    xss_matched = match_regex(fields)
    if not xss_matched:
        return False
    webpage = url[: url.find("?")]
    src_ip = str(packet[IP].src)
    logging.info("XSS detected")
    logging.info("Source ip:- " + src_ip)
    logging.info("Webpage:- " + webpage)
    return ResultPacket(src_ip, packet, fields)


class SniffHandler:
    LOG_FOLDER = "logs"

    def __init__(self, controller, should_block, should_log):
        self.controller = controller
        self.should_block = should_block
        self.should_log = should_log
        if self.should_log:
            self.timestr_safe = time.strftime("log_%Y-%m-%d-%H-%M-%S")
            if not os.path.exists(self.LOG_FOLDER):
                os.makedirs(self.LOG_FOLDER)

    def handle_packet(self, packet):
        result = check_xss(packet)
        if result:
            if self.controller and self.should_block:
                self.controller.block(result.src)
            if self.should_log:
                wrpcap(
                    os.path.join(self.LOG_FOLDER, self.timestr_safe + ".pcap"),
                    packet,
                    append=True,
                )
