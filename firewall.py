from curses import nonl
import logging
import re
from scapy.all import TCP, Raw, IP
from scapy.layers.http import HTTPRequest


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


def check_xss(p):
    if not p or not TCP in p:
        return False

    if HTTPRequest in p:
        http_layer = p[HTTPRequest]
    elif Raw in p:
        try:
            http_layer = HTTPRequest(p[Raw].load)
        except:
            return False
    else:
        return False

    try:
        h = "{0[Path]}".format(http_layer.fields)
        url = http_layer.Host.decode() + http_layer.Path.decode()
    except:
        return False

    
    xss_matched = match_regex(h)
    if not xss_matched:
        return False
    webpage = url[: url.find("?")]
    src_ip = str(p[IP].src)
    logging.info("XSS detected")
    logging.info("Source ip:- " + src_ip)
    logging.info("Webpage:- " + webpage)
    return src_ip


def handle_packet(controller):
    def _handle_packet(p):
        nonlocal controller
        src = check_xss(p)
        if src:
            controller.block(src)

    return _handle_packet
