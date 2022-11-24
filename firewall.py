import logging
import os
import re2 as re
import time
from typing import Any, Optional
from scapy.all import TCP, Raw, IP, wrpcap
from scapy.layers.http import HTTPRequest
import hyperscan


class ResultPacket:
    def __init__(self, src, packet, fields) -> None:
        self.src = src
        self.packet = packet
        self.fields = fields


import errno
import os
import signal
import functools


# class TimeoutError(Exception):
#     pass


# def timeout(seconds, error_message=os.strerror(errno.ETIME)):
#     def decorator(func):
#         def _handle_timeout(signum, frame):
#             raise TimeoutError(error_message)

#         @functools.wraps(func)
#         def wrapper(*args, **kwargs):
#             signal.signal(signal.SIGALRM, _handle_timeout)
#             signal.alarm(seconds)
#             try:
#                 result = func(*args, **kwargs)
#             finally:
#                 signal.alarm(0)
#             return result

#         return wrapper

#     return decorator


REGEX_STRINGS = [
    "((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
    "((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)",
    "\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*",
    "((%3C)|<)((%2F)|/)*[a-z0-9%]+((%3E)|>)",
    "((%3C)|<)((%69)|i|(%49))((%6D)|m|(%4D))((%67)|g|(%47))[^\n]+((%3E)|>)",
    r"""(\\s+\\w+(\\s\*=\\s\*(?:"(.)\*?"|'(.)\*?'|\[^'"\>\\s\]+))?)+\\s\*|\\s\*""",
    "((alert|on\w+|function\s+\w+)\s*\(\s*(['+\d\w](,?\s*['+\d\w]*)*)*\s*\))",
    "(<(script|iframe|embed|frame|frameset|object|img|applet|body|html|style|layer|link|ilayer|meta|bgsound))",
    r"""<[^\w<>]*(?:[^<>"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*s\W*v\W*g|\W*m\W*a\W*r\W*q\W*u\W*e\W*e|(?:\W*l\W*i\W*n\W*k|\W*o\W*b\W*j\W*e\W*c\W*t|\W*e\W*m\W*b\W*e\W*d|\W*a\W*p\W*p\W*l\W*e\W*t|\W*p\W*a\W*r\W*a\W*m|\W*i?\W*f\W*r\W*a\W*m\W*e|\W*b\W*a\W*s\W*e|\W*b\W*o\W*d\W*y|\W*m\W*e\W*t\W*a|\W*i\W*m\W*a?\W*g\W*e?|\W*v\W*i\W*d\W*e\W*o|\W*a\W*u\W*d\W*i\W*o|\W*b\W*i\W*n\W*d\W*i\W*n\W*g\W*s|\W*s\W*e\W*t|\W*i\W*s\W*i\W*n\W*d\W*e\W*x|\W*a\W*n\W*i\W*m\W*a\W*t\W*e)[^>\w])|(?:<\w[\s\S]*[\s\0\/]|['"])(?:formaction|style|background|src|lowsrc|ping|on(?:d(?:e(?:vice(?:(?:orienta|mo)tion|proximity|found|light)|livery(?:success|error)|activate)|r(?:ag(?:e(?:n(?:ter|d)|xit)|(?:gestur|leav)e|start|drop|over)?|op)|i(?:s(?:c(?:hargingtimechange|onnect(?:ing|ed))|abled)|aling)|ata(?:setc(?:omplete|hanged)|(?:availabl|chang)e|error)|urationchange|ownloading|blclick)|Moz(?:M(?:agnifyGesture(?:Update|Start)?|ouse(?:PixelScroll|Hittest))|S(?:wipeGesture(?:Update|Start|End)?|crolledAreaChanged)|(?:(?:Press)?TapGestur|BeforeResiz)e|EdgeUI(?:C(?:omplet|ancel)|Start)ed|RotateGesture(?:Update|Start)?|A(?:udioAvailable|fterPaint))|c(?:o(?:m(?:p(?:osition(?:update|start|end)|lete)|mand(?:update)?)|n(?:t(?:rolselect|extmenu)|nect(?:ing|ed))|py)|a(?:(?:llschang|ch)ed|nplay(?:through)?|rdstatechange)|h(?:(?:arging(?:time)?ch)?ange|ecking)|(?:fstate|ell)change|u(?:echange|t)|l(?:ick|ose))|m(?:o(?:z(?:pointerlock(?:change|error)|(?:orientation|time)change|fullscreen(?:change|error)|network(?:down|up)load)|use(?:(?:lea|mo)ve|o(?:ver|ut)|enter|wheel|down|up)|ve(?:start|end)?)|essage|ark)|s(?:t(?:a(?:t(?:uschanged|echange)|lled|rt)|k(?:sessione|comma)nd|op)|e(?:ek(?:complete|ing|ed)|(?:lec(?:tstar)?)?t|n(?:ding|t))|u(?:ccess|spend|bmit)|peech(?:start|end)|ound(?:start|end)|croll|how)|b(?:e(?:for(?:e(?:(?:scriptexecu|activa)te|u(?:nload|pdate)|p(?:aste|rint)|c(?:opy|ut)|editfocus)|deactivate)|gin(?:Event)?)|oun(?:dary|ce)|l(?:ocked|ur)|roadcast|usy)|a(?:n(?:imation(?:iteration|start|end)|tennastatechange)|fter(?:(?:scriptexecu|upda)te|print)|udio(?:process|start|end)|d(?:apteradded|dtrack)|ctivate|lerting|bort)|DOM(?:Node(?:Inserted(?:IntoDocument)?|Removed(?:FromDocument)?)|(?:CharacterData|Subtree)Modified|A(?:ttrModified|ctivate)|Focus(?:Out|In)|MouseScroll)|r(?:e(?:s(?:u(?:m(?:ing|e)|lt)|ize|et)|adystatechange|pea(?:tEven)?t|movetrack|trieving|ceived)|ow(?:s(?:inserted|delete)|e(?:nter|xit))|atechange)|p(?:op(?:up(?:hid(?:den|ing)|show(?:ing|n))|state)|a(?:ge(?:hide|show)|(?:st|us)e|int)|ro(?:pertychange|gress)|lay(?:ing)?)|t(?:ouch(?:(?:lea|mo)ve|en(?:ter|d)|cancel|start)|ime(?:update|out)|ransitionend|ext)|u(?:s(?:erproximity|sdreceived)|p(?:gradeneeded|dateready)|n(?:derflow|load))|f(?:o(?:rm(?:change|input)|cus(?:out|in)?)|i(?:lterchange|nish)|ailed)|l(?:o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|evelchange|y)|g(?:amepad(?:(?:dis)?connected|button(?:down|up)|axismove)|et)|e(?:n(?:d(?:Event|ed)?|abled|ter)|rror(?:update)?|mptied|xit)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|valid|put))|o(?:(?:(?:ff|n)lin|bsolet)e|verflow(?:changed)?|pen)|SVG(?:(?:Unl|L)oad|Resize|Scroll|Abort|Error|Zoom)|h(?:e(?:adphoneschange|l[dp])|ashchange|olding)|v(?:o(?:lum|ic)e|ersion)change|w(?:a(?:it|rn)ing|heel)|key(?:press|down|up)|(?:AppComman|Loa)d|no(?:update|match)|Request|zoom))[\s\0]*=""",
]
URL_REPLACEMENTS = {
    "\s": "(\%20|\%09|\%0A|\+)",
    "\(": "(\%28)",
    "'": "(\%27)",
    ",": "(\%2C)",
    "\)": "(\%29)",
}
REGEX_ACCURATE_STRING_ORIGINAL = r"(alert|on\w+|prompt|function(\%20|\%09|\%0A|\+)+\w+)(\%20|\%09|\%0A|\+)*(\%28)(\%20|\%09|\%0A|\+)*((\%27|\%2B|\d|\w)((\%2C)?(\%20|\%09|\%0A|\+)*(\%27|\%2B|\d|\w)*)*)*(\%20|\%09|\%0A|\+)*\%29"
REGEX_ACCURATE_STRING = REGEX_ACCURATE_STRING_ORIGINAL
# print(REGEX_ACCURATE_STRING)

# for key in URL_REPLACEMENTS:
#     REGEX_ACCURATE_STRING = REGEX_ACCURATE_STRING.replace(key, URL_REPLACEMENTS[key])
# print(REGEX_ACCURATE_STRING)
# print(REGEX_ACCURATE_STRING)
REGEX_ACCURATE_ARR = [REGEX_ACCURATE_STRING]
REGEX_ACCURATE_STRING_PATTERN = re.compile(REGEX_ACCURATE_STRING.encode())

# REGEX_FAST = ["\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*"]
# @timeout(seconds=1)
def accurate_regex_decode(payload):
    payload = urllib.parse.unquote_plus(payload)
    return REGEX_ACCURATE_STRING_PATTERN.search(payload)


def accurate_regex_no_decode(payload):
    # print(payload)
    return REGEX_ACCURATE_STRING_PATTERN.search(payload)


db = hyperscan.Database()

hyperscan_patterns = [
    # expression,  id, flags
    (
        pattern.encode("utf-8"),
        id,
        hyperscan.HS_FLAG_CASELESS | hyperscan.HS_FLAG_SINGLEMATCH,
    )
    for id, pattern in enumerate(REGEX_ACCURATE_ARR)
]
expressions, ids, flags = zip(*hyperscan_patterns)
db.compile(
    expressions=expressions, ids=ids, elements=len(hyperscan_patterns), flags=flags
)

matches_hyperscan = 0


def on_match_hyperscan(
    id: int, froms: int, to: int, flags: int, context: Optional[Any] = None
) -> Optional[bool]:
    global matches_hyperscan
    matches_hyperscan += 1
    print("MATCHES", matches_hyperscan)


def fast_regex(payload):
    regex_string = "\%3C(?:[^>=]|='[^']*'|=\"[^\"]*\"|=[^'\"][^\\s>]*)*"
    return re.search(regex_string, payload)


def _hyperscan_regex(payload):
    global matches_hyperscan
    prev_value = matches_hyperscan
    # print(payload)
    db.scan(payload, match_event_handler=on_match_hyperscan)
    return matches_hyperscan != prev_value


# @timeout(seconds=1)
def hyperscan_regex(payload):
    return _hyperscan_regex(payload)


# def match_regex(payload):
#     for regex_string in REGEX_STRINGS:
#         if re.search(regex_string, payload):
#             return True
#     return False
def match_regex(payload):
    result = False
    # try:
    #     result = hyperscan_regex(payload)
    # except:
    #     print("EXCEPTION")
    #     result = fast_regex(payload)
    # result = accurate_regex_decode(payload)
    # print("PAYLOAD", payload)
    result = accurate_regex_no_decode(payload)
    return result


def match_regex_csv(payload):
    result = False
    # try:
    #     result = hyperscan_regex(payload)
    # except:
    #     print("EXCEPTION")
    #     result = fast_regex(payload)
    result = accurate_regex_no_decode(payload)
    return result


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
        method = http_request.Method
        # path = http_request.fields["Path"]
        path = http_request.Path
        host = http_request.Host
        if not host:
            host=b''
        url = host + path
        return path, url, method
    except:
        raise
        return None


import urllib


def check_xss(packet):
    http_info = get_http_info(packet)

    if not http_info:
        return False
    path, url, method = http_info
    xss_matched = None
    if method == b"GET":
        xss_matched = match_regex(path)
        # print("matched",xss_matched)
    elif method == b"POST" and Raw in packet:
        xss_matched = match_regex(packet[Raw].load)
    if not xss_matched:
        return False
    url = url.decode()
    webpage = url[: url.find("?")]
    src_ip = str(packet[IP].src)
    logging.info("XSS detected")
    logging.info("Source ip:- " + src_ip)
    logging.info("Webpage:- " + webpage)
    return ResultPacket(src_ip, packet, path)


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
