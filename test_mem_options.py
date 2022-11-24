from firewall import REGEX_ACCURATE_STRING
import re2
from scapy.all import sniff, wrpcap, Raw
from abc import abstractmethod
import time
from firewall import check_xss, get_http_info
import matplotlib.pyplot as plt

mem_usage_list = [
    a << 11 for a in list(range(10,100000,100))
]

encoded_pattern = REGEX_ACCURATE_STRING.encode()


class RunRegex:
    SUMMARY_FREQ = 50000

    def __init__(self, filenames, regex_obj):
        self.filenames = filenames
        self.regex = regex_obj

    def evaluate(self):
        for filename in self.filenames:
            try:
                with open(filename, "rb") as pcap_file:
                    sniff(
                        offline=pcap_file,
                        prn=self.packet_callback,
                        store=0,
                    )
            except Exception as e:
                print(e)
                raise
                continue
        self.final_callback()

    @abstractmethod
    def packet_callback(self, packet):
        http_info = get_http_info(packet)
        if not http_info:
            return False
        path, url, method = http_info
        xss_matched = None
        if method == b"GET":
            xss_matched = self.match_regex(path)
            # print("matched",xss_matched)
        elif method == b"POST" and Raw in packet:
            xss_matched = self.match_regex(packet[Raw].load)

    def match_regex(self, payload):
        return self.regex.search(payload)


times = []
for mem_usage in mem_usage_list:
    options = re2.Options()
    options.max_mem = mem_usage
    regexp = re2.compile(encoded_pattern, options=options)
    start = time.time()
    RunRegex(["../captures/processed_all_payloads_6579.pcap"], regexp)
    time_taken = time.time() - start
    print(f"{mem_usage>>17}kb:{time_taken}secs")
    times.append(time_taken)

plt.plot(times)
plt.show()