from abc import abstractmethod
import logging
from scapy.all import sniff, wrpcap
from firewall import check_xss
import time


class Evaluate:
    SUMMARY_FREQ = 50000

    def __init__(self, filenames):
        self.filenames = filenames
        self.count = 0
        self.detected = 0

    def evaluate(self):
        for filename in self.filenames:
            try:
                with open(filename, "rb") as pcap_file:
                    logging.info(f"Reading packets from {filename}")
                    sniff(
                        offline=pcap_file,
                        prn=self.packet_callback,
                        store=0,
                    )
            except:
                continue

    @abstractmethod
    def packet_callback(self, packet):
        src = check_xss(packet)
        if src:
            self.detected += 1
        self.count += 1
        if src or self.count % self.SUMMARY_FREQ == 0:
            self.summary()
        if src:
            return src

    @abstractmethod
    def summary(self):
        pass


class Evaluate_FP(Evaluate):
    def __init__(self, filenames):
        timestr_safe = time.strftime("%Y-%m-%d-%H-%M-%S")
        self.fp_name = f"fp_{timestr_safe}"
        super().__init__(filenames)

    def packet_callback(self, packet):
        result = super().packet_callback(packet)
        if result:
            wrpcap(self.fp_name + ".pcap", packet, append=True)
            del result

    def summary(self):
        print(f"FP {self.detected}/{self.count} packets")


class Evaluate_Positives(Evaluate):
    SUMMARY_FREQ = 1000

    def __init__(self, packet_file, attack_count):
        super().__init__(packet_file)
        self.attack_count = attack_count

    def summary(self):
        print(
            f"Detected {self.detected}/{self.attack_count} attack packets out of total {self.count} packets "
        )
