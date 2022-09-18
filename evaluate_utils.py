from abc import abstractmethod
import logging
from scapy.all import sniff, TCPSession, PcapReader
from firewall import check_xss


class Evaluate:
    SUMMARY_FREQ = 1000

    def __init__(self, packet_file):
        self.packet_file = packet_file
        self.count = 0
        self.detected = 0

    def evaluate(self):
        sniff(
            offline=self.packet_file,
            prn=self.packet_callback,
            store=0,
        )

    def packet_callback(self, packet):
        src = check_xss(packet)
        if src:
            self.detected += 1
        self.count += 1
        if src or self.count % self.SUMMARY_FREQ == 0:
            self.summary()

    @abstractmethod
    def summary(self):
        pass


class Evaluate_FP(Evaluate):
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
