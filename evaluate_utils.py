from abc import abstractmethod
import logging
import os
from scapy.all import sniff, wrpcap
from firewall import (
    check_xss,
    get_http_info,
    match_regex_csv,
    accurate_regex_no_decode,
    get_http_request,
)
import time
import urllib.parse
import pandas as pd


class Evaluate:
    SUMMARY_FREQ = 50000

    def __init__(self, filenames):
        self.filenames = filenames
        self.count = 0
        self.detected = 0
        self.times = []
        self.http_count = 0

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
            except Exception as e:
                print(e)
                raise
                continue
        self.final_callback()

    @abstractmethod
    def packet_callback(self, packet):
        start = time.time()
        src = check_xss(packet)
        self.times.append(time.time() - start)
        if src:
            self.detected += 1
        self.count += 1
        if get_http_request(packet):
            self.http_count += 1
        if src or self.count % self.SUMMARY_FREQ == 0:
            self.summary()
        if src:
            return src

    @abstractmethod
    def summary(self):
        pass

    def final_callback(self):
        evaluate_fn_calls(self.times)
        pass


class Evaluate_FP(Evaluate):
    def __init__(self, filenames):
        timestr_safe = time.strftime("%Y-%m-%d-%H-%M-%S")
        self.fp_name = f"fp_{timestr_safe}"
        super().__init__(filenames)

    def packet_callback(self, packet):
        try:
            result = super().packet_callback(packet)
            if result:
                wrpcap(self.fp_name + ".pcap", packet, append=True)
                del result
        except:
            raise
            return

    def summary(self):
        # print(f"FP {self.detected}/{self.count} packets out of{}")
        print(f"DETECTED:{self.detected}, HTTP:{self.http_count},TOTAL:{self.count}")


class Evaluate_Positives(Evaluate):
    SUMMARY_FREQ = 1000

    def __init__(self, packet_files, attack_count):
        super().__init__(packet_files)
        self.attack_count = attack_count
        self.payload_history = set()
        timestr_safe = time.strftime("%Y-%m-%d-%H-%M-%S")
        self.payload_log_path = os.path.join("logs", f"payloads_{timestr_safe}.txt")

    def packet_callback(self, packet):
        result = super().packet_callback(packet)
        http_res = get_http_info(packet)
        # if http_res:
        #     payload, url,method = http_res
        #     with open(self.payload_log_path, "a") as f:
        #         f.write(payload + "\n")
        if result:
            if result.fields not in self.payload_history:
                self.payload_history.add(result.fields)
            else:
                print("Duplicate payload detected.")
        else:
            print(http_res)
    def summary(self):
        print(
            f"Detected {len(self.payload_history)}/{self.attack_count} attack packets out of total {self.count} packets "
        )


class Evaluate_Payload_Traffic(Evaluate):
    SUMMARY_FREQ = 1000

    def __init__(self, packet_files, attack_file):
        super().__init__(packet_files)
        with open(attack_file, "r") as f:
            self.attack_payload_truth = set(f.readlines())
        self.attack_payload_history = set()

    def packet_callback(self, packet):
        result = super().packet_callback(packet)


class LabelledPayload:
    def __init__(self, payload, label):
        self.payload = payload
        self.label = label


import bleach


def predict_bleach(payload):
    # print(payload, bleach.clean(payload))
    return payload == bleach.clean(payload, strip=True)


def get_safe_timestr():
    return time.strftime("%Y-%m-%d-%H-%M-%S")


def evaluate_fn_calls(times):
    with open(f"{get_safe_timestr()}.txt", "w") as f:
        f.write(str(times))
    times = pd.Series(times)
    print(times.describe().apply("{0:.6f}".format))
    print("Total time", times.sum())


def evaluate_csv(csv_file_path):
    import csv
    import urllib.parse
    import time

    false_p, true_p, false_n, true_n = 0, 0, 0, 0
    detections = 0
    times = []
    with open(csv_file_path) as csv_file:
        data = csv.DictReader(csv_file)
        for row in data:
            payload = row["Sentence"]
            # print(urllib.parse.quote(payload))
            label = bool(eval(row["Label"]))
            encoded_payload = urllib.parse.quote(payload).encode()
            start = time.time()
            prediction = accurate_regex_no_decode(encoded_payload)
            times.append(time.time() - start)
            # evaluate_fn_calls(times)
            # prediction = match_regex_csv(payload)
            # prediction = predict_bleach(payload)
            if prediction:
                detections += 1
            if prediction and label:
                true_p += 1
            elif prediction and not label:
                false_p += 1
            elif not prediction and not label:
                true_n += 1
            elif not prediction and label:
                # print(payload)
                # print()
                # print(urllib.parse.quote(payload))
                # print()
                # print()
                # print()
                false_n += 1
        print("False Positives", false_p)
        print("True Positives", true_p)
        print("False Negatives", false_n)
        print("True Negatives", true_n)
        # print(detections)
        evaluate_fn_calls(times)


class Counter:
    SUMMARY_FREQ = 1

    def __init__(self, pcap_file) -> None:
        self.get_count = 0
        self.post_count = 0
        self.count = 0
        sniff(
            offline=pcap_file,
            prn=self.packet_callback,
            store=0,
        )

    def packet_callback(self, packet):
        result = get_http_info(packet)
        self.count += 1
        if not result:
            return
        field, url, method = result
        if method == "GET":
            self.get_count += 1
        elif method == "POST":
            self.post_count += 1
        if self.count % self.SUMMARY_FREQ == 0:
            self.summary()

    def summary(self):
        print(f"GET: {self.get_count}, POST: {self.post_count}, TOTAL: {self.count}")
