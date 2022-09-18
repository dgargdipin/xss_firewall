import argparse
from evaluate_utils import Evaluate_FP, Evaluate_Positives


def main():
    parser = argparse.ArgumentParser(description="Evaluate XSS firewall")
    parser.add_argument("mode", type=str, help="Evaluation mode: normal or fp")
    parser.add_argument("-count", type=int, help="Number of attacks in case of normal mode")
    parser.add_argument("filename", type=str, help="Pcap filename")
    args = parser.parse_args()
    with open(args.filename, "rb") as pcap_file:
        if args.mode == "fp":
            Evaluate_FP(pcap_file).evaluate()
        else:
            Evaluate_Positives(pcap_file,args.count).evaluate()


if __name__ == "__main__":
    main()
