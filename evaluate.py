import argparse
import logging
from evaluate_utils import Evaluate_FP, Evaluate_Positives, evaluate_csv

# logging.basicConfig(level=logging.INFO)


def main():
    parser = argparse.ArgumentParser(description="Evaluate XSS firewall")
    parser.add_argument("mode", type=str, help="Evaluation mode: normal or fp")
    parser.add_argument(
        "-count", type=int, help="Number of attacks in case of normal mode"
    )
    parser.add_argument("filenames", type=str, help="Pcap filename", nargs="+")
    args = parser.parse_args()
    logging.debug(args)
    if args.mode == "fp":
        Evaluate_FP(args.filenames).evaluate()
    elif args.mode == "normal":
        Evaluate_Positives(args.filenames, args.count).evaluate()
    elif args.mode == "csv":
        evaluate_csv(args.filenames[0])


if __name__ == "__main__":
    main()
