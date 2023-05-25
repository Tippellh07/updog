"""CLI for updog."""

# standard imports
import argparse
import logging

# project imports
from updog.updog import analyse

# logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    datefmt="%H:%M:%S",
    format="[%(asctime)s] [%(levelname)8s] %(message)s",
)


def main() -> None:
    """CLI entrypoint for updog."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--input-pcap",
        help="PCAP file to analyse",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output-json",
        help="File to output summary JSON to.",
        type=argparse.FileType("w"),
        required=True,
    )
    parser.add_argument(
        "--output-html",
        help="File to output summary HTML to.",
        type=argparse.FileType("w"),
        required=False,
    )

    args = parser.parse_args()

    analyse(args.input_pcap.name, args.output_json, args.output_html)


if __name__ == "__main__":
    main()
