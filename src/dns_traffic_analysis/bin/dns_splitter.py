#!/usr/bin/env python3

# Disable warning messages on startup
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

import argparse

from scapy.all import *


def write(pkt, dnsid):
    wrpcap(dnsid + ".pcap", pkt, append=True)  # appends packet to output file


def splitpcap(pcap, dnsid):
    print(f"Opening file: {pcap}")
    print(f"Searching for Query ID: {dnsid}")
    pckts = rdpcap(pcap)
    for p in pckts:
        if DNS in p:
            dns = p.getlayer(DNS)
            if dns is not None and dns.id == int(dnsid):
                print(f"Transaction ID match found for {dns.id}")
                write(p, dnsid)


def main():
    parser = argparse.ArgumentParser(
        description="Parse pcap files and seperate specific DNS Query IDs into new pcap file",
        epilog="Uses query IDs found by traffic-analysis.py",
    )
    parser.add_argument("-p", "--pcap", help="traffic capture file", required=True)
    parser.add_argument("-d", "--dnsid", help="dns query id", required=True)
    args = parser.parse_args()

    splitpcap(args.pcap, args.dnsid)


if __name__ == "__main__":
    main()
