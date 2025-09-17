#!/usr/bin/env python3

# Disable warning messages on startup
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import *
import argparse


def write(pkt, dnsid):
    wrpcap(dnsid + ".pcap", pkt, append=True)  # appends packet to output file


def splitpcap(pcap, dnsid):
    print("Opening file: {}".format(pcap))
    print("Searching for Query ID: {}".format(dnsid))
    pckts = rdpcap(pcap)
    for p in pckts:
        if DNS in p:
            dns = p.getlayer(DNS)
            if dns is not None:
                if dns.id == int(dnsid):
                    print("Transaction ID match found for {}".format(dns.id))
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
