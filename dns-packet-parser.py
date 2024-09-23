#!/usr/bin/env python3

# Disable warning messages
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import *
import argparse
import time


def process_dns_packet(packet, packet_time):
    if packet.haslayer(DNS):
        dns = packet[DNS]
        print("Time:", packet_time)
        print("Transaction ID:", dns.id)
        print("QR (Query/Response):", "Response" if dns.qr else "Query")
        print("Opcode:", dns.opcode)
        print("AA (Authoritative Answer):", dns.aa)
        print("TC (Truncated):", dns.tc)
        print("RD (Recursion Desired):", dns.rd)
        print("RA (Recursion Available):", dns.ra)
        print("Z (Reserved):", dns.z)
        print("RCODE (Response Code):", dns.rcode)
        print("QDCOUNT (Number of questions):", dns.qdcount)
        print("ANCOUNT (Number of answers):", dns.ancount)
        print("NSCOUNT (Number of authority records):", dns.nscount)
        print("ARCOUNT (Number of additional records):", dns.arcount)
        print("Questions:")
        for q in dns.qd:
            print("\tName:", q.qname)
            print("\tType:", q.qtype)
            print("\tClass:", q.qclass)
        if dns.ancount:
            print("Answers:")
            for a in dns.an:
                print("\tName:", a.rrname)
                print("\tType:", a.type)
                print("\tTTL:", a.ttl)
                if hasattr(a, "rdata"):  # Check if rdata field exists
                    print("\tData:", a.rdata)
        if dns.nscount:
            print("Authority Records:")
            for auth in dns.ns:
                print("\tName:", auth.rrname)
                print("\tType:", auth.type)
                print("\tTTL:", auth.ttl)
                if hasattr(auth, "rdata"):  # Check if rdata field exists
                    print("\tData:", auth.rdata)
        if dns.arcount:
            print("Additional Records:")
            for additional in dns.ar:
                print("\tName:", additional.rrname)
                print("\tType:", additional.type)
                if hasattr(additional, "ttl"):  # Check if ttl field exists
                    print("\tTTL:", additional.ttl)
                else:
                    print("\tTTL: Not available")
                if hasattr(additional, "rdata"):  # Check if rdata field exists
                    print("\tData:", additional.rdata)
        print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Read a pcap file and display DNS packet fields."
    )
    parser.add_argument("-f", "--file", help="Path to the pcap file", required=True)
    args = parser.parse_args()

    packets = rdpcap(args.file)
    packet_times = [
        (pkt.time, pkt) for pkt in packets
    ]  # Store packet times and packets

    # Sort packets by time
    packet_times.sort(key=lambda x: x[0])

    for packet_time, packet in packet_times:
        process_dns_packet(
            packet, time.strftime("%H:%M:%S", time.localtime(int(packet_time)))
        )


if __name__ == "__main__":
    main()
