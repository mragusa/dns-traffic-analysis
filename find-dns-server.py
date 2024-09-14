#!/usr/bin/env python3

import cProfile
import argparse
from scapy.all import rdpcap, DNS

dns_servers_found = {}


def find_dns_servers(packet):
    if packet.haslayer("UDP"):
        if packet["UDP"].dport == 53:
            if packet["IP"].dst in dns_servers_found:
                dns_servers_found[packet["IP"].dst] += 1
            else:
                dns_servers_found[packet["IP"].dst] = 1


def main(file, display, count):
    if file:
        packet_file = rdpcap(file)
        for packet in packet_file:
            find_dns_servers(packet)
        sorted_dns_servers = dict(
            sorted(dns_servers_found.items(), key=lambda item: item[1], reverse=True)
        )
        if display:
            if count:
                c = 0
                while c < count:
                    for n in sorted_dns_servers:
                        print(
                            "DNS Server: {} Count: {}".format(n, sorted_dns_servers[n])
                        )
                        if c == count:
                            break
                        else:
                            c += 1
            else:
                for n in sorted_dns_servers:
                    print("DNS Server: {} Count: {}".format(n, sorted_dns_servers[n]))
        else:
            print("Total DNS servers found: {}".format(len(sorted_dns_servers)))
    else:
        print("File argument not declared")


if __name__ == "__main__":
    # TODO
    # Update to allow display by count instead of one giant output dump
    parser = argparse.ArgumentParser(
        description="Parse pcap files to file DNS servers",
        epilog="Utilize traffic_analysis script to parse pcap files for slow DNS queries",
    )
    parser.add_argument("-f", "--file", help="pcap source file to parse")
    parser.add_argument(
        "-p", "--profile", action="store_true", help="Enable CPU profiling"
    )
    parser.add_argument(
        "-d", "--display", action="store_true", help="display dns servers found"
    )
    parser.add_argument(
        "-c", "--count", type=int, help="display x amount of dns servers"
    )
    args = parser.parse_args()

    if args.profile:
        cProfile.run("main(args.file, args.display, args.count)")
    else:
        main(args.file, args.display, args.count)
