#!/usr/bin/env python3

import cProfile
import argparse

# Disable warning log messages
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import rdpcap, DNS

dns_servers_found = {}
recursive_dns_servers = {}
dns_clients = {}


def find_dns_servers(packet):
    if packet.haslayer("UDP"):
        if packet["UDP"].dport == 53:
            if packet["IP"].dst in dns_servers_found:
                dns_servers_found[packet["IP"].dst] += 1
            else:
                dns_servers_found[packet["IP"].dst] = 1
        if packet["UDP"].sport == 53:
            if packet["IP"].dst in dns_clients:
                dns_clients[packet["IP"].dst] += 1
            else:
                dns_clients[packet["IP"].dst] = 1
                if packet["IP"].dst in dns_servers_found:
                    if packet["IP"].dst in recursive_dns_servers:
                        recursive_dns_servers[packet["IP"].dst] += 1
                    else:
                        recursive_dns_servers[packet["IP"].dst] = dns_servers_found[
                            packet["IP"].dst
                        ]
            for r in recursive_dns_servers:
                if r in dns_servers_found or r in dns_clients:
                    dns_servers_found.pop(r, None)
                    dns_clients.pop(r, None)


def main(file, display, count, focus):
    type_choice = {}
    if file:
        packet_file = rdpcap(file)
        for packet in packet_file:
            find_dns_servers(packet)

        if display:
            if focus == "servers":
                sorted_dns_servers = dict(
                    sorted(
                        dns_servers_found.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )
                )
                type_choice["servers"] = sorted_dns_servers
            if focus == "recursive":
                sorted_recursive_servers = dict(
                    sorted(
                        recursive_dns_servers.items(),
                        key=lambda item: [1],
                        reverse=True,
                    )
                )
                type_choice["recursive"] = sorted_recursive_servers
            if focus == "clients":
                sorted_clients = dict(
                    sorted(dns_clients.items(), key=lambda item: [1], reverse=True)
                )
                type_choice["clients"] = sorted_clients

            if count:
                c = 0
                while c < count:
                    for n in type_choice[focus]:
                        print(
                            "{}: {} Count: {}".format(focus, n, type_choice[focus][n])
                        )
                        if c == count:
                            break
                        else:
                            c += 1
            else:
                if focus == "servers":
                    sorted_data = dict(
                        sorted(
                            dns_servers_found.items(),
                            key=lambda item: item[1],
                            reverse=True,
                        )
                    )
                if focus == "recursive":
                    sorted_data = dict(
                        sorted(
                            recursive_dns_servers.items(),
                            key=lambda item: [1],
                            reverse=True,
                        )
                    )
                if focus == "clients":
                    sorted_data = dict(
                        sorted(dns_clients.items(), key=lambda item: [1], reverse=True)
                    )
                for n in sorted_data:
                    print("{}: {} Count: {}".format(focus, n, sorted_data[n]))
        else:
            print("Total DNS servers found: {}".format(len(dns_servers_found)))
            print(
                "Total recursive DNS servers found: {}".format(
                    len(recursive_dns_servers)
                )
            )
            print("Total DNS clients found: {}".format(len(dns_clients)))

    else:
        print("File argument not declared")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse pcap files to file DNS servers",
        epilog="Identify DNS servers and clients from a PCAP file",
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
    parser.add_argument(
        "--focus",
        choices=["servers", "recursive", "clients"],
        help="Specify traffic to display",
    )
    args = parser.parse_args()

    if args.profile:
        cProfile.run("main(args.file, args.display, args.count)")
    else:
        main(args.file, args.display, args.count, args.focus)
