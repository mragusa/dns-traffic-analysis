#!/usr/bin/env python3

import cProfile
import argparse

# Disable warning log messages
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import rdpcap, IP, IPv6, UDP, TCP

dns_servers_found = {}
recursive_dns_servers = {}
dns_clients = {}


def find_dns_servers(packet):
    if UDP in packet and packet[UDP].dport == 53:
        if IP in packet:
            if packet[IP].dst in dns_servers_found:
                dns_servers_found[packet[IP].dst] += 1
            else:
                dns_servers_found[packet[IP].dst] = 1
        if IPv6 in packet:
            if packet[IPv6].dst in dns_servers_found:
                dns_servers_found[packet[IPv6].dst] += 1
            else:
                dns_servers_found[packet[IPv6].dst] = 1
    if UDP in packet and packet[UDP].sport == 53:
        if IP in packet:
            if packet[IP].dst in dns_clients:
                dns_clients[packet[IP].dst] += 1
            else:
                dns_clients[packet[IP].dst] = 1
        if IPv6 in packet:
            if packet[IPv6].dst in dns_clients:
                dns_clients[packet[IPv6].dst] += 1
            else:
                dns_clients[packet[IPv6].dst] = 1

    if TCP in packet and packet[TCP].dport == 53:
        if IP in packet:
            if packet[IP].dst in dns_servers_found:
                dns_servers_found[packet[IP].dst] += 1
            else:
                dns_servers_found[packet[IP].dst] = 1
        if IPv6 in packet:
            if packet[IPv6].dst in dns_servers_found:
                dns_servers_found[packet[IPv6].dst] += 1
            else:
                dns_servers_found[packet[IPv6].dst] = 1
    if TCP in packet and packet[TCP].sport == 53:
        if IP in packet:
            if packet[IP].dst in dns_clients:
                dns_clients[packet[IP].dst] += 1
            else:
                dns_clients[packet[IP].dst] = 1
        if IPv6 in packet:
            if packet[IPv6].dst in dns_clients:
                dns_clients[packet[IPv6].dst] += 1
            else:
                dns_clients[packet[IPv6].dst] = 1


def main(file: str, display: bool, count: int, focus: list):
    type_choice = {}
    if file:
        packet_file = rdpcap(file)
        for packet in packet_file:
            find_dns_servers(packet)

        # Find recursive DNS servers
        for c in dns_clients:
            if c in dns_servers_found:
                query_count = dns_clients[c] + dns_servers_found[c]
                recursive_dns_servers[c] = query_count
        # Clean recursive servers from dns_servers and dns_clients
        for r in recursive_dns_servers:
            if r in dns_servers_found or r in dns_clients:
                dns_servers_found.pop(r, None)
                dns_clients.pop(r, None)

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
                        key=lambda item: item[1],
                        reverse=True,
                    )
                )
                type_choice["recursive"] = sorted_recursive_servers
            if focus == "clients":
                sorted_clients = dict(
                    sorted(dns_clients.items(), key=lambda item: item[1], reverse=True)
                )
                type_choice["clients"] = sorted_clients
            if count:
                c = 0
                # adjust count if results are less than count
                if len(type_choice[focus]) < count:
                    count = len(type_choice[focus])
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
                if type_choice:
                    for n in type_choice[focus]:
                        print(
                            "{}: {} Count: {}".format(focus, n, type_choice[focus][n])
                        )
                else:
                    print("No sorted data found")
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
