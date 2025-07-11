#!/usr/bin/env python3

import click
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from collections import defaultdict

# Disable scapy warnings
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Dot1Q, DNS, DNSQR, DNSRR

dns_clients = defaultdict(lambda: defaultdict(int))
dns_servers = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
network_vlan = defaultdict(int)
success_rate = defaultdict(int)
query_types = defaultdict(int)
op_codes = defaultdict(int)
notify_traffic = defaultdict(int)
# Op Code definitions
op_code_def = {0: "Query", 2: "Status", 4: "Notify", 5: "Update"}
# DNS query type definitions
record_type_lookup = {
    1: "A",
    28: "AAAA",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    108: "EUI48",
    109: "EUI64",
    13: "HINFO",
    55: "HIP",
    65: "HTTPS",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    12: "PTR",
    17: "RP",
    46: "RRSIG",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    64: "SVCB",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",
    63: "ZONEMD",
    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT",
    3: "MD",
    4: "MF",
    254: "MAILA",
    7: "MB",
    8: "MG",
    9: "MR",
    14: "MINFO",
    253: "MAILB",
    11: "WKS",
    32: "NB",
    10: "NULL",
    38: "A6",
    30: "NXT",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP-PTR",
    26: "PX",
    31: "EID",
    34: "ATMA",
    40: "SINK",
    27: "GPOS",
    100: "UINFO",
    101: "UID",
    102: "GID",
    103: "UNSPEC",
    99: "SPF",
    56: "NINFO",
    57: "RKEY",
    58: "TALINK",
    104: "NID",
    105: "L32",
    106: "L64",
    107: "LP",
    259: "DOA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
}


@click.command()
@click.option("-f", "--file", help="Packet Capture File")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output for debugging")
@click.option("-c", "--clients", is_flag=True, help="Display Client Data")
@click.option("-s", "--servers", is_flag=True, help="Display Server Data")
@click.option("-r", "--report", is_flag=True, help="Summary Report")
def main(
    file: str,
    verbose: bool,
    clients: bool,
    servers: bool,
    report: bool,
):
    """Report on DNS Statistics in PCAP File"""
    console = Console()
    total_packets = 0
    print("Processing File: {}".format(file))
    with PcapReader(file) as packets:
        for _ in packets:
            total_packets += 1
    console.print(
        "[bold cyan]Total Packets Found: {}[/bold cyan]".format(total_packets)
    )
    with tqdm(
        total=total_packets, desc="Analyzing Capture", unit="packets", colour="blue"
    ) as pbar:
        with PcapReader(file) as packets:
            for packet in packets:
                process_packet(packet, verbose)
                pbar.update(1)
    if clients:
        for c in sorted(dns_clients):
            for q in dns_clients[c]:
                print(c, q, dns_clients[c][q])
    if servers:
        for s in sorted(dns_servers):
            for q in dns_servers[s]:
                for v in dns_servers[s][q]:
                    print(s, q, v, dns_servers[s][q][v])
    if report:
        display_report("Query Types", query_types)
        display_report("Op Codes", op_codes)
        display_report("Success Rates", success_rate)
        if notify_traffic:
            display_report("DNS Notifies", notify_traffic)
        else:
            print("DNS Notifies not detected in this capture")
        if network_vlan:
            display_report("VLANs", network_vlan)
        else:
            print("No VLANs detected in this capture")


def process_packet(packet, verbose: bool):
    if verbose:
        print(packet)
    if UDP in packet or TCP in packet:
        dns = packet.getlayer(DNS)
        if dns is None or DNSQR not in dns:
            return
        if (
            Dot1Q in packet
            and IP in packet
            and (
                (UDP in packet and packet[UDP].dport == 53)
                or (TCP in packet and packet[TCP].dport == 53)
            )
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {} VLAN: {}".format(
                        packet[IP].src,
                        dns.qd.qname.decode("utf-8", errors="replace"),
                        packet[Dot1Q].vlan,
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            network_vlan[packet[Dot1Q].vlan] += 1
            dns_clients[packet[IP].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif IP in packet and (
            (UDP in packet and packet[UDP].dport == 53)
            or (TCP in packet and packet[TCP].dport == 53)
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IP].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IP].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (
            Dot1Q in packet
            and IPv6 in packet
            and (
                (UDP in packet and packet[UDP].dport == 53)
                or (TCP in packet and packet[TCP].dport == 53)
            )
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IPv6].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IPv6].src, "-", packet[IPv6].dst] += 1
            network_vlan[packet[Dot1Q].vlan] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IPv6].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (IPv6 in packet and UDP in packet and packet[UDP].dport == 53) or (
            IPv6 in packet and TCP in packet and packet[TCP].dport == 53
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IPv6].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IPv6].src, "-", packet[IPv6].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IPv6].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (
            Dot1Q in packet
            and IP in packet
            and (
                (UDP in packet and packet[UDP].sport == 53)
                or (TCP in packet and packet[TCP].sport == 53)
            )
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} VLAN: {} RCode: {}".format(
                        packet[IP].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        packet[Dot1Q].vlan,
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].dst, "-", packet[IP].src] += 1
                query_types[packet[DNS].qd.qtype] += 1
                network_vlan[packet[Dot1Q].vlan] += 1
                dns_servers[packet[IP].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif (IP in packet and UDP in packet and packet[UDP].sport == 53) or (
            IP in packet and TCP in packet and packet[TCP].sport == 53
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IP].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].dst, "-", packet[IP].src] += 1
                query_types[packet[DNS].qd.qtype] += 1
                dns_servers[packet[IP].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif (
            Dot1Q in packet
            and IPv6 in packet
            and (
                (UDP in packet and packet[UDP].sport == 53)
                or (TCP in packet and packet[TCP].sport == 53)
            )
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IPv6].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].dst, "-", packet[IP].src] += 1
                query_types[packet[DNS].qd.qtype] += 1
                network_vlan[packet[Dot1Q].vlan] += 1
                dns_servers[packet[IPv6].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif IPv6 in packet and (
            (UDP in packet and packet[UDP].sport == 53)
            or (TCP in packet and packet[TCP].sport == 53)
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IPv6].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].dst, "-", packet[IP].src] += 1
                query_types[packet[DNS].qd.qtype] += 1
                dns_servers[packet[IPv6].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        else:
            print("Unconsidered: {}".format(packet))


def display_report(report_name: str, data: dict):
    table = Table(title=report_name)
    if report_name == "Query Types":
        table.add_column("Type", justify="center")
        table.add_column("Count", justify="center")
        for qt in data:
            table.add_row(record_type_lookup[qt], str(data[qt]))
        console = Console()
        console.print(table)
    if report_name == "Op Codes":
        table.add_column("Code", justify="center")
        table.add_column("Count", justify="center")
        for oc in data:
            table.add_row(op_code_def[oc], str(data[oc]))
        console = Console()
        console.print(table)
    if report_name == "Success Rates":
        table.add_column("RCode", justify="center")
        table.add_column("Count", justify="center")
        for r in data:
            table.add_row(r, str(data[r]))
        console = Console()
        console.print(table)
    if report_name == "DNS Notifies":
        table.add_column("SRC", justify="center")
        table.add_column("DST", justify="center")
        table.add_column("Count", justify="center")
        for n in data:
            table.add_row(n[0], n[2], str(data[n]))
        console = Console()
        console.print(table)
    if report_name == "VLANs":
        table.add_column("VLAN", justify="center")
        table.add_column("Count", justify="center")
        for v in data:
            table.add_row(str(v), str(data[v]))
        console = Console()
        console.print(table)


if __name__ == "__main__":
    main()
